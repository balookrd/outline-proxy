use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{Mutex, watch};
use tokio::time::{sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::metrics;
use crate::transport::TcpShadowsocksReader;
use crate::types::TargetAddr;
use crate::uplink::TransportKind;

use super::super::TcpFlowKey;
use super::super::maintenance::{
    FlowMaintenancePlan, plan_flow_maintenance, sync_flow_metrics_and_wake,
};
use super::super::state_machine::{
    ServerFlush, TcpFlowState, TcpFlowStatus, assess_server_backlog_pressure, clear_flow_metrics,
    client_fin_seen, flush_server_output, server_fin_sent,
};
use super::connect::select_tcp_candidate_and_connect;
use super::{TunTcpEngine, close_upstream_writer, ip_family_from_version, key_uplink_name};

impl TunTcpEngine {
    pub(super) fn spawn_flow_maintenance(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let maintenance_notify = { flow.lock().await.maintenance_notify.clone() };
            loop {
                let plan = {
                    let mut state = flow.lock().await;
                    if state.status == TcpFlowStatus::Closed {
                        return;
                    }
                    plan_flow_maintenance(
                        &mut state,
                        &engine.inner.tcp,
                        engine.inner.idle_timeout,
                        Instant::now(),
                    )
                };

                match plan {
                    Ok(FlowMaintenancePlan::Abort(reason)) => {
                        engine.abort_flow_with_rst(&key, reason).await;
                        return;
                    },
                    Ok(FlowMaintenancePlan::Close(reason)) => {
                        engine.close_flow(&key, reason).await;
                        return;
                    },
                    Ok(FlowMaintenancePlan::SendPacket { packet, packet_metric, event }) => {
                        let ip_family = ip_family_from_version(key.version);
                        if let Err(error) = engine.inner.writer.write_packet(&packet).await {
                            warn!(
                                error = %format!("{error:#}"),
                                "failed to write maintenance TUN TCP packet"
                            );
                            engine.close_flow(&key, "write_tun_error").await;
                            return;
                        }
                        let (group_name, uplink_name) = super::key_group_and_uplink(&flow).await;
                        metrics::record_tun_tcp_event(&group_name, &uplink_name, event);
                        metrics::record_tun_packet("upstream_to_tun", ip_family, packet_metric);
                    },
                    Ok(FlowMaintenancePlan::Wait(deadline)) => match deadline {
                        Some(deadline) if deadline <= Instant::now() => continue,
                        Some(deadline) => {
                            tokio::select! {
                                changed = close_rx.changed() => {
                                    if changed.is_err() || *close_rx.borrow() {
                                        return;
                                    }
                                }
                                _ = maintenance_notify.notified() => {}
                                _ = sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                            }
                        },
                        None => {
                            tokio::select! {
                                changed = close_rx.changed() => {
                                    if changed.is_err() || *close_rx.borrow() {
                                        return;
                                    }
                                }
                                _ = maintenance_notify.notified() => {}
                            }
                        },
                    },
                    Err(error) => {
                        warn!(
                            error = %format!("{error:#}"),
                            "failed to plan TUN TCP flow maintenance"
                        );
                        engine.abort_flow_with_rst(&key, "retransmit_build_error").await;
                        return;
                    },
                }
            }
        });
    }

    pub(super) fn spawn_upstream_connect(
        &self,
        key: TcpFlowKey,
        target: TargetAddr,
        flow_id: u64,
        flow: Arc<Mutex<TcpFlowState>>,
        mut close_rx: watch::Receiver<bool>,
        ip_family: &'static str,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            struct AsyncConnectActiveGuard;
            impl Drop for AsyncConnectActiveGuard {
                fn drop(&mut self) {
                    metrics::add_tun_tcp_async_connects_active(-1);
                }
            }

            metrics::add_tun_tcp_async_connects_active(1);
            metrics::record_tun_tcp_async_connect("started");
            let _active_guard = AsyncConnectActiveGuard;

            // Use the flow's bound manager and route — set by handle_new_flow.
            let (manager, route) = {
                let state = flow.lock().await;
                (state.manager.clone(), state.route.clone())
            };

            let is_direct = matches!(route, crate::tun::TunRoute::Direct { .. });

            if is_direct {
                // Direct: plain TcpStream, no Shadowsocks framing.
                let fwmark = match route {
                    crate::tun::TunRoute::Direct { fwmark } => fwmark,
                    _ => None,
                };
                let addr = match crate::transport::resolve_host_with_preference(
                    &format!("{}", target),
                    0, // port already in SocketAddr
                    "resolve direct target",
                    false,
                )
                .await
                {
                    Ok(addrs) if !addrs.is_empty() => addrs[0],
                    _ => {
                        // Fallback: construct from the TargetAddr directly
                        match &target {
                            crate::types::TargetAddr::IpV4(ip, port) => {
                                std::net::SocketAddr::new(std::net::IpAddr::V4(*ip), *port)
                            },
                            crate::types::TargetAddr::IpV6(ip, port) => {
                                std::net::SocketAddr::new(std::net::IpAddr::V6(*ip), *port)
                            },
                            crate::types::TargetAddr::Domain(_, _) => {
                                metrics::record_tun_tcp_async_connect("failed");
                                warn!(flow_id, remote = %target, "direct TUN TCP: domain targets not supported");
                                engine.abort_flow_with_rst(&key, "connect_failed").await;
                                return;
                            },
                        }
                    },
                };
                let stream = match timeout(
                    engine.inner.tcp.connect_timeout,
                    crate::transport::connect_tcp_socket(addr, fwmark),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        metrics::record_tun_tcp_async_connect("failed");
                        warn!(flow_id, remote = %target, error = %format!("{error:#}"), "failed to establish direct TUN TCP connection");
                        engine.abort_flow_with_rst(&key, "connect_failed").await;
                        return;
                    },
                    Err(_) => {
                        metrics::record_tun_tcp_async_connect("timeout");
                        warn!(flow_id, remote = %target, "timed out establishing direct TUN TCP connection");
                        engine.abort_flow_with_rst(&key, "connect_timeout").await;
                        return;
                    },
                };
                let (read_half, write_half) = stream.into_split();
                let upstream_writer = Arc::new(Mutex::new(
                    super::super::state_machine::TunTcpUpstreamWriter::Direct(write_half),
                ));
                {
                    let mut state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                        return;
                    }
                    clear_flow_metrics(&mut state);
                    state.uplink_name = "direct".to_string();
                    state.upstream_writer = Some(Arc::clone(&upstream_writer));
                    let pending = state.pending_client_data.drain(..).collect::<Vec<_>>();
                    let should_close = client_fin_seen(state.status);
                    sync_flow_metrics_and_wake(&mut state);
                    // Send pending data.
                    for payload in pending {
                        let mut w = upstream_writer.lock().await;
                        if let Err(error) = w.send_chunk(&payload).await {
                            drop(w);
                            warn!(flow_id, error = %format!("{error:#}"), "direct TUN TCP send error");
                            engine.abort_flow_with_rst(&key, "send_error").await;
                            return;
                        }
                    }
                    if should_close {
                        close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
                    }
                }
                metrics::record_tun_tcp_async_connect("connected");
                // Spawn a plain reader for the direct stream.
                engine.spawn_direct_upstream_reader(
                    key.clone(),
                    flow.clone(),
                    read_half,
                    close_rx,
                );
                metrics::record_uplink_selected(
                    "tcp",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                info!(flow_id, remote = %target, "created direct TUN TCP flow");
                return;
            }

            // Tunneled path (existing).
            let connected = tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(flow_id, remote = %target, "cancelled pending async TUN TCP upstream connect");
                        return;
                    }
                    metrics::record_tun_tcp_async_connect("cancelled");
                    return;
                }
                result = timeout(
                    engine.inner.tcp.connect_timeout,
                    select_tcp_candidate_and_connect(&manager, &target),
                ) => result,
            };

            let (candidate, upstream_writer, upstream_reader) = match connected {
                Ok(Ok(connected)) => connected,
                Ok(Err(error)) => {
                    metrics::record_tun_tcp_async_connect("failed");
                    warn!(flow_id, remote = %target, error = %format!("{error:#}"), "failed to establish async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_failed").await;
                    return;
                },
                Err(_) => {
                    metrics::record_tun_tcp_async_connect("timeout");
                    warn!(flow_id, remote = %target, timeout_secs = engine.inner.tcp.connect_timeout.as_secs(), "timed out establishing async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_timeout").await;
                    return;
                },
            };

            let upstream_writer = Arc::new(Mutex::new(
                super::super::state_machine::TunTcpUpstreamWriter::Tunneled(upstream_writer),
            ));
            let (pending_payloads, should_close_client_half) = {
                let mut state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                    drop(state);
                    close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
                    return;
                }
                clear_flow_metrics(&mut state);
                state.uplink_index = candidate.index;
                state.uplink_name = candidate.uplink.name.clone();
                state.upstream_writer = Some(Arc::clone(&upstream_writer));
                let pending_payloads = state.pending_client_data.drain(..).collect::<Vec<_>>();
                let should_close_client_half = client_fin_seen(state.status);
                sync_flow_metrics_and_wake(&mut state);
                (pending_payloads, should_close_client_half)
            };
            metrics::record_tun_tcp_async_connect("connected");

            engine.spawn_upstream_reader(
                key.clone(),
                flow.clone(),
                upstream_reader,
                close_rx.clone(),
            );

            for payload in pending_payloads {
                let send_result = {
                    let mut writer = upstream_writer.lock().await;
                    writer.send_chunk(&payload).await
                };
                if let Err(error) = send_result {
                    engine
                        .report_tcp_runtime_failure_and_abort(
                            &key,
                            &manager,
                            candidate.index,
                            &error,
                            "send_error",
                        )
                        .await;
                    return;
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    manager.group_name(),
                    &candidate.uplink.name,
                    payload.len(),
                );
            }

            if should_close_client_half {
                close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
            }

            metrics::record_uplink_selected(
                "tcp",
                manager.group_name(),
                &candidate.uplink.name,
            );
            info!(
                flow_id,
                uplink = %candidate.uplink.name,
                remote = %target,
                ip_family,
                "created TUN TCP flow"
            );
        });
    }

    pub(super) fn spawn_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut upstream_reader: TcpShadowsocksReader,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                let manager = { flow.lock().await.manager.clone() };
                if manager.strict_active_uplink_for(TransportKind::Tcp) {
                    let active_uplink = manager
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await;
                    let should_abort = {
                        let state = flow.lock().await;
                        active_uplink.is_some_and(|active| {
                            state.uplink_index != usize::MAX && state.uplink_index != active
                        })
                    };
                    if should_abort {
                        engine.abort_flow_with_rst(&key, "global_switch").await;
                        return;
                    }
                }

                let read_result = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            debug!("upstream TCP flow reader cancelled");
                            return;
                        }
                        continue;
                    }
                    result = upstream_reader.read_chunk() => result,
                };
                match read_result {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let chunk_len = chunk.len();
                        let (flush, ip_family, backlog_pressure, uplink_name) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk.into());
                            let flush = flush_server_output(&mut state);
                            let backlog_pressure = assess_server_backlog_pressure(
                                &mut state,
                                &engine.inner.tcp,
                                Instant::now(),
                                flush.as_ref().map(|flush| flush.window_stalled).unwrap_or(false),
                            );
                            sync_flow_metrics_and_wake(&mut state);
                            (
                                flush,
                                ip_family_from_version(key.version),
                                backlog_pressure,
                                state.uplink_name.clone(),
                            )
                        };

                        if backlog_pressure.should_abort {
                            let uplink_name = key_uplink_name(&flow).await;
                            let (uplink_index, flow_manager) = {
                                let state = flow.lock().await;
                                (state.uplink_index, state.manager.clone())
                            };
                            let error = anyhow!("server backlog limit exceeded for TUN TCP flow");
                            engine
                                .report_tcp_runtime_failure(&flow_manager, uplink_index, &error)
                                .await;
                            let (cooldown_ms, penalty_ms) = flow_manager
                                .runtime_failure_debug_state(uplink_index, TransportKind::Tcp)
                                .await;
                            warn!(
                                uplink = %uplink_name,
                                uplink_index,
                                cooldown_ms,
                                penalty_ms,
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                grace_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms = backlog_pressure.no_progress_ms.unwrap_or_default(),
                                "closing TUN TCP flow after server backlog limit"
                            );
                            engine.abort_flow_with_rst(&key, "server_backlog_limit").await;
                            return;
                        } else if backlog_pressure.exceeded {
                            debug!(
                                uplink = %uplink_name,
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                over_limit_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms = backlog_pressure.no_progress_ms.unwrap_or_default(),
                                window_stalled = backlog_pressure.window_stalled,
                                "TUN TCP flow is under backlog pressure, delaying abort"
                            );
                        }

                        match flush {
                            Ok(flush) => {
                                let (group_name, uplink_name) =
                                    super::key_group_and_uplink(&flow).await;
                                if flush.window_stalled {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "window_stall",
                                    );
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_stall",
                                    );
                                }
                                for packet in flush.data_packets {
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write TUN TCP data packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                if let Some(packet) = flush.probe_packet {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "zero_window_probe",
                                    );
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write TUN TCP zero-window probe");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_probe",
                                    );
                                }
                                if let Some(packet) = flush.fin_packet {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "deferred_fin_sent",
                                    );
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write deferred TUN TCP FIN packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_fin",
                                    );
                                }
                                metrics::add_bytes(
                                    "tcp",
                                    "upstream_to_client",
                                    &group_name,
                                    &uplink_name,
                                    chunk_len,
                                );
                            },
                            Err(error) => {
                                warn!(error = %format!("{error:#}"), "failed to build TUN TCP data packet");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }
                    },
                    Err(error) => {
                        // Transport errors (e.g. QUIC APPLICATION_CLOSE /
                        // H3_INTERNAL_ERROR) set closed_cleanly=false.  Report
                        // them as uplink runtime failures so the penalty system
                        // can switch to a backup uplink or fall back to H2/H1.
                        // Clean WebSocket closes (FIN, Close frame) do not
                        // indicate an uplink problem and are not reported.
                        if !upstream_reader.closed_cleanly {
                            let (uplink_index, flow_manager) = {
                                let state = flow.lock().await;
                                (state.uplink_index, state.manager.clone())
                            };
                            if crate::error_text::is_websocket_closed(&error) {
                                flow_manager
                                    .report_upstream_close(uplink_index, TransportKind::Tcp)
                                    .await;
                            } else {
                                engine
                                    .report_tcp_runtime_failure(
                                        &flow_manager,
                                        uplink_index,
                                        &error,
                                    )
                                    .await;
                            }
                        }
                        debug!(error = %format!("{error:#}"), "upstream TCP flow reader ended");
                        let flush = {
                            let mut state = flow.lock().await;
                            if state.status == TcpFlowStatus::Closed
                                || server_fin_sent(state.status)
                            {
                                Ok(ServerFlush::default())
                            } else {
                                state.server_fin_pending = true;
                                let flush = flush_server_output(&mut state);
                                sync_flow_metrics_and_wake(&mut state);
                                flush
                            }
                        };

                        match flush {
                            Ok(flush) => {
                                let (group_name, uplink_name) =
                                    super::key_group_and_uplink(&flow).await;
                                let ip_family = ip_family_from_version(key.version);
                                if flush.window_stalled {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "window_stall",
                                    );
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_stall",
                                    );
                                }
                                for packet in flush.data_packets {
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write pending TUN TCP data packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                if let Some(packet) = flush.probe_packet {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "zero_window_probe",
                                    );
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write TUN TCP zero-window probe");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_probe",
                                    );
                                }
                                if let Some(fin) = flush.fin_packet {
                                    metrics::record_tun_tcp_event(
                                        &group_name,
                                        &uplink_name,
                                        "deferred_fin_sent",
                                    );
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&fin).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write TUN TCP FIN packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_fin",
                                    );
                                }
                            },
                            Err(flush_error) => {
                                warn!(error = %format!("{flush_error:#}"), "failed to flush deferred server FIN/data");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }

                        let should_close = {
                            let state = flow.lock().await;
                            state.status == TcpFlowStatus::Closed
                        };
                        if should_close {
                            engine.close_flow(&key, "upstream_closed").await;
                        }
                        return;
                    },
                }
            }
        });
    }

    /// Simpler reader for direct (non-tunneled) TCP flows: reads raw bytes
    /// from the plain `OwnedReadHalf` and pushes them through the same TCP
    /// state machine that synthesises IP packets for the TUN device.
    pub(super) fn spawn_direct_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut read_half: OwnedReadHalf,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16_384];
            loop {
                let read_result = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                    result = read_half.read(&mut buf) => result,
                };
                match read_result {
                    Ok(0) => {
                        // EOF — upstream closed.
                        let ip_family = ip_family_from_version(key.version);
                        let flush = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.server_fin_pending = true;
                            let flush = flush_server_output(&mut state);
                            sync_flow_metrics_and_wake(&mut state);
                            flush
                        };
                        match flush {
                            Ok(flush) => {
                                for packet in flush.data_packets {
                                    if engine.inner.writer.write_packet(&packet).await.is_err() {
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                if let Some(fin) = flush.fin_packet {
                                    if engine.inner.writer.write_packet(&fin).await.is_err() {
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_fin",
                                    );
                                }
                            },
                            Err(_) => {
                                engine.close_flow(&key, "build_packet_error").await;
                            },
                        }
                        return;
                    },
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&buf[..n]);
                        let ip_family = ip_family_from_version(key.version);
                        let flush = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk);
                            let flush = flush_server_output(&mut state);
                            sync_flow_metrics_and_wake(&mut state);
                            flush
                        };
                        match flush {
                            Ok(flush) => {
                                for packet in flush.data_packets {
                                    if engine.inner.writer.write_packet(&packet).await.is_err() {
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                metrics::add_bytes(
                                    "tcp",
                                    "upstream_to_client",
                                    metrics::DIRECT_GROUP_LABEL,
                                    metrics::DIRECT_UPLINK_LABEL,
                                    n,
                                );
                            },
                            Err(error) => {
                                warn!(
                                    error = %format!("{error:#}"),
                                    "failed to flush direct TUN TCP data"
                                );
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }
                    },
                    Err(error) => {
                        debug!(error = %format!("{error:#}"), "direct upstream TCP reader ended");
                        engine.close_flow(&key, "read_error").await;
                        return;
                    },
                }
            }
        });
    }
}
