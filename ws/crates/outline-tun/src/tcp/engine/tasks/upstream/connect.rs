use std::sync::Arc;

use tokio::sync::{Mutex, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use outline_metrics as metrics;
use outline_transport::TcpWriter;
use socks5_proto::TargetAddr;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, UpstreamWriter, clear_flow_metrics, client_fin_seen,
};
use super::super::super::connect::select_tcp_candidate_and_connect;
use super::super::super::{TunTcpEngine, close_upstream_writer};

impl TunTcpEngine {
    pub(in crate::tcp::engine) fn spawn_upstream_connect(
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
                (state.routing.manager.clone(), state.routing.route.clone())
            };

            let is_direct = matches!(route, crate::TunRoute::Direct { .. });

            if is_direct {
                // Direct: plain TcpStream, no Shadowsocks framing.
                let fwmark = match route {
                    crate::TunRoute::Direct { fwmark } => fwmark,
                    _ => None,
                };
                let addr = match outline_transport::resolve_host_with_preference(
                    engine.dns_cache(),
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
                            socks5_proto::TargetAddr::IpV4(ip, port) => {
                                std::net::SocketAddr::new(std::net::IpAddr::V4(*ip), *port)
                            },
                            socks5_proto::TargetAddr::IpV6(ip, port) => {
                                std::net::SocketAddr::new(std::net::IpAddr::V6(*ip), *port)
                            },
                            socks5_proto::TargetAddr::Domain(_, _) => {
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
                    outline_net::connect_tcp_socket(addr, fwmark),
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
                let upstream_writer = Arc::new(Mutex::new(UpstreamWriter::Direct(write_half)));
                {
                    let mut state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                        return;
                    }
                    clear_flow_metrics(&mut state);
                    state.routing.uplink_name = Arc::from("direct");
                    state.routing.upstream_writer = Some(Arc::clone(&upstream_writer));
                    let pending = std::mem::take(&mut state.pending_client_data);
                    let should_close = client_fin_seen(state.status);
                    commit_flow_changes(&mut state, &engine.inner.tcp);
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

            let upstream_writer = Arc::new(Mutex::new(match upstream_writer {
                TcpWriter::Ws(w) => UpstreamWriter::TunneledWs(w),
                TcpWriter::Socket(w) => UpstreamWriter::TunneledSocket(w),
                TcpWriter::Vless(w) => UpstreamWriter::TunneledVless(w),
                #[cfg(feature = "quic")]
                TcpWriter::QuicSs(w) => UpstreamWriter::TunneledQuicSs(w),
            }));
            let (pending_payloads, should_close_client_half) = {
                let mut state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                    drop(state);
                    close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
                    return;
                }
                clear_flow_metrics(&mut state);
                state.routing.uplink_index = candidate.index;
                state.routing.uplink_name = Arc::from(candidate.uplink.name.as_str());
                state.routing.upstream_writer = Some(Arc::clone(&upstream_writer));
                let pending_payloads = std::mem::take(&mut state.pending_client_data);
                let should_close_client_half = client_fin_seen(state.status);
                commit_flow_changes(&mut state, &engine.inner.tcp);
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
}
