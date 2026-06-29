use std::sync::Arc;

use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, timeout};
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
use super::super::super::{TunTcpEngine, close_upstream_writer, target_socket_addr};
use crate::sniff::{SNIFF_PEEK_CAP, SniffOutcome, sniff_host};

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
                // SNI bypass: when enabled, peek the first client bytes and, if
                // they carry a TLS SNI / HTTP Host, re-resolve that domain
                // through this node's own resolver and dial the IP *it* returns
                // — not the (possibly dead / foreign-resolved) literal IP the
                // client dialled. `sniff_and_override_target` reuses the peek +
                // exclude-list logic and hands back a `Domain` target for a
                // sniffed, non-excluded host; everything else stays the literal
                // IP. Off by default, so direct keeps the zero-latency IP dial.
                let target = if engine.inner.tcp.sniffing && engine.inner.tcp.sniff_direct_reresolve
                {
                    match engine.sniff_and_override_target(&flow, target, &mut close_rx).await {
                        Some(target) => target,
                        None => {
                            metrics::record_tun_tcp_async_connect("cancelled");
                            debug!(flow_id, "direct TUN TCP flow closed during sniffing");
                            return;
                        },
                    }
                } else {
                    target
                };

                // The TUN ingress carries a literal IP target; map it straight
                // to a SocketAddr. A `Domain` only appears via SNI bypass above —
                // re-resolve it locally to an address this node can reach.
                let addr = match &target {
                    TargetAddr::Domain(host, port) => {
                        match outline_transport::resolve_host_with_preference(
                            engine.dns_cache(),
                            host,
                            *port,
                            "tun_direct_sni",
                            false,
                        )
                        .await
                        {
                            Ok(addrs) if !addrs.is_empty() => {
                                debug!(flow_id, host, resolved = %addrs[0], "direct TUN TCP: SNI re-resolved via local resolver");
                                addrs[0]
                            },
                            other => {
                                metrics::record_tun_tcp_async_connect("failed");
                                warn!(flow_id, host, error = ?other.err(), "direct TUN TCP: local SNI re-resolve failed");
                                engine.abort_flow_with_rst(&key, "connect_failed").await;
                                return;
                            },
                        }
                    },
                    _ => match target_socket_addr(&target) {
                        Some(addr) => addr,
                        None => {
                            metrics::record_tun_tcp_async_connect("failed");
                            warn!(flow_id, remote = %target, "direct TUN TCP: domain targets not supported");
                            engine.abort_flow_with_rst(&key, "connect_failed").await;
                            return;
                        },
                    },
                };
                let stream = match timeout(
                    engine.inner.tcp.connect_timeout,
                    outline_net::connect_tcp_socket_direct(addr, fwmark),
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
                let (group_name, uplink_name, notify) = {
                    let mut state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                        return;
                    }
                    clear_flow_metrics(&mut state);
                    state.routing.uplink_name = Arc::from("direct");
                    state.routing.upstream_writer = Some(Arc::clone(&upstream_writer));
                    let notify = state.signals.upstream_pump.clone();
                    commit_flow_changes(&mut state, &engine.inner.tcp);
                    let group_name = state.routing.group_name.clone();
                    let uplink_name = state.routing.uplink_name.clone();
                    (group_name, uplink_name, notify)
                };
                metrics::record_tun_tcp_async_connect("connected");
                // Reader drains upstream→TUN; pump drains TUN→upstream
                // (including any data/FIN buffered before connect completed),
                // so the shared read-loop never blocks on this flow's send.
                engine.spawn_direct_upstream_reader(
                    key.clone(),
                    flow.clone(),
                    read_half,
                    close_rx.clone(),
                );
                engine.spawn_upstream_pump(
                    key.clone(),
                    flow.clone(),
                    upstream_writer,
                    manager.clone(),
                    usize::MAX,
                    group_name,
                    uplink_name,
                    notify,
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
            //
            // Connection sniffing (Xray destOverride): before selecting an
            // uplink, peek the first client bytes and, if they carry a TLS
            // ClientHello SNI or an HTTP Host, rewrite the literal-IP target
            // into a domain so the request leaves over VLESS/SS as a *domain*
            // and the exit node resolves it. Sniffable flows resolve almost
            // instantly (the TUN stack terminated the handshake locally, so
            // the client already sent its preface); the bounded wait only
            // affects server-speaks-first protocols, which fall back to
            // dialling by IP. Cancellation during the wait aborts the connect.
            let target = if engine.inner.tcp.sniffing {
                match engine.sniff_and_override_target(&flow, target, &mut close_rx).await {
                    Some(target) => target,
                    None => {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(flow_id, "TUN TCP flow closed during sniffing");
                        return;
                    },
                }
            } else {
                target
            };

            // Per-client affinity key: the LAN client's source IP. Consulted
            // only under routing_scope = "per_client"; ignored otherwise.
            let client_id = key.client_ip.to_string();
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
                    select_tcp_candidate_and_connect(&manager, &target, Some(&client_id)),
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
            let (group_name, uplink_name, notify) = {
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
                let notify = state.signals.upstream_pump.clone();
                commit_flow_changes(&mut state, &engine.inner.tcp);
                let group_name = state.routing.group_name.clone();
                let uplink_name = state.routing.uplink_name.clone();
                (group_name, uplink_name, notify)
            };
            metrics::record_tun_tcp_async_connect("connected");

            // Reader drains upstream→TUN; pump drains TUN→upstream (including
            // data/FIN buffered before connect completed), so the shared
            // read-loop never blocks on this flow's upstream back-pressure.
            engine.spawn_upstream_reader(
                key.clone(),
                flow.clone(),
                upstream_reader,
                close_rx.clone(),
            );
            engine.spawn_upstream_pump(
                key.clone(),
                flow.clone(),
                upstream_writer,
                manager.clone(),
                candidate.index,
                group_name,
                uplink_name,
                notify,
                close_rx,
            );

            metrics::record_uplink_selected("tcp", manager.group_name(), &candidate.uplink.name);
            info!(
                flow_id,
                uplink = %candidate.uplink.name,
                remote = %target,
                ip_family,
                "created TUN TCP flow"
            );
        });
    }

    /// Peek the buffered client prefix and, if it carries a recoverable
    /// destination host (TLS SNI / HTTP Host), return a domain target;
    /// otherwise return the original IP target. Returns `None` if the flow is
    /// torn down (or the connect cancelled) while waiting for the preface.
    ///
    /// The buffer is only peeked, never consumed — the same bytes are later
    /// pumped upstream verbatim, so the server still receives the exact
    /// ClientHello / request the client sent.
    pub(in crate::tcp::engine) async fn sniff_and_override_target(
        &self,
        flow: &Arc<Mutex<TcpFlowState>>,
        target: TargetAddr,
        close_rx: &mut watch::Receiver<bool>,
    ) -> Option<TargetAddr> {
        let notify = {
            let state = flow.lock().await;
            state.signals.upstream_pump.clone()
        };
        let deadline = Instant::now() + self.inner.tcp.sniff_timeout;
        loop {
            let (peeked, client_done) = {
                let state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    return None;
                }
                let mut buf = Vec::new();
                for chunk in &state.pending_client_data {
                    if buf.len() >= SNIFF_PEEK_CAP {
                        break;
                    }
                    let take = (SNIFF_PEEK_CAP - buf.len()).min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
                (buf, client_fin_seen(state.status))
            };

            match sniff_host(&peeked) {
                SniffOutcome::Found(host) => {
                    if crate::sniff::host_is_excluded(&host, &self.inner.tcp.sniff_override_exclude)
                    {
                        metrics::record_tun_tcp_sniff("excluded");
                        debug!(host, original = %target, "TUN TCP sniff: host excluded from override, dialing by IP");
                        return Some(target);
                    }
                    let port = target_port(&target);
                    metrics::record_tun_tcp_sniff("override");
                    debug!(host, port, original = %target, "TUN TCP sniff: destination overridden to domain");
                    return Some(TargetAddr::Domain(host, port));
                },
                SniffOutcome::NotMatched => {
                    metrics::record_tun_tcp_sniff("miss");
                    return Some(target);
                },
                SniffOutcome::Incomplete => {
                    if client_done || peeked.len() >= SNIFF_PEEK_CAP {
                        // No more bytes will help (client half-closed, or we
                        // have all we are willing to buffer): dial by IP.
                        metrics::record_tun_tcp_sniff("miss");
                        return Some(target);
                    }
                    tokio::select! {
                        changed = close_rx.changed() => {
                            // A send means the flow was closed; treat any other
                            // outcome (sender dropped) as a teardown too.
                            if changed.is_err() || *close_rx.borrow() {
                                return None;
                            }
                        }
                        _ = notify.notified() => {}
                        _ = tokio::time::sleep_until(deadline) => {
                            metrics::record_tun_tcp_sniff("timeout");
                            return Some(target);
                        }
                    }
                },
            }
        }
    }
}

fn target_port(target: &TargetAddr) -> u16 {
    match target {
        TargetAddr::IpV4(_, port) | TargetAddr::IpV6(_, port) | TargetAddr::Domain(_, port) => {
            *port
        },
    }
}
