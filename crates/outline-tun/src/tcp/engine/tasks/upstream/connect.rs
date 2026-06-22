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
    TcpFlowState, TcpFlowStatus, UpstreamWriter, clear_flow_metrics,
};
use super::super::super::connect::select_tcp_candidate_and_connect;
use super::super::super::{TunTcpEngine, close_upstream_writer, target_socket_addr};

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
                // The TUN ingress always carries a literal IP target, so map it
                // straight to a SocketAddr. Re-resolving it through the system
                // resolver (the previous behaviour) stringified the IP back into
                // "<ip>:<port>", which is not a valid host literal and forced a
                // bogus getaddrinfo lookup that blocked on the resolver's
                // multi-second timeout before falling back to this very address.
                let addr = match target_socket_addr(&target) {
                    Some(addr) => addr,
                    None => {
                        metrics::record_tun_tcp_async_connect("failed");
                        warn!(flow_id, remote = %target, "direct TUN TCP: domain targets not supported");
                        engine.abort_flow_with_rst(&key, "connect_failed").await;
                        return;
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
}
