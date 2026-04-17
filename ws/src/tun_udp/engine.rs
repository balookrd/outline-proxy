use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::UdpSocket;
use tracing::info;

use crate::atomic_counter::CounterU64;
use crate::metrics;
use crate::transport::is_dropped_oversized_udp_error;
use crate::tun::{SharedTunWriter, TunRoute, TunRouting};
use crate::types::TargetAddr;
use crate::uplink::TransportKind;

use super::types::{DirectFlowTable, DirectUdpFlowState, FlowTable, UdpFlowKey};
use super::wire::ParsedUdpPacket;

#[derive(Clone)]
pub struct TunUdpEngine {
    pub(super) inner: Arc<TunUdpEngineInner>,
}

pub(super) struct TunUdpEngineInner {
    pub(super) writer: SharedTunWriter,
    /// Dispatch resolves a flow's destination to a group manager at
    /// creation time; engine code that needs a "default" (cleanup loops,
    /// strict checks without flow context) reads `dispatch.default_group()`.
    pub(super) dispatch: TunRouting,
    pub(super) flows: FlowTable,
    /// Direct-routed flows: per-flow UDP socket + reader task.
    pub(super) direct_flows: DirectFlowTable,
    pub(super) next_flow_id: CounterU64,
    pub(super) max_flows: usize,
    pub(super) idle_timeout: Duration,
}

impl TunUdpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        dispatch: TunRouting,
        max_flows: usize,
        idle_timeout: Duration,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunUdpEngineInner {
                writer,
                dispatch,
                flows: Arc::new(RwLock::new(HashMap::new())),
                direct_flows: Arc::new(RwLock::new(HashMap::new())),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
            }),
        };
        engine.spawn_cleanup_loop();
        engine
    }

    pub(crate) async fn handle_packet(&self, packet: ParsedUdpPacket) -> Result<()> {
        let remote_target = super::ip_to_target(packet.destination_ip, packet.destination_port);
        let key = UdpFlowKey {
            version: packet.version,
            local_ip: packet.source_ip,
            local_port: packet.source_port,
            remote_ip: packet.destination_ip,
            remote_port: packet.destination_port,
        };

        // Check if this is an existing direct flow first. Clone the Arc
        // under a short read-lock, then operate on the per-flow Mutex so
        // concurrent packets on other flows are not serialised.
        let direct_flow = {
            let guard = self.inner.direct_flows.read().await;
            guard.get(&key).map(Arc::clone)
        };
        if let Some(flow_handle) = direct_flow {
            let mut flow = flow_handle.lock().await;
            flow.last_seen = Instant::now();
            let target_addr = SocketAddr::new(key.remote_ip, key.remote_port);
            // `send_to().await` runs under the per-flow Mutex only — other
            // direct flows remain unblocked while the kernel completes the
            // send. Ordering of datagrams within this flow is preserved.
            flow.socket
                .send_to(&packet.payload, target_addr)
                .await
                .context("direct UDP send failed")?;
            metrics::add_udp_datagram(
                "client_to_upstream",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
            );
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
                packet.payload.len(),
            );
            return Ok(());
        }

        // Tunnel-flow hot path: short read-lock, clone `Arc<Mutex<State>>`.
        let existing_handle = self.inner.flows.read().await.get(&key).map(Arc::clone);

        // If this flow exists, snapshot what we need under the per-flow lock,
        // update last_seen, and drop the lock before any .await on the send.
        let existing_tuple = if let Some(handle) = existing_handle.as_ref() {
            let mut flow = handle.lock().await;
            flow.last_seen = Instant::now();
            Some((
                flow.id,
                Arc::clone(&flow.transport),
                flow.uplink_index,
                flow.uplink_name.clone(),
                flow.manager.clone(),
            ))
        } else {
            None
        };

        // Check per-flow strict-active-uplink against the flow's own group.
        // A group in active_passive / global scope may have repointed; the
        // flow must follow or be torn down. The removal takes the write-lock
        // only if the flow is actually stale — common case is no-op.
        let existing_tuple = if let Some((_, _, flow_index, _, ref flow_manager)) =
            existing_tuple
        {
            if flow_manager.strict_active_uplink_for(TransportKind::Udp) {
                let active_uplink = flow_manager
                    .active_uplink_index_for_transport(TransportKind::Udp)
                    .await;
                if active_uplink.is_some_and(|active| active != flow_index) {
                    let stale = self.inner.flows.write().await.remove(&key);
                    if let Some(stale) = stale {
                        super::lifecycle::close_udp_flow(stale, "global_switch").await;
                    }
                    None
                } else {
                    existing_tuple
                }
            } else {
                existing_tuple
            }
        } else {
            existing_tuple
        };

        let (flow_id, transport, uplink_index, uplink_name, manager) = match existing_tuple {
            Some(existing) => existing,
            None => {
                let route = self.inner.dispatch.resolve(&remote_target).await;
                match route {
                    TunRoute::Direct { fwmark } => {
                        return self
                            .handle_direct_packet(key, &remote_target, &packet, fwmark)
                            .await;
                    },
                    TunRoute::Drop { reason } => {
                        debug!(
                            target = %remote_target,
                            reason,
                            "TUN UDP route: dropping flow"
                        );
                        return Ok(());
                    },
                    TunRoute::Group { manager, .. } => {
                        let (id, t, index, name) =
                            self.create_flow(key.clone(), &manager).await?;
                        (id, t, index, name, manager)
                    },
                }
            },
        };

        let payload = super::build_udp_payload(&remote_target, &packet.payload)?;
        if let Err(error) = transport.send_packet(&payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            let (replacement_flow_id, replacement_transport, replacement_index, replacement_name) =
                self.recreate_flow_after_send_error(
                    &key,
                    flow_id,
                    uplink_index,
                    &uplink_name,
                    &manager,
                    &error,
                )
                .await?;
            if let Err(error) = replacement_transport.send_packet(&payload).await {
                if is_dropped_oversized_udp_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
            metrics::add_udp_datagram(
                "client_to_upstream",
                manager.group_name(),
                &replacement_name,
            );
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                manager.group_name(),
                &replacement_name,
                payload.len(),
            );
            debug!(
                flow_id = replacement_flow_id,
                uplink = %replacement_name,
                "recreated TUN UDP flow after send failure"
            );
            let _ = replacement_index;
        } else {
            metrics::add_udp_datagram("client_to_upstream", manager.group_name(), &uplink_name);
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                manager.group_name(),
                &uplink_name,
                payload.len(),
            );
        }

        Ok(())
    }

    /// Handle a packet that resolved to `via = "direct"`: open (or reuse) a
    /// plain UDP socket, send the datagram, and spawn a response reader that
    /// writes synthetic IP+UDP packets back into the TUN device.
    async fn handle_direct_packet(
        &self,
        key: UdpFlowKey,
        remote_target: &TargetAddr,
        packet: &ParsedUdpPacket,
        fwmark: Option<u32>,
    ) -> Result<()> {
        let target_addr = SocketAddr::new(key.remote_ip, key.remote_port);
        let bind_addr = match key.remote_ip {
            std::net::IpAddr::V4(_) => SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            ),
            std::net::IpAddr::V6(_) => SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                0,
            ),
        };
        let std_sock = crate::transport::bind_udp_socket(bind_addr, fwmark)
            .with_context(|| format!("failed to bind direct UDP socket for TUN flow to {remote_target}"))?;
        let sock = Arc::new(UdpSocket::from_std(std_sock)?);
        sock.send_to(&packet.payload, target_addr)
            .await
            .context("direct TUN UDP send failed")?;

        let flow_id = self
            .inner
            .next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Instant::now();

        // Spawn a reader task that receives responses on this socket and writes
        // them as synthetic IP+UDP packets back into the TUN device.
        let reader_sock = Arc::clone(&sock);
        let writer = self.inner.writer.clone();
        let reader_key = key.clone();
        let direct_flows = Arc::clone(&self.inner.direct_flows);
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (len, src_addr) = match reader_sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let src_target = crate::types::socket_addr_to_target(src_addr);
                let response_packet = match super::wire::build_response_packet(
                    reader_key.version,
                    &src_target,
                    reader_key.local_ip,
                    reader_key.local_port,
                    &buf[..len],
                ) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                    len,
                );
                if writer.write_packet(&response_packet).await.is_err() {
                    break;
                }
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    super::ip_family_from_version(reader_key.version),
                    "accepted",
                );
                // Update last_seen on the flow. Read-lock to clone the Arc,
                // then per-flow Mutex — does not block other flows' I/O.
                let handle = direct_flows.read().await.get(&reader_key).map(Arc::clone);
                if let Some(handle) = handle {
                    let mut flow = handle.lock().await;
                    if flow.id == flow_id {
                        flow.last_seen = Instant::now();
                    }
                }
            }
        });

        self.inner.direct_flows.write().await.insert(
            key,
            Arc::new(Mutex::new(DirectUdpFlowState {
                id: flow_id,
                socket: sock,
                _reader: reader,
                created_at: now,
                last_seen: now,
            })),
        );

        metrics::add_udp_datagram(
            "client_to_upstream",
            metrics::DIRECT_GROUP_LABEL,
            metrics::DIRECT_UPLINK_LABEL,
        );
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            metrics::DIRECT_GROUP_LABEL,
            metrics::DIRECT_UPLINK_LABEL,
            packet.payload.len(),
        );
        metrics::record_tun_flow_created(metrics::DIRECT_GROUP_LABEL, metrics::DIRECT_UPLINK_LABEL);
        info!(
            flow_id,
            target = %remote_target,
            "created direct TUN UDP flow"
        );
        Ok(())
    }
}
