use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::debug;

use crate::atomic_counter::CounterU64;
use crate::metrics;
use crate::transport::is_dropped_oversized_udp_error;
use crate::tun::{SharedTunWriter, TunRoute, TunRouting};
use crate::uplink::TransportKind;

use super::types::{FlowTable, UdpFlowKey};
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
                flows: Arc::new(Mutex::new(HashMap::new())),
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

        let (existing, stale_flow) = {
            let guard = self.inner.flows.lock().await;
            match guard.get(&key) {
                Some(flow) => (
                    Some((
                        flow.id,
                        Arc::clone(&flow.transport),
                        flow.uplink_index,
                        flow.uplink_name.clone(),
                        flow.manager.clone(),
                    )),
                    None::<super::types::UdpFlowState>,
                ),
                None => (None, None),
            }
        };

        // Check per-flow strict-active-uplink against the flow's own group.
        // A group in active_passive / global scope may have repointed; the
        // flow must follow or be torn down.
        let stale_flow = if let Some((.., flow_manager)) = existing.as_ref() {
            if flow_manager.strict_active_uplink_for(TransportKind::Udp) {
                let active_uplink = flow_manager
                    .active_uplink_index_for_transport(TransportKind::Udp)
                    .await;
                let flow_index = existing.as_ref().map(|f| f.2);
                if active_uplink.is_some_and(|active| Some(active) != flow_index) {
                    let mut guard = self.inner.flows.lock().await;
                    guard.remove(&key)
                } else {
                    stale_flow
                }
            } else {
                stale_flow
            }
        } else {
            stale_flow
        };

        if let Some(stale) = stale_flow {
            super::lifecycle::close_udp_flow(stale, "global_switch").await;
        }

        // Re-check flow state after potential removal.
        let existing = if existing.is_some() {
            let guard = self.inner.flows.lock().await;
            guard.get(&key).map(|flow| {
                (
                    flow.id,
                    Arc::clone(&flow.transport),
                    flow.uplink_index,
                    flow.uplink_name.clone(),
                    flow.manager.clone(),
                )
            })
        } else {
            None
        };

        let (flow_id, transport, uplink_index, uplink_name, manager) = match existing {
            Some(existing) => {
                let mut guard = self.inner.flows.lock().await;
                if let Some(flow) = guard.get_mut(&key) {
                    flow.last_seen = Instant::now();
                }
                existing
            },
            None => {
                let route = self.inner.dispatch.resolve(&remote_target).await;
                let manager = match route {
                    TunRoute::Group { manager, .. } => manager,
                    TunRoute::Drop { reason } => {
                        debug!(
                            target = %remote_target,
                            reason,
                            "TUN UDP route: dropping flow"
                        );
                        return Ok(());
                    },
                };
                let (id, t, index, name) = self.create_flow(key.clone(), &manager).await?;
                (id, t, index, name, manager)
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
            metrics::add_udp_datagram("client_to_upstream", &replacement_name);
            metrics::add_bytes("udp", "client_to_upstream", &replacement_name, payload.len());
            debug!(
                flow_id = replacement_flow_id,
                uplink = %replacement_name,
                "recreated TUN UDP flow after send failure"
            );
            let _ = replacement_index;
        } else {
            metrics::add_udp_datagram("client_to_upstream", &uplink_name);
            metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
        }

        Ok(())
    }
}
