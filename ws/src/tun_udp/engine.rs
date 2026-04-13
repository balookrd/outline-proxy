use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::debug;

use crate::atomic_counter::CounterU64;
use crate::metrics;
use crate::transport::is_dropped_oversized_udp_error;
use crate::tun::SharedTunWriter;
use crate::uplink::{TransportKind, UplinkManager};

use super::types::{FlowTable, UdpFlowKey};
use super::wire::ParsedUdpPacket;

#[derive(Clone)]
pub struct TunUdpEngine {
    pub(super) inner: Arc<TunUdpEngineInner>,
}

pub(super) struct TunUdpEngineInner {
    pub(super) writer: SharedTunWriter,
    pub(super) uplinks: UplinkManager,
    pub(super) flows: FlowTable,
    pub(super) next_flow_id: CounterU64,
    pub(super) max_flows: usize,
    pub(super) idle_timeout: Duration,
}

impl TunUdpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        uplinks: UplinkManager,
        max_flows: usize,
        idle_timeout: Duration,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunUdpEngineInner {
                writer,
                uplinks,
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

        let active_uplink = if self.inner.uplinks.strict_active_uplink_for(TransportKind::Udp) {
            self.inner
                .uplinks
                .active_uplink_index_for_transport(TransportKind::Udp)
                .await
        } else {
            None
        };

        let (existing, stale_flow) = {
            let mut guard = self.inner.flows.lock().await;
            match guard.get(&key) {
                Some(flow) if active_uplink.is_some_and(|active| active != flow.uplink_index) => {
                    let stale = guard.remove(&key).expect("stale TUN UDP flow must exist");
                    (None, Some(stale))
                },
                Some(_) => {
                    let flow = guard.get_mut(&key).expect("TUN UDP flow must still exist");
                    flow.last_seen = Instant::now();
                    (
                        Some((
                            flow.id,
                            Arc::clone(&flow.transport),
                            flow.uplink_index,
                            flow.uplink_name.clone(),
                        )),
                        None,
                    )
                },
                None => (None, None),
            }
        };

        if let Some(stale_flow) = stale_flow {
            super::lifecycle::close_udp_flow(stale_flow, "global_switch").await;
        }

        let (flow_id, transport, uplink_index, uplink_name) = match existing {
            Some(existing) => existing,
            None => self.create_flow(key.clone()).await?,
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
