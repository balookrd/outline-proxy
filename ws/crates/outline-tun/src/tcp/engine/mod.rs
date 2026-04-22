use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::atomic_counter::CounterU64;
use crate::config::TunTcpConfig;
use outline_metrics as metrics;
use super::state_machine::{ServerFlush, TunTcpUpstreamWriter, build_flow_ack_packet, build_flow_syn_ack_packet};
use crate::{SharedTunWriter, TunRouting};
use outline_uplink::{TransportKind, UplinkManager};

use super::state_machine::TcpFlowState;
use super::wire::parse_tcp_packet;
use super::{TCP_FLAG_ACK, TCP_FLAG_RST, TcpFlowKey};

mod connect;
mod flow_ops;
mod packet;
pub(in crate::tcp) mod scheduler;
mod tasks;
#[cfg(test)]
pub(in crate::tcp) mod tests;

#[derive(Clone)]
pub struct TunTcpEngine {
    pub(super) inner: Arc<TunTcpEngineInner>,
}

pub(super) struct TunTcpEngineInner {
    pub(super) writer: SharedTunWriter,
    pub(super) dispatch: TunRouting,
    pub(super) flows: DashMap<TcpFlowKey, Arc<Mutex<TcpFlowState>>>,
    pub(super) pending_connects: Mutex<HashSet<TcpFlowKey>>,
    pub(super) next_flow_id: CounterU64,
    pub(super) max_flows: usize,
    pub(super) idle_timeout: Duration,
    pub(super) tcp: Arc<TunTcpConfig>,
    pub(super) dns_cache: Arc<outline_transport::DnsCache>,
    /// Shared deadline priority queue for the central maintenance loop.
    /// Flows push new deadlines here whenever their state changes; the
    /// single `spawn_maintenance_loop` task consumes entries in time order.
    pub(super) scheduler: Arc<scheduler::FlowScheduler>,
}

impl TunTcpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        dispatch: TunRouting,
        max_flows: usize,
        idle_timeout: Duration,
        tcp: TunTcpConfig,
        dns_cache: Arc<outline_transport::DnsCache>,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunTcpEngineInner {
                writer,
                dispatch,
                flows: DashMap::new(),
                pending_connects: Mutex::new(HashSet::new()),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
                tcp: Arc::new(tcp),
                dns_cache,
                scheduler: Arc::new(scheduler::FlowScheduler::new()),
            }),
        };
        engine.spawn_cleanup_loop();
        engine.spawn_maintenance_loop();
        engine
    }

    pub fn dns_cache(&self) -> &outline_transport::DnsCache {
        &self.inner.dns_cache
    }


    pub async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        let parsed = parse_tcp_packet(packet)?;
        let key = TcpFlowKey {
            version: parsed.version,
            client_ip: parsed.source_ip,
            client_port: parsed.source_port,
            remote_ip: parsed.destination_ip,
            remote_port: parsed.destination_port,
        };
        let ip_family = ip_family_from_version(parsed.version);
        let flow = self.lookup_flow(&key).await;
        match flow {
            Some(flow) => self.handle_existing_flow(flow, parsed).await,
            None if (parsed.flags & TCP_FLAG_RST) != 0 => {
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_rst_observed");
                Ok(())
            },
            None => self.handle_new_flow(key, parsed).await,
        }
    }

    pub(super) async fn lookup_flow(&self, key: &TcpFlowKey) -> Option<Arc<Mutex<TcpFlowState>>> {
        self.inner.flows.get(key).map(|v| Arc::clone(v.value()))
    }

    pub(super) async fn write_tun_packet_or_close_flow(
        &self,
        key: &TcpFlowKey,
        packet: &[u8],
    ) -> Result<()> {
        if let Err(error) = self.inner.writer.write_packet(packet).await {
            self.close_flow(key, "write_tun_error").await;
            return Err(error);
        }
        Ok(())
    }

    // Emit the packets produced by `flush_server_output` to the TUN,
    // recording per-stage metrics (window-stall, data, zero-window probe,
    // deferred FIN). On write failure the caller is expected to close the
    // flow — this method records the first failure and bubbles it up.
    pub(super) async fn write_server_flush(
        &self,
        key: &TcpFlowKey,
        flush: ServerFlush,
        group_name: &str,
        uplink_name: &str,
    ) -> Result<()> {
        let ip_family = ip_family_from_version(key.version);
        if flush.window_stalled {
            metrics::record_tun_tcp_event(group_name, uplink_name, "window_stall");
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
        }
        for packet in flush.data_packets {
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
        }
        if let Some(packet) = flush.probe_packet {
            metrics::record_tun_tcp_event(group_name, uplink_name, "zero_window_probe");
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
        }
        if let Some(packet) = flush.fin_packet {
            metrics::record_tun_tcp_event(group_name, uplink_name, "deferred_fin_sent");
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
        }
        Ok(())
    }

    /// Variant of [`write_server_flush`] that closes the flow on the first
    /// TUN-write error instead of bubbling the error up to the caller. Used
    /// by the per-packet path in `handle_existing_flow`, where a write
    /// failure means the flow is dead and the caller cannot retry.
    pub(super) async fn write_server_flush_or_close(
        &self,
        key: &TcpFlowKey,
        flush: ServerFlush,
        group_name: &str,
        uplink_name: &str,
    ) -> Result<()> {
        let ip_family = ip_family_from_version(key.version);
        if flush.window_stalled {
            metrics::record_tun_tcp_event(group_name, uplink_name, "window_stall");
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
        }
        for packet in flush.data_packets {
            self.write_tun_packet_or_close_flow(key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
        }
        if let Some(packet) = flush.probe_packet {
            metrics::record_tun_tcp_event(group_name, uplink_name, "zero_window_probe");
            self.write_tun_packet_or_close_flow(key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
        }
        if let Some(packet) = flush.fin_packet {
            metrics::record_tun_tcp_event(group_name, uplink_name, "deferred_fin_sent");
            self.write_tun_packet_or_close_flow(key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
        }
        Ok(())
    }

    /// Build a pure-ACK packet from the current state (server_seq /
    /// client_next_seq), drop the passed-in state guard so the TUN write
    /// doesn't run under the per-flow lock, then write the packet and
    /// record the `tcp_ack` metric.
    pub(super) async fn write_pure_ack_and_drop(
        &self,
        state: tokio::sync::MutexGuard<'_, TcpFlowState>,
        ip_family: &'static str,
    ) -> Result<()> {
        let ack = build_flow_ack_packet(
            &state,
            state.server_seq,
            state.client_next_seq,
            TCP_FLAG_ACK,
        )?;
        let key = state.key.clone();
        drop(state);
        self.write_tun_packet_or_close_flow(&key, &ack).await?;
        metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        Ok(())
    }

    /// Build a SYN/ACK retransmit from the current state and write it to
    /// the TUN, mirroring [`write_pure_ack_and_drop`] for the handshake
    /// path. The state guard is dropped before the async write.
    pub(super) async fn write_syn_ack_and_drop(
        &self,
        state: tokio::sync::MutexGuard<'_, TcpFlowState>,
        ip_family: &'static str,
    ) -> Result<()> {
        let syn_ack = build_flow_syn_ack_packet(
            &state,
            state.server_seq.wrapping_sub(1),
            state.client_next_seq,
        )?;
        let key = state.key.clone();
        drop(state);
        self.write_tun_packet_or_close_flow(&key, &syn_ack).await?;
        metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_synack");
        Ok(())
    }

    pub(super) async fn write_ack_packet_with_event(
        &self,
        key: &TcpFlowKey,
        ack: Vec<u8>,
        ip_family: &'static str,
        group_name: &str,
        uplink_name: &str,
        event: &'static str,
    ) -> Result<()> {
        self.write_tun_packet_or_close_flow(key, &ack).await?;
        metrics::record_tun_tcp_event(group_name, uplink_name, event);
        metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        Ok(())
    }

    pub(super) async fn report_tcp_runtime_failure(
        &self,
        manager: &UplinkManager,
        uplink_index: usize,
        error: &anyhow::Error,
    ) {
        if uplink_index == usize::MAX {
            return;
        }
        manager
            .report_runtime_failure(uplink_index, TransportKind::Tcp, error)
            .await;
    }

    pub(super) async fn report_tcp_runtime_failure_and_abort(
        &self,
        key: &TcpFlowKey,
        manager: &UplinkManager,
        uplink_index: usize,
        error: &anyhow::Error,
        reason: &'static str,
    ) {
        self.report_tcp_runtime_failure(manager, uplink_index, error).await;
        self.abort_flow_with_rst(key, reason).await;
    }
}

pub(super) async fn close_upstream_writer(
    upstream_writer: Option<Arc<Mutex<TunTcpUpstreamWriter>>>,
) {
    let Some(upstream_writer) = upstream_writer else {
        return;
    };
    let mut upstream_writer = upstream_writer.lock().await;
    let _ = upstream_writer.close().await;
}

pub(super) async fn key_uplink_name(flow: &Arc<Mutex<TcpFlowState>>) -> Arc<str> {
    flow.lock().await.routing.uplink_name.clone()
}

/// Fetches `(group_name, uplink_name)` for a flow — used where both are
/// needed for the `group`/`uplink` Prometheus labels.
pub(super) async fn key_group_and_uplink(flow: &Arc<Mutex<TcpFlowState>>) -> (Arc<str>, Arc<str>) {
    let state = flow.lock().await;
    (state.routing.group_name.clone(), state.routing.uplink_name.clone())
}

pub(super) use crate::wire::{ip_family_from_version, ip_to_target};

/// Policy predicate: returns `true` when a flow bound to `flow_uplink_index`
/// must be torn down because its group is in strict-active-uplink mode and
/// has repointed to a different uplink. The `usize::MAX` sentinel marks a
/// flow that hasn't been bound to an uplink yet (SynReceived mid-handshake)
/// — such flows are never migrated.
pub(super) async fn should_migrate_tcp_flow(
    manager: &UplinkManager,
    flow_uplink_index: usize,
) -> bool {
    if !manager.strict_active_uplink_for(TransportKind::Tcp) {
        return false;
    }
    manager
        .active_uplink_index_for_transport(TransportKind::Tcp)
        .await
        .is_some_and(|active| {
            flow_uplink_index != usize::MAX && flow_uplink_index != active
        })
}
