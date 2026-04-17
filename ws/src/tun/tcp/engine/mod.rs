use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{Mutex, RwLock};

use crate::atomic_counter::CounterU64;
use crate::config::TunTcpConfig;
use crate::metrics;
use super::state_machine::TunTcpUpstreamWriter;
use crate::tun::{SharedTunWriter, TunRouting};
use crate::uplink::{TransportKind, UplinkManager};

use super::state_machine::TcpFlowState;
use super::wire::parse_tcp_packet;
use super::{TCP_FLAG_RST, TcpFlowKey};

mod connect;
mod flow_ops;
mod packet;
mod tasks;
#[cfg(test)]
pub(in crate::tun::tcp) mod tests;

#[derive(Clone)]
pub struct TunTcpEngine {
    pub(super) inner: Arc<TunTcpEngineInner>,
}

pub(super) struct TunTcpEngineInner {
    pub(super) writer: SharedTunWriter,
    pub(super) dispatch: TunRouting,
    pub(super) flows: RwLock<HashMap<TcpFlowKey, Arc<Mutex<TcpFlowState>>>>,
    pub(super) pending_connects: Mutex<HashSet<TcpFlowKey>>,
    pub(super) next_flow_id: CounterU64,
    pub(super) max_flows: usize,
    pub(super) idle_timeout: Duration,
    pub(super) tcp: TunTcpConfig,
    pub(super) dns_cache: Arc<crate::transport::DnsCache>,
}

impl TunTcpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        dispatch: TunRouting,
        max_flows: usize,
        idle_timeout: Duration,
        tcp: TunTcpConfig,
        dns_cache: Arc<crate::transport::DnsCache>,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunTcpEngineInner {
                writer,
                dispatch,
                flows: RwLock::new(HashMap::new()),
                pending_connects: Mutex::new(HashSet::new()),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
                tcp,
                dns_cache,
            }),
        };
        engine.spawn_cleanup_loop();
        engine
    }

    pub fn dns_cache(&self) -> &crate::transport::DnsCache {
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
        self.inner.flows.read().await.get(key).cloned()
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
    flow.lock().await.uplink_name.clone()
}

/// Fetches `(group_name, uplink_name)` for a flow — used where both are
/// needed for the `group`/`uplink` Prometheus labels.
pub(super) async fn key_group_and_uplink(flow: &Arc<Mutex<TcpFlowState>>) -> (Arc<str>, Arc<str>) {
    let state = flow.lock().await;
    (state.group_name.clone(), state.uplink_name.clone())
}

pub(super) use crate::tun::wire::{ip_family_from_version, ip_to_target};
