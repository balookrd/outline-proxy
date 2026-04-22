use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};

use super::super::types::UplinkManager;

impl UplinkManager {
    /// Test-only constructor that supplies a fresh throwaway [`DnsCache`] so
    /// existing tests do not need to build one at every call site.
    pub fn new_for_test(
        group_name: impl Into<String>,
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
    ) -> Result<Self> {
        Self::new(
            group_name,
            uplinks,
            probe,
            load_balancing,
            Arc::new(outline_transport::DnsCache::default()),
        )
    }

    /// Test helper: directly set TCP health / latency for uplink `index`.
    #[doc(hidden)]
    pub async fn test_set_tcp_health(&self, index: usize, healthy: bool, rtt_ms: u64) {
        self.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(healthy);
            status.tcp.latency = Some(Duration::from_millis(rtt_ms));
            status.tcp.rtt_ewma = Some(Duration::from_millis(rtt_ms));
        });
    }

    /// Test helper: directly set UDP health / latency for uplink `index`.
    #[doc(hidden)]
    pub async fn test_set_udp_health(&self, index: usize, healthy: bool, rtt_ms: u64) {
        self.inner.with_status_mut(index, |status| {
            status.udp.healthy = Some(healthy);
            status.udp.latency = Some(Duration::from_millis(rtt_ms));
            status.udp.rtt_ewma = Some(Duration::from_millis(rtt_ms));
        });
    }

    /// Test helper: read tcp_healthy for uplink `index`.
    #[doc(hidden)]
    pub async fn test_tcp_healthy(&self, index: usize) -> Option<bool> {
        self.inner.read_status(index).tcp.healthy
    }
}
