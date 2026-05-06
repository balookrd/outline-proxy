use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};

use super::super::types::UplinkManager;

impl UplinkManager {
    /// Test-only constructor that supplies a fresh throwaway
    /// [`DnsCache`](outline_transport::DnsCache) so existing tests do not need
    /// to build one at every call site.
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

    /// Test helper: snapshot of full UplinkStatus for uplink `index`.
    /// Visibility is `pub(crate)` because `UplinkStatus` itself is
    /// crate-private; the helper is only consumed by inline tests in
    /// this crate. `allow(dead_code)` because it isn't called in the
    /// non-test lib build (test_helpers.rs is included via cfg-gated
    /// `#[path]` for both `cfg(test)` and `feature = "test-helpers"`,
    /// and the latter activates without Rust knowing the inline tests
    /// will pick up the helpers).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn read_status_for_test(
        &self,
        index: usize,
    ) -> crate::manager::status::UplinkStatus {
        self.inner.read_status(index)
    }

    /// Test helper: feed a synthetic [`ProbeOutcome`] through the same path
    /// the scheduler uses, so probe-driven side effects (health flip,
    /// streak counters, mode-downgrade window, early active-wire failback)
    /// run without spinning up real probe targets. `pub(crate)` for the
    /// same reason as `read_status_for_test` — `ProbeOutcome` is
    /// crate-private, the helper is only used by inline tests.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_apply_probe_outcome_for_test(
        &self,
        index: usize,
        outcome: crate::manager::probe::outcome::ProbeOutcome,
    ) {
        // The real scheduler walks `process_probe_ok` with the per-uplink
        // effective TCP/UDP modes; for tests we read them off the uplink
        // config directly (no async-friendly accessor here, so block).
        let uplink = self.uplinks()[index].clone();
        let effective_tcp = uplink.tcp_dial_mode();
        let effective_udp = uplink.udp_dial_mode();
        let mut h3_tcp_recovery = Vec::new();
        let mut h3_udp_recovery = Vec::new();
        let _ = self.process_probe_ok(
            index,
            &uplink,
            outcome,
            effective_tcp,
            effective_udp,
            &mut h3_tcp_recovery,
            &mut h3_udp_recovery,
        );
    }

    /// Feed a synthetic probe error through `process_probe_err`. Mirrors
    /// `test_apply_probe_outcome_for_test` for the failure side: lets
    /// inline tests exercise the failure-path bookkeeping (active-wire
    /// advance on probe machinery error, consecutive_failures streak,
    /// cooldown / penalty) without standing up real probe targets.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) fn test_apply_probe_err_for_test(&self, index: usize, error: anyhow::Error) {
        let uplink = self.uplinks()[index].clone();
        self.process_probe_err(index, &uplink, error);
    }
}
