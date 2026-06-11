//! Configuration knobs for the cross-transport session-resumption feature.
//!
//! Defaults match `docs/SESSION-RESUMPTION.md`.

use std::time::Duration;

use crate::config::SessionResumptionConfig;

#[derive(Debug, Clone)]
pub(crate) struct ResumptionConfig {
    pub(crate) enabled: bool,
    pub(crate) orphan_ttl_tcp: Duration,
    pub(crate) orphan_ttl_udp: Duration,
    pub(crate) orphan_per_user_cap: usize,
    pub(crate) orphan_global_cap: usize,
    /// Per-session capacity of the v2 Symmetric Downlink Replay ring
    /// buffer. `0` keeps v2 server-side disabled even when the rest of
    /// session resumption is enabled — the capability is never
    /// echoed and the relay path skips ring allocation.
    pub(crate) downlink_buffer_bytes: usize,
}

impl ResumptionConfig {
    /// Defaults from `docs/SESSION-RESUMPTION.md`. The feature is OFF unless
    /// explicitly enabled by config.
    pub(crate) fn defaults_disabled() -> Self {
        Self {
            enabled: false,
            orphan_ttl_tcp: Duration::from_secs(30),
            orphan_ttl_udp: Duration::from_secs(30),
            orphan_per_user_cap: 4,
            orphan_global_cap: 10_000,
            downlink_buffer_bytes: 0,
        }
    }

    /// Whether the v2 Symmetric Downlink Replay protocol is enabled
    /// server-side: requires both the parent feature on and a
    /// non-zero ring capacity.
    pub(crate) fn symmetric_replay_enabled(&self) -> bool {
        self.enabled && self.downlink_buffer_bytes > 0
    }
}

impl Default for ResumptionConfig {
    fn default() -> Self {
        Self::defaults_disabled()
    }
}

impl From<&SessionResumptionConfig> for ResumptionConfig {
    fn from(cfg: &SessionResumptionConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            orphan_ttl_tcp: Duration::from_secs(cfg.orphan_ttl_tcp_secs),
            orphan_ttl_udp: Duration::from_secs(cfg.orphan_ttl_udp_secs),
            orphan_per_user_cap: cfg.orphan_per_user_cap,
            orphan_global_cap: cfg.orphan_global_cap,
            downlink_buffer_bytes: cfg.downlink_buffer_bytes,
        }
    }
}
