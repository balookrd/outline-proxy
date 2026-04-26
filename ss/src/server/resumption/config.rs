//! Configuration knobs for the cross-transport session-resumption feature.
//!
//! Defaults match `docs/SESSION-RESUMPTION.md`. UDP-related knobs are
//! accepted at the config layer even though the MVP only implements TCP
//! resumption — keeping the resolved struct shape stable as later stages
//! land avoids churn in callers.

use std::time::Duration;

use crate::config::SessionResumptionConfig;

#[derive(Debug, Clone)]
pub(crate) struct ResumptionConfig {
    pub(crate) enabled: bool,
    pub(crate) orphan_ttl_tcp: Duration,
    #[allow(dead_code)]
    pub(crate) orphan_ttl_udp: Duration,
    pub(crate) orphan_per_user_cap: usize,
    pub(crate) orphan_global_cap: usize,
    #[allow(dead_code)]
    pub(crate) udp_orphan_backbuf_bytes: usize,
    #[allow(dead_code)]
    pub(crate) udp_orphan_total_budget_bytes: usize,
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
            udp_orphan_backbuf_bytes: 64 * 1024,
            udp_orphan_total_budget_bytes: 512 * 1024 * 1024,
        }
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
            udp_orphan_backbuf_bytes: cfg.udp_orphan_backbuf_bytes,
            udp_orphan_total_budget_bytes: cfg.udp_orphan_total_budget_bytes,
        }
    }
}
