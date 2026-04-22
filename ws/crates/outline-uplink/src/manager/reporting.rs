use tracing::info;

use super::super::types::UplinkManager;

/// Collect the unique names of uplinks attempted during TCP chunk-0 phase-1
/// failover, in attempt order.  Accepts an iterator of names from previous
/// failures plus the currently-active uplink name, and returns a deduplicated
/// list.  Used by the dispatch layer to annotate failover log lines and to
/// suppress spurious per-uplink failure attribution when every candidate
/// was tried before the first server byte arrived.
pub fn deduplicate_attempted_uplink_names<'a>(
    previous_attempts: impl IntoIterator<Item = &'a str>,
    current_name: &'a str,
) -> Vec<&'a str> {
    let mut seen: Vec<&'a str> = Vec::new();
    for name in previous_attempts {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    if !seen.contains(&current_name) {
        seen.push(current_name);
    }
    seen
}

pub fn log_uplink_summary(manager: &UplinkManager) {
    log_uplink_summary_named(manager, "default");
}

pub fn log_uplink_summary_named(manager: &UplinkManager, group: &str) {
    info!(
        group,
        uplinks = manager.uplinks().len(),
        mode = ?manager.inner.load_balancing.mode,
        routing_scope = ?manager.inner.load_balancing.routing_scope,
        sticky_ttl_secs = manager.inner.load_balancing.sticky_ttl.as_secs(),
        hysteresis_ms = manager.inner.load_balancing.hysteresis.as_millis() as u64,
        failure_cooldown_secs = manager.inner.load_balancing.failure_cooldown.as_secs(),
        tcp_chunk0_failover_timeout_secs =
            manager.inner.load_balancing.tcp_chunk0_failover_timeout.as_secs(),
        warm_standby_tcp = manager.inner.load_balancing.warm_standby_tcp,
        warm_standby_udp = manager.inner.load_balancing.warm_standby_udp,
        rtt_ewma_alpha = manager.inner.load_balancing.rtt_ewma_alpha,
        failure_penalty_ms = manager.inner.load_balancing.failure_penalty.as_millis() as u64,
        failure_penalty_max_ms =
            manager.inner.load_balancing.failure_penalty_max.as_millis() as u64,
        failure_penalty_halflife_secs = manager
            .inner
            .load_balancing
            .failure_penalty_halflife
            .as_secs(),
        "uplink group initialized"
    );
}
