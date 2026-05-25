use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use super::macros::register_labeled;
use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Registry};

/// Maximum number of distinct normalized `detail` label values that the
/// `uplink_runtime_failure_other_details_total` metric may track globally.
///
/// `normalize_other_runtime_failure_detail` routes errors that did not match
/// any known signature through this limit.  Once `MAX_DETAIL_CARDINALITY`
/// unique values have been observed, further unseen values are replaced by the
/// sentinel `"other_overflow"` so that a burst of novel error texts cannot
/// cause unbounded growth in the Prometheus label cardinality.
///
/// 64 is intentionally conservative: any deployment with more than 64
/// distinct *un-classifiable* error patterns has a far bigger problem than
/// metric cardinality.
const MAX_DETAIL_CARDINALITY: usize = 64;

static DETAIL_SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

pub fn normalize_other_runtime_failure_detail(error_text: &str) -> String {
    let normalized = normalize_detail_string(error_text);
    intern_detail(normalized)
}

/// Normalize an error string to a compact, metric-safe token.
/// Returns `[a-z_#]+`, max 48 characters, digits replaced by `#`.
fn normalize_detail_string(error_text: &str) -> String {
    let first_line = error_text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("other");
    let mut normalized = String::with_capacity(first_line.len().min(48));
    let mut prev_underscore = false;
    for ch in first_line.to_ascii_lowercase().chars() {
        let mapped = if ch.is_ascii_alphabetic() {
            ch
        } else if ch.is_ascii_digit() {
            '#'
        } else {
            '_'
        };
        if mapped == '_' {
            if prev_underscore {
                continue;
            }
            prev_underscore = true;
        } else {
            prev_underscore = false;
        }
        normalized.push(mapped);
        if normalized.len() >= 48 {
            break;
        }
    }
    let normalized = normalized.trim_matches('_').chars().take(48).collect::<String>();
    if normalized.is_empty() {
        "other".to_string()
    } else {
        normalized
    }
}

/// Guard against unbounded Prometheus label cardinality.
///
/// Returns `detail` unchanged if it has been seen before or if the global
/// pool has not yet reached `MAX_DETAIL_CARDINALITY`.  Once the cap is hit,
/// any *new* unseen value is replaced by `"other_overflow"` so the number
/// of distinct `detail` label values emitted to Prometheus is bounded.
fn intern_detail(detail: String) -> String {
    let pool = DETAIL_SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    // Unwrap: poisoning can only happen on panic inside the lock, which we
    // never do.  Recovering from a poisoned mutex is not worth the complexity.
    let mut seen = pool.lock().unwrap_or_else(|e| e.into_inner());
    if seen.contains(&detail) {
        return detail;
    }
    if seen.len() >= MAX_DETAIL_CARDINALITY {
        return "other_overflow".to_string();
    }
    seen.insert(detail.clone());
    detail
}

#[cfg(test)]
#[path = "tests/uplink.rs"]
mod tests;

pub(super) struct UplinkFields {
    pub(super) uplink_selected_total: IntCounterVec,
    pub(super) uplink_runtime_failures_total: IntCounterVec,
    pub(super) uplink_runtime_failures_suppressed_total: IntCounterVec,
    pub(super) uplink_runtime_failure_causes_total: IntCounterVec,
    pub(super) uplink_runtime_failure_signatures_total: IntCounterVec,
    pub(super) uplink_runtime_failure_other_details_total: IntCounterVec,
    pub(super) uplink_failovers_total: IntCounterVec,
    pub(super) uplink_mid_session_retries_total: IntCounterVec,
    pub(super) uplink_health: GaugeVec,
    pub(super) uplink_health_effective: GaugeVec,
    pub(super) uplink_latency_seconds: GaugeVec,
    pub(super) uplink_rtt_ewma_seconds: GaugeVec,
    pub(super) uplink_active_wire_rtt_ewma_seconds: GaugeVec,
    pub(super) uplink_penalty_seconds: GaugeVec,
    pub(super) uplink_effective_latency_seconds: GaugeVec,
    pub(super) uplink_score_seconds: GaugeVec,
    pub(super) uplink_weight: GaugeVec,
    pub(super) uplink_cooldown_seconds: GaugeVec,
    pub(super) uplink_standby_ready: IntGaugeVec,
    pub(super) uplink_active_wire_index: IntGaugeVec,
    pub(super) uplink_active_wire_pin_remaining_seconds: GaugeVec,
    pub(super) uplink_mode_downgrade_remaining_seconds: GaugeVec,
    pub(super) uplink_mode_downgrade_capped_to_info: IntGaugeVec,
    pub(super) uplink_configured_fallbacks_count: IntGaugeVec,
    pub(super) selection_mode_info: IntGaugeVec,
    pub(super) routing_scope_info: IntGaugeVec,
    pub(super) global_active_uplink_info: IntGaugeVec,
    pub(super) per_uplink_active_uplink_info: IntGaugeVec,
    pub(super) sticky_routes_total: IntGaugeVec,
    pub(super) sticky_routes_by_uplink: IntGaugeVec,
    pub(super) uplink_fingerprint_profile_strategy_info: IntGaugeVec,
    pub(super) uplink_open_connections: IntGaugeVec,
    pub(super) uplink_connection_close_total: IntCounterVec,
    pub(super) socks_tcp_strict_aborts_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> UplinkFields {
    let uplink_selected_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_selected_total",
        "Times an uplink was selected for a transport.",
        ["transport", "group", "uplink"]
    );
    let uplink_runtime_failures_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_runtime_failures_total",
        "Runtime transport failures by uplink.",
        ["transport", "group", "uplink"]
    );
    let uplink_runtime_failures_suppressed_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_runtime_failures_suppressed_total",
        "Runtime failures observed while the uplink was already in cooldown.",
        ["transport", "group", "uplink"]
    );
    let uplink_runtime_failure_causes_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_runtime_failure_causes_total",
        "Runtime transport failures by uplink and classified cause.",
        ["transport", "group", "uplink", "cause"]
    );
    let uplink_runtime_failure_signatures_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_runtime_failure_signatures_total",
        "Runtime transport failures by uplink and normalized failure signature.",
        ["transport", "group", "uplink", "signature"]
    );
    let uplink_runtime_failure_other_details_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_runtime_failure_other_details_total",
        "Runtime transport failures that remained in the 'other' bucket, grouped by a normalized raw detail signature.",
        ["transport", "group", "uplink", "detail"]
    );
    let uplink_failovers_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_failovers_total",
        "Runtime failovers from one uplink to another.",
        ["transport", "group", "from_uplink", "to_uplink"]
    );
    let uplink_mid_session_retries_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_mid_session_retries_total",
        "Ack-Prefix Protocol mid-session retries on the pinned-relay uplink path, by outcome. \
         `success` = redial + replay completed and the relay continued; `failed_redial` = the \
         redial itself failed (no new transport to migrate to); `failed_replay` = redial \
         succeeded but the server's reported `up_acked` offset fell outside the local ring \
         buffer; `buffer_overflow` = a single uplink chunk exceeded the buffer cap so the \
         retry budget for the session was burned without a redial attempt.",
        ["transport", "group", "uplink", "outcome"]
    );
    let uplink_health = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_health",
        "Probe-confirmed uplink health by transport. Reflects only the primary wire's probe verdict; an uplink whose primary is down but whose fallback is delivering traffic still shows 0 here.",
        ["group", "transport", "uplink"]
    );
    let uplink_health_effective = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_health_effective",
        "Effective uplink health by transport: 1 when probe-confirmed OR (for uplinks with at least one fallback) when any wire has dialed successfully within the runtime-failure window. The 'is this uplink delivering traffic?' signal that dashboards should prefer; equals `outline_ws_rust_uplink_health` for single-wire uplinks.",
        ["group", "transport", "uplink"]
    );
    let uplink_latency_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_latency_seconds",
        "Last observed uplink probe latency.",
        ["group", "transport", "uplink"]
    );
    let uplink_rtt_ewma_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_rtt_ewma_seconds",
        "EWMA RTT latency on the primary wire (kept for backward compatibility — \
         see active_wire_rtt_ewma_seconds for the wire actually carrying traffic).",
        ["group", "transport", "uplink"]
    );
    // Latency of the wire that **new sessions currently land on**.
    // Equals `rtt_ewma_seconds` while `active_wire == 0`; on a fallback
    // it reads the corresponding per-fallback-wire EWMA slot. Lets
    // operators alert / graph against the carrier actually in use rather
    // than primary's (potentially stale, potentially belonging to a now-
    // broken wire) measurement.
    let uplink_active_wire_rtt_ewma_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_active_wire_rtt_ewma_seconds",
        "EWMA RTT latency of the wire currently carrying traffic on this uplink \
         (primary's EWMA when active_wire == 0, the matching fallback's slot otherwise).",
        ["group", "transport", "uplink"]
    );
    let uplink_penalty_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_penalty_seconds",
        "Current failure penalty applied to an uplink.",
        ["group", "transport", "uplink"]
    );
    let uplink_effective_latency_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_effective_latency_seconds",
        "Latency used for uplink ranking, including penalty.",
        ["group", "transport", "uplink"]
    );
    let uplink_score_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_score_seconds",
        "Final weighted uplink selection score.",
        ["group", "transport", "uplink"]
    );
    let uplink_weight = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_weight",
        "Configured static weight for each uplink.",
        ["group", "uplink"]
    );
    let uplink_cooldown_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_cooldown_seconds",
        "Remaining cooldown time for an uplink.",
        ["group", "transport", "uplink"]
    );
    let uplink_standby_ready = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_standby_ready",
        "Currently available warm-standby websocket connections.",
        ["group", "transport", "uplink"]
    );
    let uplink_active_wire_index = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_active_wire_index",
        "Index into [primary, fallbacks[0], fallbacks[1], ...] of the wire that new sessions on this uplink+transport currently start with. 0 = primary; non-zero = sticky-fallback after consecutive primary failures. Always 0 for uplinks declared without `[[outline.uplinks.fallbacks]]`.",
        ["group", "transport", "uplink"]
    );
    let uplink_active_wire_pin_remaining_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_active_wire_pin_remaining_seconds",
        "Seconds remaining on the active-wire auto-failback pin for this uplink+transport. Visible only while a non-primary wire is sticky; the metric is cleared once the pin expires and active snaps back to primary.",
        ["group", "transport", "uplink"]
    );
    let uplink_configured_fallbacks_count = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_configured_fallbacks_count",
        "Number of fallback transports declared under `[[outline.uplinks.fallbacks]]` for this uplink. Identity-level (no transport label).",
        ["group", "uplink"]
    );
    let uplink_mode_downgrade_remaining_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_mode_downgrade_remaining_seconds",
        "Seconds remaining on the per-uplink mode-downgrade window for this transport. \
         Visible only while a window is active (runtime-failure / probe-failure / \
         silent-fallback have set or extended `mode_downgrade_until`); the metric \
         is cleared once the window expires. Manual switch via the control plane \
         resets this to 0 instantly.",
        ["group", "transport", "uplink"]
    );
    let uplink_mode_downgrade_capped_to_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_mode_downgrade_capped_to_info",
        "Family-aware ceiling carrier the dispatcher returns from `effective_*_mode` \
         while the per-uplink mode-downgrade window is active. The label `mode` \
         carries the capped carrier (one of `ws_h2`, `ws_h1`, `xhttp_h2`, `xhttp_h1`, \
         `quic`); the gauge is 1 on the active cap and 0 on every other mode. All \
         labels are 0 when no cap is set.",
        ["group", "transport", "uplink", "mode"]
    );
    let selection_mode_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_selection_mode_info",
        "Configured load-balancing selection mode.",
        ["group", "mode"]
    );
    let routing_scope_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_routing_scope_info",
        "Configured routing scope.",
        ["group", "scope"]
    );
    let global_active_uplink_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_global_active_uplink_info",
        "Currently selected active uplink for global routing scope.",
        ["group", "uplink"]
    );
    let per_uplink_active_uplink_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_per_uplink_active_uplink_info",
        "Currently selected active uplink per transport protocol for per_uplink routing scope.",
        ["group", "proto", "uplink"]
    );
    let sticky_routes_total = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_sticky_routes_total",
        "Current number of sticky routes per uplink group.",
        ["group"]
    );
    let sticky_routes_by_uplink = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_sticky_routes_by_uplink",
        "Current number of sticky routes pinned to each uplink.",
        ["group", "uplink"]
    );
    let uplink_fingerprint_profile_strategy_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_fingerprint_profile_strategy_info",
        "Effective browser-fingerprint diversification strategy for this uplink. \
         The label `strategy` is one of `none`, `per_host_stable`, `random`; \
         the gauge is 1 on the active strategy and 0 on the others. Effective \
         means the per-uplink override if set, otherwise the process-wide \
         default wired by `--fingerprint-profile` / top-level \
         `fingerprint_profile`.",
        ["group", "uplink", "strategy"]
    );
    let uplink_open_connections = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_uplink_open_connections",
        "Currently open upstream transports attributed to this uplink, by transport \
         (`tcp`/`udp`). Incremented when a connection is dialled through the uplink, \
         decremented on close. In `Global` / `PerUplink` `active_passive` modes the \
         ingress layer aborts established sessions on switch (SOCKS5 sends TCP RST \
         and TUN sends RST+ACK), so a sustained non-zero reading on a non-active \
         uplink usually points at a stuck transport (drop is still in flight, \
         half-closed downlink waiting on `post_client_eof_downstream`, etc.) rather \
         than the by-design migration gap. Cross-reference with \
         `outline_ws_rust_global_active_uplink_info` / \
         `outline_ws_rust_per_uplink_active_uplink_info` and \
         `outline_ws_rust_socks_tcp_strict_aborts_total` — see the dashboard panel \
         `Inactive uplink open connections (leak)`.",
        ["group", "transport", "uplink"]
    );
    let uplink_connection_close_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_uplink_connection_close_total",
        "Upstream transports closed, classified by whether the uplink they were dialled \
         through was still the active one at close time. `classification` is \
         `active` when the uplink was still active, `inactive` when the active pointer \
         had flipped to a different uplink in the meantime (the connection was a \
         stranded survivor of a switchover), or `unknown` when no active-uplink snapshot \
         was available (e.g. `PerFlow` scope where the concept does not apply). \
         `rate(... {classification=\"inactive\"}[5m])` measures the speed at which \
         leaked sessions drain after a switchover.",
        ["group", "transport", "uplink", "classification"]
    );
    let socks_tcp_strict_aborts_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_socks_tcp_strict_aborts_total",
        "SOCKS5 TCP sessions forcibly terminated because the group is in \
         `active_passive` mode and the active uplink changed away from the one the \
         session was pinned to. The session is closed with TCP RST so the client \
         reconnects through the new active uplink (egress consistency). `reason` mirrors \
         the TUN-side event labels: `global_switch` for an active-uplink flip.",
        ["group", "uplink", "reason"]
    );

    UplinkFields {
        uplink_selected_total,
        uplink_runtime_failures_total,
        uplink_runtime_failures_suppressed_total,
        uplink_runtime_failure_causes_total,
        uplink_runtime_failure_signatures_total,
        uplink_runtime_failure_other_details_total,
        uplink_failovers_total,
        uplink_mid_session_retries_total,
        uplink_health,
        uplink_health_effective,
        uplink_latency_seconds,
        uplink_rtt_ewma_seconds,
        uplink_active_wire_rtt_ewma_seconds,
        uplink_penalty_seconds,
        uplink_effective_latency_seconds,
        uplink_score_seconds,
        uplink_weight,
        uplink_cooldown_seconds,
        uplink_standby_ready,
        uplink_active_wire_index,
        uplink_active_wire_pin_remaining_seconds,
        uplink_mode_downgrade_remaining_seconds,
        uplink_mode_downgrade_capped_to_info,
        uplink_configured_fallbacks_count,
        selection_mode_info,
        routing_scope_info,
        global_active_uplink_info,
        per_uplink_active_uplink_info,
        sticky_routes_total,
        sticky_routes_by_uplink,
        uplink_fingerprint_profile_strategy_info,
        uplink_open_connections,
        uplink_connection_close_total,
        socks_tcp_strict_aborts_total,
    }
}
