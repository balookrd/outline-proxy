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
    pub(super) uplink_health: GaugeVec,
    pub(super) uplink_latency_seconds: GaugeVec,
    pub(super) uplink_rtt_ewma_seconds: GaugeVec,
    pub(super) uplink_penalty_seconds: GaugeVec,
    pub(super) uplink_effective_latency_seconds: GaugeVec,
    pub(super) uplink_score_seconds: GaugeVec,
    pub(super) uplink_weight: GaugeVec,
    pub(super) uplink_cooldown_seconds: GaugeVec,
    pub(super) uplink_standby_ready: IntGaugeVec,
    pub(super) uplink_active_wire_index: IntGaugeVec,
    pub(super) uplink_active_wire_pin_remaining_seconds: GaugeVec,
    pub(super) uplink_configured_fallbacks_count: IntGaugeVec,
    pub(super) selection_mode_info: IntGaugeVec,
    pub(super) routing_scope_info: IntGaugeVec,
    pub(super) global_active_uplink_info: IntGaugeVec,
    pub(super) per_uplink_active_uplink_info: IntGaugeVec,
    pub(super) sticky_routes_total: IntGaugeVec,
    pub(super) sticky_routes_by_uplink: IntGaugeVec,
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
    let uplink_health = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_uplink_health",
        "Current uplink health by transport.",
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
        "EWMA RTT latency used as the probe baseline.",
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

    UplinkFields {
        uplink_selected_total,
        uplink_runtime_failures_total,
        uplink_runtime_failures_suppressed_total,
        uplink_runtime_failure_causes_total,
        uplink_runtime_failure_signatures_total,
        uplink_runtime_failure_other_details_total,
        uplink_failovers_total,
        uplink_health,
        uplink_latency_seconds,
        uplink_rtt_ewma_seconds,
        uplink_penalty_seconds,
        uplink_effective_latency_seconds,
        uplink_score_seconds,
        uplink_weight,
        uplink_cooldown_seconds,
        uplink_standby_ready,
        uplink_active_wire_index,
        uplink_active_wire_pin_remaining_seconds,
        uplink_configured_fallbacks_count,
        selection_mode_info,
        routing_scope_info,
        global_active_uplink_info,
        per_uplink_active_uplink_info,
        sticky_routes_total,
        sticky_routes_by_uplink,
    }
}
