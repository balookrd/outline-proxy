use super::macros::register_labeled;
use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Registry};

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
        selection_mode_info,
        routing_scope_info,
        global_active_uplink_info,
        per_uplink_active_uplink_info,
        sticky_routes_total,
        sticky_routes_by_uplink,
    }
}
