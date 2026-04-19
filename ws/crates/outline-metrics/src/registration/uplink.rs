use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Opts, Registry};

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
    let uplink_selected_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_selected_total",
            "Times an uplink was selected for a transport.",
        ),
        &["transport", "group", "uplink"],
    )
    .expect("uplink_selected_total metric");

    let uplink_runtime_failures_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_runtime_failures_total",
            "Runtime transport failures by uplink.",
        ),
        &["transport", "group", "uplink"],
    )
    .expect("uplink_runtime_failures_total metric");

    let uplink_runtime_failures_suppressed_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_runtime_failures_suppressed_total",
            "Runtime failures observed while the uplink was already in cooldown.",
        ),
        &["transport", "group", "uplink"],
    )
    .expect("uplink_runtime_failures_suppressed_total metric");

    let uplink_runtime_failure_causes_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_runtime_failure_causes_total",
            "Runtime transport failures by uplink and classified cause.",
        ),
        &["transport", "group", "uplink", "cause"],
    )
    .expect("uplink_runtime_failure_causes_total metric");

    let uplink_runtime_failure_signatures_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_runtime_failure_signatures_total",
            "Runtime transport failures by uplink and normalized failure signature.",
        ),
        &["transport", "group", "uplink", "signature"],
    )
    .expect("uplink_runtime_failure_signatures_total metric");

    let uplink_runtime_failure_other_details_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_runtime_failure_other_details_total",
            "Runtime transport failures that remained in the 'other' bucket, grouped by a normalized raw detail signature.",
        ),
        &["transport", "group", "uplink", "detail"],
    )
    .expect("uplink_runtime_failure_other_details_total metric");

    let uplink_failovers_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_uplink_failovers_total",
            "Runtime failovers from one uplink to another.",
        ),
        &["transport", "group", "from_uplink", "to_uplink"],
    )
    .expect("uplink_failovers_total metric");

    let uplink_health = GaugeVec::new(
        Opts::new("outline_ws_rust_uplink_health", "Current uplink health by transport."),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_health metric");

    let uplink_latency_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_latency_seconds",
            "Last observed uplink probe latency.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_latency_seconds metric");

    let uplink_rtt_ewma_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_rtt_ewma_seconds",
            "EWMA RTT latency used as the probe baseline.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_rtt_ewma_seconds metric");

    let uplink_penalty_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_penalty_seconds",
            "Current failure penalty applied to an uplink.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_penalty_seconds metric");

    let uplink_effective_latency_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_effective_latency_seconds",
            "Latency used for uplink ranking, including penalty.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_effective_latency_seconds metric");

    let uplink_score_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_score_seconds",
            "Final weighted uplink selection score.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_score_seconds metric");

    let uplink_weight = GaugeVec::new(
        Opts::new("outline_ws_rust_uplink_weight", "Configured static weight for each uplink."),
        &["group", "uplink"],
    )
    .expect("uplink_weight metric");

    let uplink_cooldown_seconds = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_cooldown_seconds",
            "Remaining cooldown time for an uplink.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_cooldown_seconds metric");

    let uplink_standby_ready = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_uplink_standby_ready",
            "Currently available warm-standby websocket connections.",
        ),
        &["group", "transport", "uplink"],
    )
    .expect("uplink_standby_ready metric");

    let selection_mode_info = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_selection_mode_info",
            "Configured load-balancing selection mode.",
        ),
        &["group", "mode"],
    )
    .expect("selection_mode_info metric");

    let routing_scope_info = IntGaugeVec::new(
        Opts::new("outline_ws_rust_routing_scope_info", "Configured routing scope."),
        &["group", "scope"],
    )
    .expect("routing_scope_info metric");

    let global_active_uplink_info = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_global_active_uplink_info",
            "Currently selected active uplink for global routing scope.",
        ),
        &["group", "uplink"],
    )
    .expect("global_active_uplink_info metric");

    let per_uplink_active_uplink_info = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_per_uplink_active_uplink_info",
            "Currently selected active uplink per transport protocol for per_uplink routing scope.",
        ),
        &["group", "proto", "uplink"],
    )
    .expect("per_uplink_active_uplink_info metric");

    let sticky_routes_total = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_sticky_routes_total",
            "Current number of sticky routes per uplink group.",
        ),
        &["group"],
    )
    .expect("sticky_routes_total metric");

    let sticky_routes_by_uplink = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_sticky_routes_by_uplink",
            "Current number of sticky routes pinned to each uplink.",
        ),
        &["group", "uplink"],
    )
    .expect("sticky_routes_by_uplink metric");

    registry
        .register(Box::new(uplink_selected_total.clone()))
        .expect("register uplink_selected_total");
    registry
        .register(Box::new(uplink_runtime_failures_total.clone()))
        .expect("register uplink_runtime_failures_total");
    registry
        .register(Box::new(uplink_runtime_failures_suppressed_total.clone()))
        .expect("register uplink_runtime_failures_suppressed_total");
    registry
        .register(Box::new(uplink_runtime_failure_causes_total.clone()))
        .expect("register uplink_runtime_failure_causes_total");
    registry
        .register(Box::new(uplink_runtime_failure_signatures_total.clone()))
        .expect("register uplink_runtime_failure_signatures_total");
    registry
        .register(Box::new(uplink_runtime_failure_other_details_total.clone()))
        .expect("register uplink_runtime_failure_other_details_total");
    registry
        .register(Box::new(uplink_failovers_total.clone()))
        .expect("register uplink_failovers_total");
    registry
        .register(Box::new(uplink_health.clone()))
        .expect("register uplink_health");
    registry
        .register(Box::new(uplink_latency_seconds.clone()))
        .expect("register uplink_latency_seconds");
    registry
        .register(Box::new(uplink_rtt_ewma_seconds.clone()))
        .expect("register uplink_rtt_ewma_seconds");
    registry
        .register(Box::new(uplink_penalty_seconds.clone()))
        .expect("register uplink_penalty_seconds");
    registry
        .register(Box::new(uplink_effective_latency_seconds.clone()))
        .expect("register uplink_effective_latency_seconds");
    registry
        .register(Box::new(uplink_score_seconds.clone()))
        .expect("register uplink_score_seconds");
    registry
        .register(Box::new(uplink_weight.clone()))
        .expect("register uplink_weight");
    registry
        .register(Box::new(uplink_cooldown_seconds.clone()))
        .expect("register uplink_cooldown_seconds");
    registry
        .register(Box::new(uplink_standby_ready.clone()))
        .expect("register uplink_standby_ready");
    registry
        .register(Box::new(selection_mode_info.clone()))
        .expect("register selection_mode_info");
    registry
        .register(Box::new(routing_scope_info.clone()))
        .expect("register routing_scope_info");
    registry
        .register(Box::new(global_active_uplink_info.clone()))
        .expect("register global_active_uplink_info");
    registry
        .register(Box::new(per_uplink_active_uplink_info.clone()))
        .expect("register per_uplink_active_uplink_info");
    registry
        .register(Box::new(sticky_routes_total.clone()))
        .expect("register sticky_routes_total");
    registry
        .register(Box::new(sticky_routes_by_uplink.clone()))
        .expect("register sticky_routes_by_uplink");

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
