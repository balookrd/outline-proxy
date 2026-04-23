use super::macros::{register_histogram, register_labeled};
use prometheus::{HistogramVec, IntCounterVec, Registry};

pub(super) struct ProbeFields {
    pub(super) probe_runs_total: IntCounterVec,
    pub(super) probe_duration_seconds: HistogramVec,
    pub(super) probe_bytes_total: IntCounterVec,
    pub(super) probe_wakeups_total: IntCounterVec,
    pub(super) warm_standby_acquire_total: IntCounterVec,
    pub(super) warm_standby_refill_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> ProbeFields {
    let probe_runs_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_probe_runs_total",
        "Probe runs by uplink, transport, probe type and result.",
        ["group", "uplink", "transport", "probe", "result"]
    );
    let probe_duration_seconds = register_histogram!(
        registry,
        "outline_ws_rust_probe_duration_seconds",
        "Probe duration by uplink, transport and probe type.",
        [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0],
        ["group", "uplink", "transport", "probe"]
    );
    let probe_bytes_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_probe_bytes_total",
        "Application payload bytes exchanged by probes, by uplink, transport, probe type, and direction.",
        ["group", "uplink", "transport", "probe", "direction"]
    );
    let probe_wakeups_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_probe_wakeups_total",
        "Early probe wakeup events by uplink, transport, reason, and result.",
        ["group", "uplink", "transport", "reason", "result"]
    );
    let warm_standby_acquire_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_warm_standby_acquire_total",
        "Warm-standby acquire attempts by transport, uplink and outcome.",
        ["transport", "group", "uplink", "outcome"]
    );
    let warm_standby_refill_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_warm_standby_refill_total",
        "Warm-standby refill attempts by transport, uplink and result.",
        ["transport", "group", "uplink", "result"]
    );

    ProbeFields {
        probe_runs_total,
        probe_duration_seconds,
        probe_bytes_total,
        probe_wakeups_total,
        warm_standby_acquire_total,
        warm_standby_refill_total,
    }
}
