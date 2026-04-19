use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

pub(super) struct ProbeFields {
    pub(super) probe_runs_total: IntCounterVec,
    pub(super) probe_duration_seconds: HistogramVec,
    pub(super) probe_bytes_total: IntCounterVec,
    pub(super) probe_wakeups_total: IntCounterVec,
    pub(super) warm_standby_acquire_total: IntCounterVec,
    pub(super) warm_standby_refill_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> ProbeFields {
    let probe_runs_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_probe_runs_total",
            "Probe runs by uplink, transport, probe type and result.",
        ),
        &["group", "uplink", "transport", "probe", "result"],
    )
    .expect("probe_runs_total metric");

    let probe_duration_seconds = HistogramVec::new(
        HistogramOpts::new(
            "outline_ws_rust_probe_duration_seconds",
            "Probe duration by uplink, transport and probe type.",
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0]),
        &["group", "uplink", "transport", "probe"],
    )
    .expect("probe_duration_seconds metric");

    let probe_bytes_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_probe_bytes_total",
            "Application payload bytes exchanged by probes, by uplink, transport, probe type, and direction.",
        ),
        &["group", "uplink", "transport", "probe", "direction"],
    )
    .expect("probe_bytes_total metric");

    let probe_wakeups_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_probe_wakeups_total",
            "Early probe wakeup events by uplink, transport, reason, and result.",
        ),
        &["group", "uplink", "transport", "reason", "result"],
    )
    .expect("probe_wakeups_total metric");

    let warm_standby_acquire_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_warm_standby_acquire_total",
            "Warm-standby acquire attempts by transport, uplink and outcome.",
        ),
        &["transport", "group", "uplink", "outcome"],
    )
    .expect("warm_standby_acquire_total metric");

    let warm_standby_refill_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_warm_standby_refill_total",
            "Warm-standby refill attempts by transport, uplink and result.",
        ),
        &["transport", "group", "uplink", "result"],
    )
    .expect("warm_standby_refill_total metric");

    registry
        .register(Box::new(probe_runs_total.clone()))
        .expect("register probe_runs_total");
    registry
        .register(Box::new(probe_duration_seconds.clone()))
        .expect("register probe_duration_seconds");
    registry
        .register(Box::new(probe_bytes_total.clone()))
        .expect("register probe_bytes_total");
    registry
        .register(Box::new(probe_wakeups_total.clone()))
        .expect("register probe_wakeups_total");
    registry
        .register(Box::new(warm_standby_acquire_total.clone()))
        .expect("register warm_standby_acquire_total");
    registry
        .register(Box::new(warm_standby_refill_total.clone()))
        .expect("register warm_standby_refill_total");

    ProbeFields {
        probe_runs_total,
        probe_duration_seconds,
        probe_bytes_total,
        probe_wakeups_total,
        warm_standby_acquire_total,
        warm_standby_refill_total,
    }
}
