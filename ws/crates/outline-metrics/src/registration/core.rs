use prometheus::{Gauge, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct CoreFields {
    pub(super) build_info: IntGaugeVec,
    pub(super) start_time_seconds: Gauge,
    pub(super) socks_requests_total: IntCounterVec,
    pub(super) sessions_active: IntGaugeVec,
    pub(super) session_duration_seconds: HistogramVec,
    pub(super) bytes_total: IntCounterVec,
    pub(super) udp_datagrams_total: IntCounterVec,
    pub(super) udp_oversized_dropped_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> CoreFields {
    let build_info = IntGaugeVec::new(
        Opts::new("outline_ws_rust_build_info", "Build info for outline-ws-rust."),
        &["version"],
    )
    .expect("build_info metric");

    let start_time_seconds = Gauge::with_opts(Opts::new(
        "outline_ws_rust_start_time_seconds",
        "Process start time in unix seconds.",
    ))
    .expect("start_time_seconds metric");

    let socks_requests_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_requests_total",
            "Total SOCKS5 requests accepted by command.",
        ),
        &["command"],
    )
    .expect("requests_total metric");

    let sessions_active = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_sessions_active",
            "Currently active proxy sessions by protocol.",
        ),
        &["protocol"],
    )
    .expect("sessions_active metric");

    let session_duration_seconds = HistogramVec::new(
        HistogramOpts::new(
            "outline_ws_rust_session_duration_seconds",
            "Proxy session duration by protocol and result.",
        )
        .buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0, 30.0, 60.0, 300.0, 900.0]),
        &["protocol", "result"],
    )
    .expect("session_duration_seconds metric");

    let bytes_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_bytes_total",
            "Application payload bytes transferred by protocol, direction, group and uplink.",
        ),
        &["protocol", "direction", "group", "uplink"],
    )
    .expect("bytes_total metric");

    let udp_datagrams_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_udp_datagrams_total",
            "UDP datagrams forwarded by direction, group and uplink.",
        ),
        &["direction", "group", "uplink"],
    )
    .expect("udp_datagrams_total metric");

    let udp_oversized_dropped_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_udp_oversized_dropped_total",
            "Oversized UDP packets dropped before forwarding.",
        ),
        &["direction"],
    )
    .expect("udp_oversized_dropped_total metric");

    registry
        .register(Box::new(build_info.clone()))
        .expect("register build_info");
    registry
        .register(Box::new(start_time_seconds.clone()))
        .expect("register start_time_seconds");
    registry
        .register(Box::new(socks_requests_total.clone()))
        .expect("register requests_total");
    registry
        .register(Box::new(sessions_active.clone()))
        .expect("register sessions_active");
    registry
        .register(Box::new(session_duration_seconds.clone()))
        .expect("register session_duration_seconds");
    registry
        .register(Box::new(bytes_total.clone()))
        .expect("register bytes_total");
    registry
        .register(Box::new(udp_datagrams_total.clone()))
        .expect("register udp_datagrams_total");
    registry
        .register(Box::new(udp_oversized_dropped_total.clone()))
        .expect("register udp_oversized_dropped_total");

    build_info.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);
    start_time_seconds.set(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
    );

    CoreFields {
        build_info,
        start_time_seconds,
        socks_requests_total,
        sessions_active,
        session_duration_seconds,
        bytes_total,
        udp_datagrams_total,
        udp_oversized_dropped_total,
    }
}
