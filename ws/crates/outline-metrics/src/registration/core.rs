use super::macros::{register_histogram, register_labeled, register_scalar};
use prometheus::{Gauge, HistogramVec, IntCounterVec, IntGaugeVec, Registry};
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
    let build_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_build_info",
        "Build info for outline-ws-rust.",
        ["version"]
    );
    let start_time_seconds = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_start_time_seconds",
        "Process start time in unix seconds."
    );
    let socks_requests_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_requests_total",
        "Total SOCKS5 requests accepted by command.",
        ["command"]
    );
    let sessions_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_sessions_active",
        "Currently active proxy sessions by protocol.",
        ["protocol"]
    );
    let session_duration_seconds = register_histogram!(
        registry,
        "outline_ws_rust_session_duration_seconds",
        "Proxy session duration by protocol and result.",
        [0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0, 30.0, 60.0, 300.0, 900.0],
        ["protocol", "result"]
    );
    let bytes_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_bytes_total",
        "Application payload bytes transferred by protocol, direction, group and uplink.",
        ["protocol", "direction", "group", "uplink"]
    );
    let udp_datagrams_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_udp_datagrams_total",
        "UDP datagrams forwarded by direction, group and uplink.",
        ["direction", "group", "uplink"]
    );
    let udp_oversized_dropped_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_udp_oversized_dropped_total",
        "Oversized UDP packets dropped before forwarding.",
        ["direction"]
    );

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
