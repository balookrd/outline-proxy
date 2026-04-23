use super::macros::register_labeled;
use prometheus::{IntCounterVec, IntGaugeVec, Registry};

pub(super) struct TransportFields {
    pub(super) transport_connects_total: IntCounterVec,
    pub(super) transport_connects_active: IntGaugeVec,
    pub(super) upstream_transports_total: IntCounterVec,
    pub(super) upstream_transports_active: IntGaugeVec,
    pub(super) metrics_http_requests_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> TransportFields {
    let transport_connects_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_transport_connects_total",
        "Transport websocket connect attempts by source, mode and result.",
        ["source", "mode", "result"]
    );
    let transport_connects_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_transport_connects_active",
        "Currently active transport websocket connect attempts by source and mode.",
        ["source", "mode"]
    );
    let upstream_transports_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_upstream_transports_total",
        "Established upstream websocket transports by source, protocol and result.",
        ["source", "protocol", "result"]
    );
    let upstream_transports_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_upstream_transports_active",
        "Currently active established upstream websocket transports by source and protocol.",
        ["source", "protocol"]
    );
    let metrics_http_requests_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_metrics_http_requests_total",
        "HTTP requests served by the control and metrics listeners by path and status code.",
        ["path", "status"]
    );

    TransportFields {
        transport_connects_total,
        transport_connects_active,
        upstream_transports_total,
        upstream_transports_active,
        metrics_http_requests_total,
    }
}
