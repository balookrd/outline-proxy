use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

pub(super) struct TransportFields {
    pub(super) transport_connects_total: IntCounterVec,
    pub(super) transport_connects_active: IntGaugeVec,
    pub(super) upstream_transports_total: IntCounterVec,
    pub(super) upstream_transports_active: IntGaugeVec,
}

pub(super) fn build(registry: &Registry) -> TransportFields {
    let transport_connects_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_transport_connects_total",
            "Transport websocket connect attempts by source, mode and result.",
        ),
        &["source", "mode", "result"],
    )
    .expect("transport_connects_total metric");

    let transport_connects_active = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_transport_connects_active",
            "Currently active transport websocket connect attempts by source and mode.",
        ),
        &["source", "mode"],
    )
    .expect("transport_connects_active metric");

    let upstream_transports_total = IntCounterVec::new(
        Opts::new(
            "outline_ws_rust_upstream_transports_total",
            "Established upstream websocket transports by source, protocol and result.",
        ),
        &["source", "protocol", "result"],
    )
    .expect("upstream_transports_total metric");

    let upstream_transports_active = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_upstream_transports_active",
            "Currently active established upstream websocket transports by source and protocol.",
        ),
        &["source", "protocol"],
    )
    .expect("upstream_transports_active metric");

    registry
        .register(Box::new(transport_connects_total.clone()))
        .expect("register transport_connects_total");
    registry
        .register(Box::new(transport_connects_active.clone()))
        .expect("register transport_connects_active");
    registry
        .register(Box::new(upstream_transports_total.clone()))
        .expect("register upstream_transports_total");
    registry
        .register(Box::new(upstream_transports_active.clone()))
        .expect("register upstream_transports_active");

    TransportFields {
        transport_connects_total,
        transport_connects_active,
        upstream_transports_total,
        upstream_transports_active,
    }
}
