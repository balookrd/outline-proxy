use super::macros::register_labeled;
use prometheus::{IntCounterVec, IntGaugeVec, Registry};

pub(super) struct TransportFields {
    pub(super) transport_connects_total: IntCounterVec,
    pub(super) transport_connects_active: IntGaugeVec,
    pub(super) upstream_transports_total: IntCounterVec,
    pub(super) upstream_transports_active: IntGaugeVec,
    pub(super) metrics_http_requests_total: IntCounterVec,
    pub(super) carrier_writer_terminations_total: IntCounterVec,
    pub(super) h3_endpoints_active: IntGaugeVec,
    pub(super) h3_pool_carriers: IntGaugeVec,
}

pub(super) fn build(registry: &Registry) -> TransportFields {
    let transport_connects_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_transport_connects_total",
        "Transport websocket connect attempts by source, mode and result.",
        ["source", "mode", "result"]
    );
    let transport_connects_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_transport_connects_active",
        "Currently active transport websocket connect attempts by source and mode.",
        ["source", "mode"]
    );
    let upstream_transports_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_upstream_transports_total",
        "Established upstream websocket transports by source, protocol and result.",
        ["source", "protocol", "result"]
    );
    let upstream_transports_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_upstream_transports_active",
        "Currently active established upstream websocket transports by source and protocol.",
        ["source", "protocol"]
    );
    let metrics_http_requests_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_metrics_http_requests_total",
        "HTTP requests served by the control and metrics listeners by path and status code.",
        ["path", "status"]
    );

    let carrier_writer_terminations_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_carrier_writer_terminations_total",
        "WebSocket carrier writer tasks stopped by a failed sink write, by writer and reason.",
        ["writer", "reason"]
    );

    // Every QUIC endpoint owns a private UDP socket AND a receive buffer of
    // `max_udp_payload_size * gro_segments * BATCH_SIZE` — 2.87 MiB on Linux
    // with GRO. That makes the endpoint count, not the flow count, the thing
    // that sizes this process's memory, and it is invisible in every metric we
    // had. Split by who dialed: the `ws_h3` pool keeps carriers alive across
    // idle periods (a reaper could shrink it), while `xhttp_h3` has no pool at
    // all and its endpoints live exactly as long as their session.
    let h3_endpoints_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_h3_endpoints_active",
        "Live QUIC client endpoints, one private UDP socket and ~2.9 MiB receive buffer each, by what dialed them.",
        ["kind"]
    );
    // `idle` carriers hold an endpoint while carrying nothing: keep-alive PINGs
    // stop QUIC's idle timeout from ever closing them, so they persist until
    // something evicts them. Labelled by pool because the two behave very
    // differently — `ws_h3` carriers outlive their traffic, `xhttp_h3` ones are
    // opened on demand by sessions.
    let h3_pool_carriers = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_h3_pool_carriers",
        "Shared H3 carriers held in a connection pool, by pool and by whether they are carrying traffic right now.",
        ["kind", "state"]
    );

    TransportFields {
        transport_connects_total,
        transport_connects_active,
        upstream_transports_total,
        upstream_transports_active,
        metrics_http_requests_total,
        carrier_writer_terminations_total,
        h3_endpoints_active,
        h3_pool_carriers,
    }
}
