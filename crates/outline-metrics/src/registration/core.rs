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
    pub(super) udp_malformed_dropped_total: IntCounterVec,
    pub(super) udp_h3_datagrams_total: IntCounterVec,
    pub(super) udp_h3_datagram_fallback_total: IntCounterVec,
    pub(super) udp_h3_datagram_dropped_total: IntCounterVec,
    pub(super) udp_h3_datagram_sessions_total: IntCounterVec,
}

pub(super) fn build(registry: &Registry) -> CoreFields {
    let build_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_build_info",
        "Build info for outline-ws-rust.",
        ["version"]
    );
    let start_time_seconds = register_scalar!(
        registry,
        Gauge,
        "outline_ws_start_time_seconds",
        "Process start time in unix seconds."
    );
    let socks_requests_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_requests_total",
        "Total SOCKS5 requests accepted by command.",
        ["command"]
    );
    let sessions_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_sessions_active",
        "Currently active proxy sessions by protocol.",
        ["protocol"]
    );
    let session_duration_seconds = register_histogram!(
        registry,
        "outline_ws_session_duration_seconds",
        "Proxy session duration by protocol and result.",
        [0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0, 30.0, 60.0, 300.0, 900.0],
        ["protocol", "result"]
    );
    let bytes_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_bytes_total",
        "Application payload bytes transferred by protocol, direction, group and uplink.",
        ["protocol", "direction", "group", "uplink"]
    );
    let udp_datagrams_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_datagrams_total",
        "UDP datagrams forwarded by direction, group and uplink.",
        ["direction", "group", "uplink"]
    );
    let udp_oversized_dropped_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_oversized_dropped_total",
        "Oversized UDP packets dropped before forwarding, by direction and \
         cause (vless_udp / ss_socket / socks_client / socks_relay / \
         socks_direct / socks_in_tcp).",
        ["direction", "cause"]
    );
    let udp_malformed_dropped_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_malformed_dropped_total",
        "Client UDP datagrams dropped on the SOCKS5 datagram ingress because \
         they could not be decoded, by cause (parse / reassembly). Each drop \
         costs only the offending datagram; the association keeps serving.",
        ["cause"]
    );
    let udp_h3_datagrams_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_h3_datagrams_total",
        "UDP packets carried as HTTP/3 datagrams (RFC 9297) on a negotiated \
         session, by direction, transport (ws_h3 / xhttp_h3) and proto (ss / vless).",
        ["direction", "transport", "proto"]
    );
    let udp_h3_datagram_fallback_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_h3_datagram_fallback_total",
        "UDP packets of a datagram-negotiated HTTP/3 session that rode the \
         stream instead (too large for the current datagram size, the \
         datagram send failed, or a VLESS packet sent before the server's \
         first reply), by direction, transport and proto.",
        ["direction", "transport", "proto"]
    );
    let udp_h3_datagram_dropped_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_h3_datagram_dropped_total",
        "Inbound HTTP/3 datagrams dropped, by reason: unknown_stream / malformed / queue_full \
         (demultiplexer: no live stream for the id, bad prefix, the stream's receive \
         queue is full; VLESS: not exactly one record, or a padded datagram that \
         decodes to nothing) and early (VLESS: arrived before the response header). The connection keeps serving.",
        ["reason"]
    );
    let udp_h3_datagram_sessions_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_udp_h3_datagram_sessions_total",
        "HTTP/3 request streams that offered UDP over HTTP/3 datagrams, by \
         transport and state (negotiated: the server echoed the offer; declined: \
         it did not). Counts anchor streams, including standby-pool refills and \
         probe dials, not user sessions.",
        ["transport", "state"]
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
        udp_malformed_dropped_total,
        udp_h3_datagrams_total,
        udp_h3_datagram_fallback_total,
        udp_h3_datagram_dropped_total,
        udp_h3_datagram_sessions_total,
    }
}
