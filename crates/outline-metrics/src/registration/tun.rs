use super::macros::{register_histogram, register_labeled, register_scalar};
use prometheus::{Gauge, GaugeVec, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry};

pub(super) struct TunFields {
    pub(super) tun_packets_total: IntCounterVec,
    pub(super) tun_flows_total: IntCounterVec,
    pub(super) tun_flow_duration_seconds: HistogramVec,
    pub(super) tun_flows_active: IntGaugeVec,
    pub(super) tun_icmp_local_replies_total: IntCounterVec,
    pub(super) tun_udp_forward_errors_total: IntCounterVec,
    pub(super) tun_ip_fragments_total: IntCounterVec,
    pub(super) tun_ip_reassemblies_total: IntCounterVec,
    pub(super) tun_ip_fragment_sets_active: IntGaugeVec,
    pub(super) tun_max_flows: IntGauge,
    pub(super) tun_idle_timeout_seconds: Gauge,
    pub(super) tun_tcp_events_total: IntCounterVec,
    pub(super) tun_tcp_async_connects_total: IntCounterVec,
    pub(super) tun_tcp_async_connects_active: IntGauge,
    pub(super) tun_tcp_flows_active: IntGaugeVec,
    pub(super) tun_tcp_inflight_segments: IntGaugeVec,
    pub(super) tun_tcp_inflight_bytes: IntGaugeVec,
    pub(super) tun_tcp_pending_server_bytes: IntGaugeVec,
    pub(super) tun_tcp_buffered_client_segments: IntGaugeVec,
    pub(super) tun_tcp_zero_window_flows: IntGaugeVec,
    pub(super) tun_tcp_backlog_pressure_flows: IntGaugeVec,
    pub(super) tun_tcp_backlog_pressure_seconds: GaugeVec,
    pub(super) tun_tcp_ack_progress_stall_flows: IntGaugeVec,
    pub(super) tun_tcp_ack_progress_stall_seconds: GaugeVec,
    pub(super) tun_tcp_congestion_window_bytes: IntGaugeVec,
    pub(super) tun_tcp_slow_start_threshold_bytes: IntGaugeVec,
    pub(super) tun_tcp_retransmission_timeout_seconds: GaugeVec,
    pub(super) tun_tcp_smoothed_rtt_seconds: GaugeVec,
}

pub(super) fn build(registry: &Registry) -> TunFields {
    let tun_packets_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_packets_total",
        "Packets observed on the TUN path by direction, IP family and outcome.",
        ["direction", "ip_family", "outcome"]
    );
    let tun_flows_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_flows_total",
        "Lifecycle events for TUN UDP flows.",
        ["event", "group", "uplink"]
    );
    let tun_flow_duration_seconds = register_histogram!(
        registry,
        "outline_ws_rust_tun_flow_duration_seconds",
        "Lifetime of TUN UDP flows by close reason.",
        [1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0],
        ["reason", "group", "uplink"]
    );
    let tun_flows_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_flows_active",
        "Currently active TUN UDP flows by uplink.",
        ["group", "uplink"]
    );
    let tun_icmp_local_replies_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_icmp_local_replies_total",
        "Local ICMP echo replies generated on the TUN path by IP family.",
        ["ip_family"]
    );
    let tun_udp_forward_errors_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_udp_forward_errors_total",
        "UDP forwarding errors on the TUN path by reason.",
        ["reason"]
    );
    let tun_ip_fragments_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_ip_fragments_total",
        "IP fragments observed on the TUN path by IP family.",
        ["ip_family"]
    );
    let tun_ip_reassemblies_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_ip_reassemblies_total",
        "IP fragment reassembly outcomes on the TUN path by IP family and result.",
        ["ip_family", "result"]
    );
    let tun_ip_fragment_sets_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_ip_fragment_sets_active",
        "Currently buffered IP fragment sets on the TUN path by IP family.",
        ["ip_family"]
    );
    let tun_max_flows = register_scalar!(
        registry,
        IntGauge,
        "outline_ws_rust_tun_max_flows",
        "Configured maximum number of TUN UDP flows."
    );
    let tun_idle_timeout_seconds = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_tun_idle_timeout_seconds",
        "Configured idle timeout for TUN UDP flows."
    );
    let tun_tcp_events_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_tcp_events_total",
        "TCP state machine events observed on the TUN path.",
        ["group", "uplink", "event"]
    );
    let tun_tcp_async_connects_total = register_labeled!(
        registry,
        IntCounterVec,
        "outline_ws_rust_tun_tcp_async_connects_total",
        "Async upstream connect attempts for TUN TCP flows by result.",
        ["result"]
    );
    let tun_tcp_async_connects_active = register_scalar!(
        registry,
        IntGauge,
        "outline_ws_rust_tun_tcp_async_connects_active",
        "Currently active async upstream connect attempts for TUN TCP flows."
    );
    let tun_tcp_flows_active = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_flows_active",
        "Currently active TUN TCP flows by uplink.",
        ["group", "uplink"]
    );
    let tun_tcp_inflight_segments = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_inflight_segments",
        "Current number of unacknowledged server-to-client TCP segments on the TUN path.",
        ["group", "uplink"]
    );
    let tun_tcp_inflight_bytes = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_inflight_bytes",
        "Current number of unacknowledged server-to-client TCP bytes on the TUN path.",
        ["group", "uplink"]
    );
    let tun_tcp_pending_server_bytes = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_pending_server_bytes",
        "Current number of queued server-to-client TCP bytes waiting for client window on the TUN path.",
        ["group", "uplink"]
    );
    let tun_tcp_buffered_client_segments = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_buffered_client_segments",
        "Current number of buffered out-of-order client TCP segments on the TUN path.",
        ["group", "uplink"]
    );
    let tun_tcp_zero_window_flows = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_zero_window_flows",
        "Current number of TUN TCP flows stalled on a zero-sized client receive window.",
        ["group", "uplink"]
    );
    let tun_tcp_backlog_pressure_flows = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_backlog_pressure_flows",
        "Current number of TUN TCP flows above the configured server backlog limit.",
        ["group", "uplink"]
    );
    let tun_tcp_backlog_pressure_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_tun_tcp_backlog_pressure_seconds",
        "Current accumulated backlog-pressure duration for active TUN TCP flows.",
        ["group", "uplink"]
    );
    let tun_tcp_ack_progress_stall_flows = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_ack_progress_stall_flows",
        "Current number of TUN TCP flows with pending server data but no recent ACK progress.",
        ["group", "uplink"]
    );
    let tun_tcp_ack_progress_stall_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_tun_tcp_ack_progress_stall_seconds",
        "Current accumulated ACK-progress stall duration for active TUN TCP flows with pending server data.",
        ["group", "uplink"]
    );
    let tun_tcp_congestion_window_bytes = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_congestion_window_bytes",
        "Aggregated congestion window for active TUN TCP flows.",
        ["group", "uplink"]
    );
    let tun_tcp_slow_start_threshold_bytes = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_tun_tcp_slow_start_threshold_bytes",
        "Aggregated slow-start threshold for active TUN TCP flows.",
        ["group", "uplink"]
    );
    let tun_tcp_retransmission_timeout_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_tun_tcp_retransmission_timeout_seconds",
        "Aggregated retransmission timeout for active TUN TCP flows.",
        ["group", "uplink"]
    );
    let tun_tcp_smoothed_rtt_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_tun_tcp_smoothed_rtt_seconds",
        "Aggregated smoothed RTT for active TUN TCP flows.",
        ["group", "uplink"]
    );

    TunFields {
        tun_packets_total,
        tun_flows_total,
        tun_flow_duration_seconds,
        tun_flows_active,
        tun_icmp_local_replies_total,
        tun_udp_forward_errors_total,
        tun_ip_fragments_total,
        tun_ip_reassemblies_total,
        tun_ip_fragment_sets_active,
        tun_max_flows,
        tun_idle_timeout_seconds,
        tun_tcp_events_total,
        tun_tcp_async_connects_total,
        tun_tcp_async_connects_active,
        tun_tcp_flows_active,
        tun_tcp_inflight_segments,
        tun_tcp_inflight_bytes,
        tun_tcp_pending_server_bytes,
        tun_tcp_buffered_client_segments,
        tun_tcp_zero_window_flows,
        tun_tcp_backlog_pressure_flows,
        tun_tcp_backlog_pressure_seconds,
        tun_tcp_ack_progress_stall_flows,
        tun_tcp_ack_progress_stall_seconds,
        tun_tcp_congestion_window_bytes,
        tun_tcp_slow_start_threshold_bytes,
        tun_tcp_retransmission_timeout_seconds,
        tun_tcp_smoothed_rtt_seconds,
    }
}
