use super::Metrics;
use prometheus::{
    Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};
use std::time::{SystemTime, UNIX_EPOCH};

impl Metrics {
    pub(super) fn new() -> Self {
        let registry = Registry::new();

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
                "Application payload bytes transferred by protocol, direction and uplink.",
            ),
            &["protocol", "direction", "uplink"],
        )
        .expect("bytes_total metric");
        let udp_datagrams_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_udp_datagrams_total",
                "UDP datagrams forwarded by direction and uplink.",
            ),
            &["direction", "uplink"],
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
        let uplink_selected_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_selected_total",
                "Times an uplink was selected for a transport.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_selected_total metric");
        let uplink_runtime_failures_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_runtime_failures_total",
                "Runtime transport failures by uplink.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_runtime_failures_total metric");
        let uplink_runtime_failures_suppressed_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_runtime_failures_suppressed_total",
                "Runtime failures observed while the uplink was already in cooldown.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_runtime_failures_suppressed_total metric");
        let uplink_runtime_failure_causes_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_runtime_failure_causes_total",
                "Runtime transport failures by uplink and classified cause.",
            ),
            &["transport", "uplink", "cause"],
        )
        .expect("uplink_runtime_failure_causes_total metric");
        let uplink_runtime_failure_signatures_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_runtime_failure_signatures_total",
                "Runtime transport failures by uplink and normalized failure signature.",
            ),
            &["transport", "uplink", "signature"],
        )
        .expect("uplink_runtime_failure_signatures_total metric");
        let uplink_runtime_failure_other_details_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_runtime_failure_other_details_total",
                "Runtime transport failures that remained in the 'other' bucket, grouped by a normalized raw detail signature.",
            ),
            &["transport", "uplink", "detail"],
        )
        .expect("uplink_runtime_failure_other_details_total metric");
        let uplink_failovers_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_uplink_failovers_total",
                "Runtime failovers from one uplink to another.",
            ),
            &["transport", "from_uplink", "to_uplink"],
        )
        .expect("uplink_failovers_total metric");
        let probe_runs_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_probe_runs_total",
                "Probe runs by uplink, transport, probe type and result.",
            ),
            &["uplink", "transport", "probe", "result"],
        )
        .expect("probe_runs_total metric");
        let probe_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "outline_ws_rust_probe_duration_seconds",
                "Probe duration by uplink, transport and probe type.",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0]),
            &["uplink", "transport", "probe"],
        )
        .expect("probe_duration_seconds metric");
        let probe_bytes_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_probe_bytes_total",
                "Application payload bytes exchanged by probes, by uplink, transport, probe type, and direction.",
            ),
            &["uplink", "transport", "probe", "direction"],
        )
        .expect("probe_bytes_total metric");
        let probe_wakeups_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_probe_wakeups_total",
                "Early probe wakeup events by uplink, transport, reason, and result.",
            ),
            &["uplink", "transport", "reason", "result"],
        )
        .expect("probe_wakeups_total metric");
        let warm_standby_acquire_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_warm_standby_acquire_total",
                "Warm-standby acquire attempts by transport, uplink and outcome.",
            ),
            &["transport", "uplink", "outcome"],
        )
        .expect("warm_standby_acquire_total metric");
        let warm_standby_refill_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_warm_standby_refill_total",
                "Warm-standby refill attempts by transport, uplink and result.",
            ),
            &["transport", "uplink", "result"],
        )
        .expect("warm_standby_refill_total metric");
        let process_resident_memory_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_resident_memory_bytes",
            "Current resident set size of the process in bytes.",
        ))
        .expect("process_resident_memory_bytes metric");
        let process_virtual_memory_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_virtual_memory_bytes",
            "Current virtual memory size of the process in bytes.",
        ))
        .expect("process_virtual_memory_bytes metric");
        let process_heap_allocated_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_heap_allocated_bytes",
            "Current allocated heap bytes when available; may be estimated from process memory maps.",
        ))
        .expect("process_heap_allocated_bytes metric");
        let process_heap_mode_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_process_heap_mode_info",
                "Allocator heap sampling mode for the current process.",
            ),
            &["mode"],
        )
        .expect("process_heap_mode_info metric");
        let process_open_fds = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_open_fds",
            "Current number of open file descriptors used by the process.",
        ))
        .expect("process_open_fds metric");
        let process_threads = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_threads",
            "Current number of threads used by the process.",
        ))
        .expect("process_threads metric");
        let process_fd_by_type = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_process_fd_by_type",
                "Current number of open file descriptors by descriptor type.",
            ),
            &["kind"],
        )
        .expect("process_fd_by_type metric");
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
        let tun_packets_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_packets_total",
                "Packets observed on the TUN path by direction, IP family and outcome.",
            ),
            &["direction", "ip_family", "outcome"],
        )
        .expect("tun_packets_total metric");
        let tun_flows_total = IntCounterVec::new(
            Opts::new("outline_ws_rust_tun_flows_total", "Lifecycle events for TUN UDP flows."),
            &["event", "uplink"],
        )
        .expect("tun_flows_total metric");
        let tun_flow_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "outline_ws_rust_tun_flow_duration_seconds",
                "Lifetime of TUN UDP flows by close reason.",
            )
            .buckets(vec![1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0]),
            &["reason", "uplink"],
        )
        .expect("tun_flow_duration_seconds metric");
        let tun_flows_active = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_flows_active",
                "Currently active TUN UDP flows by uplink.",
            ),
            &["uplink"],
        )
        .expect("tun_flows_active metric");
        let tun_icmp_local_replies_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_icmp_local_replies_total",
                "Local ICMP echo replies generated on the TUN path by IP family.",
            ),
            &["ip_family"],
        )
        .expect("tun_icmp_local_replies_total metric");
        let tun_udp_forward_errors_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_udp_forward_errors_total",
                "UDP forwarding errors on the TUN path by reason.",
            ),
            &["reason"],
        )
        .expect("tun_udp_forward_errors_total metric");
        let tun_ip_fragments_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_ip_fragments_total",
                "IP fragments observed on the TUN path by IP family.",
            ),
            &["ip_family"],
        )
        .expect("tun_ip_fragments_total metric");
        let tun_ip_reassemblies_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_ip_reassemblies_total",
                "IP fragment reassembly outcomes on the TUN path by IP family and result.",
            ),
            &["ip_family", "result"],
        )
        .expect("tun_ip_reassemblies_total metric");
        let tun_ip_fragment_sets_active = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_ip_fragment_sets_active",
                "Currently buffered IP fragment sets on the TUN path by IP family.",
            ),
            &["ip_family"],
        )
        .expect("tun_ip_fragment_sets_active metric");
        let tun_max_flows = IntGauge::with_opts(Opts::new(
            "outline_ws_rust_tun_max_flows",
            "Configured maximum number of TUN UDP flows.",
        ))
        .expect("tun_max_flows metric");
        let tun_idle_timeout_seconds = Gauge::with_opts(Opts::new(
            "outline_ws_rust_tun_idle_timeout_seconds",
            "Configured idle timeout for TUN UDP flows.",
        ))
        .expect("tun_idle_timeout_seconds metric");
        let tun_tcp_events_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_events_total",
                "TCP state machine events observed on the TUN path.",
            ),
            &["uplink", "event"],
        )
        .expect("tun_tcp_events_total metric");
        let tun_tcp_async_connects_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_async_connects_total",
                "Async upstream connect attempts for TUN TCP flows by result.",
            ),
            &["result"],
        )
        .expect("tun_tcp_async_connects_total metric");
        let tun_tcp_async_connects_active = IntGauge::with_opts(Opts::new(
            "outline_ws_rust_tun_tcp_async_connects_active",
            "Currently active async upstream connect attempts for TUN TCP flows.",
        ))
        .expect("tun_tcp_async_connects_active metric");
        let tun_tcp_flows_active = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_flows_active",
                "Currently active TUN TCP flows by uplink.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_flows_active metric");
        let tun_tcp_inflight_segments = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_inflight_segments",
                "Current number of unacknowledged server-to-client TCP segments on the TUN path.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_inflight_segments metric");
        let tun_tcp_inflight_bytes = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_inflight_bytes",
                "Current number of unacknowledged server-to-client TCP bytes on the TUN path.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_inflight_bytes metric");
        let tun_tcp_pending_server_bytes = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_pending_server_bytes",
                "Current number of queued server-to-client TCP bytes waiting for client window on the TUN path.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_pending_server_bytes metric");
        let tun_tcp_buffered_client_segments = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_buffered_client_segments",
                "Current number of buffered out-of-order client TCP segments on the TUN path.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_buffered_client_segments metric");
        let tun_tcp_zero_window_flows = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_zero_window_flows",
                "Current number of TUN TCP flows stalled on a zero-sized client receive window.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_zero_window_flows metric");
        let tun_tcp_backlog_pressure_flows = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_backlog_pressure_flows",
                "Current number of TUN TCP flows above the configured server backlog limit.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_backlog_pressure_flows metric");
        let tun_tcp_backlog_pressure_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_backlog_pressure_seconds",
                "Current accumulated backlog-pressure duration for active TUN TCP flows.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_backlog_pressure_seconds metric");
        let tun_tcp_ack_progress_stall_flows = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_ack_progress_stall_flows",
                "Current number of TUN TCP flows with pending server data but no recent ACK progress.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_ack_progress_stall_flows metric");
        let tun_tcp_ack_progress_stall_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_ack_progress_stall_seconds",
                "Current accumulated ACK-progress stall duration for active TUN TCP flows with pending server data.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_ack_progress_stall_seconds metric");
        let tun_tcp_congestion_window_bytes = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_congestion_window_bytes",
                "Aggregated congestion window for active TUN TCP flows.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_congestion_window_bytes metric");
        let tun_tcp_slow_start_threshold_bytes = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_slow_start_threshold_bytes",
                "Aggregated slow-start threshold for active TUN TCP flows.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_slow_start_threshold_bytes metric");
        let tun_tcp_retransmission_timeout_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_retransmission_timeout_seconds",
                "Aggregated retransmission timeout for active TUN TCP flows.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_retransmission_timeout_seconds metric");
        let tun_tcp_smoothed_rtt_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_tun_tcp_smoothed_rtt_seconds",
                "Aggregated smoothed RTT for active TUN TCP flows.",
            ),
            &["uplink"],
        )
        .expect("tun_tcp_smoothed_rtt_seconds metric");
        let uplink_health = GaugeVec::new(
            Opts::new("outline_ws_rust_uplink_health", "Current uplink health by transport."),
            &["transport", "uplink"],
        )
        .expect("uplink_health metric");
        let uplink_latency_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_latency_seconds",
                "Last observed uplink probe latency.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_latency_seconds metric");
        let uplink_rtt_ewma_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_rtt_ewma_seconds",
                "EWMA RTT latency used as the probe baseline.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_rtt_ewma_seconds metric");
        let uplink_penalty_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_penalty_seconds",
                "Current failure penalty applied to an uplink.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_penalty_seconds metric");
        let uplink_effective_latency_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_effective_latency_seconds",
                "Latency used for uplink ranking, including penalty.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_effective_latency_seconds metric");
        let uplink_score_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_score_seconds",
                "Final weighted uplink selection score.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_score_seconds metric");
        let uplink_weight = GaugeVec::new(
            Opts::new("outline_ws_rust_uplink_weight", "Configured static weight for each uplink."),
            &["uplink"],
        )
        .expect("uplink_weight metric");
        let uplink_cooldown_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_cooldown_seconds",
                "Remaining cooldown time for an uplink.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_cooldown_seconds metric");
        let uplink_standby_ready = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_uplink_standby_ready",
                "Currently available warm-standby websocket connections.",
            ),
            &["transport", "uplink"],
        )
        .expect("uplink_standby_ready metric");
        let selection_mode_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_selection_mode_info",
                "Configured load-balancing selection mode.",
            ),
            &["mode"],
        )
        .expect("selection_mode_info metric");
        let routing_scope_info = IntGaugeVec::new(
            Opts::new("outline_ws_rust_routing_scope_info", "Configured routing scope."),
            &["scope"],
        )
        .expect("routing_scope_info metric");
        let global_active_uplink_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_global_active_uplink_info",
                "Currently selected active uplink for global routing scope.",
            ),
            &["uplink"],
        )
        .expect("global_active_uplink_info metric");
        let per_uplink_active_uplink_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_per_uplink_active_uplink_info",
                "Currently selected active uplink per transport protocol for per_uplink routing scope.",
            ),
            &["proto", "uplink"],
        )
        .expect("per_uplink_active_uplink_info metric");
        let sticky_routes_total = IntGauge::with_opts(Opts::new(
            "outline_ws_rust_sticky_routes_total",
            "Current number of sticky routes.",
        ))
        .expect("sticky_routes_total metric");
        let sticky_routes_by_uplink = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_sticky_routes_by_uplink",
                "Current number of sticky routes pinned to each uplink.",
            ),
            &["uplink"],
        )
        .expect("sticky_routes_by_uplink metric");

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
        registry
            .register(Box::new(process_resident_memory_bytes.clone()))
            .expect("register process_resident_memory_bytes");
        registry
            .register(Box::new(process_virtual_memory_bytes.clone()))
            .expect("register process_virtual_memory_bytes");
        registry
            .register(Box::new(process_heap_allocated_bytes.clone()))
            .expect("register process_heap_allocated_bytes");
        registry
            .register(Box::new(process_heap_mode_info.clone()))
            .expect("register process_heap_mode_info");
        registry
            .register(Box::new(process_open_fds.clone()))
            .expect("register process_open_fds");
        registry
            .register(Box::new(process_threads.clone()))
            .expect("register process_threads");
        registry
            .register(Box::new(process_fd_by_type.clone()))
            .expect("register process_fd_by_type");
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
        registry
            .register(Box::new(tun_packets_total.clone()))
            .expect("register tun_packets_total");
        registry
            .register(Box::new(tun_flows_total.clone()))
            .expect("register tun_flows_total");
        registry
            .register(Box::new(tun_flow_duration_seconds.clone()))
            .expect("register tun_flow_duration_seconds");
        registry
            .register(Box::new(tun_flows_active.clone()))
            .expect("register tun_flows_active");
        registry
            .register(Box::new(tun_icmp_local_replies_total.clone()))
            .expect("register tun_icmp_local_replies_total");
        registry
            .register(Box::new(tun_udp_forward_errors_total.clone()))
            .expect("register tun_udp_forward_errors_total");
        registry
            .register(Box::new(tun_ip_fragments_total.clone()))
            .expect("register tun_ip_fragments_total");
        registry
            .register(Box::new(tun_ip_reassemblies_total.clone()))
            .expect("register tun_ip_reassemblies_total");
        registry
            .register(Box::new(tun_ip_fragment_sets_active.clone()))
            .expect("register tun_ip_fragment_sets_active");
        registry
            .register(Box::new(tun_max_flows.clone()))
            .expect("register tun_max_flows");
        registry
            .register(Box::new(tun_idle_timeout_seconds.clone()))
            .expect("register tun_idle_timeout_seconds");
        registry
            .register(Box::new(tun_tcp_events_total.clone()))
            .expect("register tun_tcp_events_total");
        registry
            .register(Box::new(tun_tcp_async_connects_total.clone()))
            .expect("register tun_tcp_async_connects_total");
        registry
            .register(Box::new(tun_tcp_async_connects_active.clone()))
            .expect("register tun_tcp_async_connects_active");
        registry
            .register(Box::new(tun_tcp_flows_active.clone()))
            .expect("register tun_tcp_flows_active");
        registry
            .register(Box::new(tun_tcp_inflight_segments.clone()))
            .expect("register tun_tcp_inflight_segments");
        registry
            .register(Box::new(tun_tcp_inflight_bytes.clone()))
            .expect("register tun_tcp_inflight_bytes");
        registry
            .register(Box::new(tun_tcp_pending_server_bytes.clone()))
            .expect("register tun_tcp_pending_server_bytes");
        registry
            .register(Box::new(tun_tcp_buffered_client_segments.clone()))
            .expect("register tun_tcp_buffered_client_segments");
        registry
            .register(Box::new(tun_tcp_zero_window_flows.clone()))
            .expect("register tun_tcp_zero_window_flows");
        registry
            .register(Box::new(tun_tcp_backlog_pressure_flows.clone()))
            .expect("register tun_tcp_backlog_pressure_flows");
        registry
            .register(Box::new(tun_tcp_backlog_pressure_seconds.clone()))
            .expect("register tun_tcp_backlog_pressure_seconds");
        registry
            .register(Box::new(tun_tcp_ack_progress_stall_flows.clone()))
            .expect("register tun_tcp_ack_progress_stall_flows");
        registry
            .register(Box::new(tun_tcp_ack_progress_stall_seconds.clone()))
            .expect("register tun_tcp_ack_progress_stall_seconds");
        registry
            .register(Box::new(tun_tcp_congestion_window_bytes.clone()))
            .expect("register tun_tcp_congestion_window_bytes");
        registry
            .register(Box::new(tun_tcp_slow_start_threshold_bytes.clone()))
            .expect("register tun_tcp_slow_start_threshold_bytes");
        registry
            .register(Box::new(tun_tcp_retransmission_timeout_seconds.clone()))
            .expect("register tun_tcp_retransmission_timeout_seconds");
        registry
            .register(Box::new(tun_tcp_smoothed_rtt_seconds.clone()))
            .expect("register tun_tcp_smoothed_rtt_seconds");
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

        build_info.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);

        start_time_seconds.set(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        );

        Self {
            registry,
            build_info,
            start_time_seconds,
            socks_requests_total,
            sessions_active,
            session_duration_seconds,
            bytes_total,
            udp_datagrams_total,
            udp_oversized_dropped_total,
            uplink_selected_total,
            uplink_runtime_failures_total,
            uplink_runtime_failures_suppressed_total,
            uplink_runtime_failure_causes_total,
            uplink_runtime_failure_signatures_total,
            uplink_runtime_failure_other_details_total,
            uplink_failovers_total,
            probe_runs_total,
            probe_duration_seconds,
            probe_bytes_total,
            probe_wakeups_total,
            warm_standby_acquire_total,
            warm_standby_refill_total,
            process_resident_memory_bytes,
            process_virtual_memory_bytes,
            process_heap_allocated_bytes,
            process_heap_mode_info,
            process_open_fds,
            process_threads,
            process_fd_by_type,
            transport_connects_total,
            transport_connects_active,
            upstream_transports_total,
            upstream_transports_active,
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
}
