use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use crate::memory::{ProcessFdSnapshot, sample_process_memory};
use crate::uplink::UplinkManagerSnapshot;

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);
const SESSION_RECENT_WINDOW: Duration = Duration::from_secs(15 * 60);
const SESSION_RECENT_MAX_SAMPLES: usize = 4096;

#[cfg(feature = "allocator-jemalloc")]
const ACTIVE_ALLOCATOR: &str = "jemalloc";
#[cfg(not(feature = "allocator-jemalloc"))]
const ACTIVE_ALLOCATOR: &str = "system";

struct Metrics {
    registry: Registry,
    build_info: IntGaugeVec,
    allocator_info: IntGaugeVec,
    start_time_seconds: Gauge,
    socks_requests_total: IntCounterVec,
    sessions_active: IntGaugeVec,
    session_duration_seconds: HistogramVec,
    session_recent_p95_seconds: GaugeVec,
    session_recent_samples: IntGaugeVec,
    bytes_total: IntCounterVec,
    udp_datagrams_total: IntCounterVec,
    udp_oversized_dropped_total: IntCounterVec,
    uplink_selected_total: IntCounterVec,
    uplink_runtime_failures_total: IntCounterVec,
    uplink_runtime_failures_suppressed_total: IntCounterVec,
    uplink_runtime_failure_causes_total: IntCounterVec,
    uplink_runtime_failure_signatures_total: IntCounterVec,
    uplink_runtime_failure_other_details_total: IntCounterVec,
    uplink_failovers_total: IntCounterVec,
    probe_runs_total: IntCounterVec,
    probe_duration_seconds: HistogramVec,
    probe_bytes_total: IntCounterVec,
    probe_wakeups_total: IntCounterVec,
    warm_standby_acquire_total: IntCounterVec,
    warm_standby_refill_total: IntCounterVec,
    metrics_http_requests_total: IntCounterVec,
    process_resident_memory_bytes: Gauge,
    process_virtual_memory_bytes: Gauge,
    process_heap_memory_bytes: Gauge,
    process_heap_allocated_bytes: Gauge,
    process_heap_free_bytes: Gauge,
    process_heap_mode_info: IntGaugeVec,
    process_open_fds: Gauge,
    process_fd_by_type: GaugeVec,
    transport_connects_total: IntCounterVec,
    transport_connects_active: IntGaugeVec,
    upstream_transports_total: IntCounterVec,
    upstream_transports_active: IntGaugeVec,
    process_malloc_trim_total: IntCounterVec,
    process_malloc_trim_errors_total: IntCounterVec,
    process_malloc_trim_last_released_bytes: GaugeVec,
    process_malloc_trim_last_bytes: GaugeVec,
    tun_packets_total: IntCounterVec,
    tun_flows_total: IntCounterVec,
    tun_flow_duration_seconds: HistogramVec,
    tun_flows_active: IntGaugeVec,
    tun_icmp_local_replies_total: IntCounterVec,
    tun_udp_forward_errors_total: IntCounterVec,
    tun_max_flows: IntGauge,
    tun_idle_timeout_seconds: Gauge,
    tun_tcp_events_total: IntCounterVec,
    tun_tcp_async_connects_total: IntCounterVec,
    tun_tcp_async_connects_active: IntGauge,
    tun_tcp_flows_active: IntGaugeVec,
    tun_tcp_inflight_segments: IntGaugeVec,
    tun_tcp_inflight_bytes: IntGaugeVec,
    tun_tcp_pending_server_bytes: IntGaugeVec,
    tun_tcp_buffered_client_segments: IntGaugeVec,
    tun_tcp_zero_window_flows: IntGaugeVec,
    tun_tcp_congestion_window_bytes: IntGaugeVec,
    tun_tcp_slow_start_threshold_bytes: IntGaugeVec,
    tun_tcp_retransmission_timeout_seconds: GaugeVec,
    tun_tcp_smoothed_rtt_seconds: GaugeVec,
    uplink_health: GaugeVec,
    uplink_latency_seconds: GaugeVec,
    uplink_rtt_ewma_seconds: GaugeVec,
    uplink_penalty_seconds: GaugeVec,
    uplink_effective_latency_seconds: GaugeVec,
    uplink_score_seconds: GaugeVec,
    uplink_weight: GaugeVec,
    uplink_cooldown_seconds: GaugeVec,
    uplink_standby_ready: IntGaugeVec,
    selection_mode_info: IntGaugeVec,
    routing_scope_info: IntGaugeVec,
    global_active_uplink_info: IntGaugeVec,
    per_uplink_active_uplink_info: IntGaugeVec,
    sticky_routes_total: IntGauge,
    sticky_routes_by_uplink: IntGaugeVec,
    session_recent_windows: Mutex<HashMap<&'static str, RecentSessionWindow>>,
}

pub struct SessionTracker {
    protocol: &'static str,
    started_at: Instant,
}

#[derive(Default)]
struct RecentSessionWindow {
    samples: VecDeque<(Instant, f64)>,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        let build_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_build_info",
                "Build info for outline-ws-rust.",
            ),
            &["version"],
        )
        .expect("build_info metric");
        let allocator_info = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_allocator_info",
                "Allocator info for outline-ws-rust.",
            ),
            &["allocator"],
        )
        .expect("allocator_info metric");
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
            .buckets(vec![
                0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0, 30.0, 60.0, 300.0, 900.0,
            ]),
            &["protocol", "result"],
        )
        .expect("session_duration_seconds metric");
        let session_recent_p95_seconds = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_session_recent_p95_seconds",
                "Rolling p95 of completed proxy session durations by protocol.",
            ),
            &["protocol"],
        )
        .expect("session_recent_p95_seconds metric");
        let session_recent_samples = IntGaugeVec::new(
            Opts::new(
                "outline_ws_rust_session_recent_samples",
                "Number of completed proxy sessions tracked in the rolling latency window.",
            ),
            &["protocol"],
        )
        .expect("session_recent_samples metric");
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
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 10.0,
            ]),
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
        let metrics_http_requests_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_metrics_http_requests_total",
                "HTTP requests served by the built-in metrics endpoint.",
            ),
            &["path", "status"],
        )
        .expect("metrics_http_requests_total metric");
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
        let process_heap_memory_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_heap_memory_bytes",
            "Current heap usage of the process in bytes.",
        ))
        .expect("process_heap_memory_bytes metric");
        let process_heap_allocated_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_heap_allocated_bytes",
            "Current allocator-reported allocated heap bytes.",
        ))
        .expect("process_heap_allocated_bytes metric");
        let process_heap_free_bytes = Gauge::with_opts(Opts::new(
            "outline_ws_rust_process_heap_free_bytes",
            "Current allocator-reported free heap bytes.",
        ))
        .expect("process_heap_free_bytes metric");
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
        let process_malloc_trim_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_process_malloc_trim_total",
                "malloc_trim invocations by reason and result.",
            ),
            &["reason", "result"],
        )
        .expect("process_malloc_trim_total metric");
        let process_malloc_trim_errors_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_process_malloc_trim_errors_total",
                "malloc_trim errors by reason.",
            ),
            &["reason"],
        )
        .expect("process_malloc_trim_errors_total metric");
        let process_malloc_trim_last_released_bytes = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_process_malloc_trim_last_released_bytes",
                "Last observed bytes released by malloc_trim for each memory kind.",
            ),
            &["kind"],
        )
        .expect("process_malloc_trim_last_released_bytes metric");
        let process_malloc_trim_last_bytes = GaugeVec::new(
            Opts::new(
                "outline_ws_rust_process_malloc_trim_last_bytes",
                "Last observed malloc_trim values by memory kind and stage.",
            ),
            &["kind", "stage"],
        )
        .expect("process_malloc_trim_last_bytes metric");
        let tun_packets_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_packets_total",
                "Packets observed on the TUN path by direction, IP family and outcome.",
            ),
            &["direction", "ip_family", "outcome"],
        )
        .expect("tun_packets_total metric");
        let tun_flows_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_tun_flows_total",
                "Lifecycle events for TUN UDP flows.",
            ),
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
            Opts::new(
                "outline_ws_rust_uplink_health",
                "Current uplink health by transport.",
            ),
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
            Opts::new(
                "outline_ws_rust_uplink_weight",
                "Configured static weight for each uplink.",
            ),
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
            Opts::new(
                "outline_ws_rust_routing_scope_info",
                "Configured routing scope.",
            ),
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
            .register(Box::new(allocator_info.clone()))
            .expect("register allocator_info");
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
            .register(Box::new(session_recent_p95_seconds.clone()))
            .expect("register session_recent_p95_seconds");
        registry
            .register(Box::new(session_recent_samples.clone()))
            .expect("register session_recent_samples");
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
            .register(Box::new(metrics_http_requests_total.clone()))
            .expect("register metrics_http_requests_total");
        registry
            .register(Box::new(process_resident_memory_bytes.clone()))
            .expect("register process_resident_memory_bytes");
        registry
            .register(Box::new(process_virtual_memory_bytes.clone()))
            .expect("register process_virtual_memory_bytes");
        registry
            .register(Box::new(process_heap_memory_bytes.clone()))
            .expect("register process_heap_memory_bytes");
        registry
            .register(Box::new(process_heap_allocated_bytes.clone()))
            .expect("register process_heap_allocated_bytes");
        registry
            .register(Box::new(process_heap_free_bytes.clone()))
            .expect("register process_heap_free_bytes");
        registry
            .register(Box::new(process_heap_mode_info.clone()))
            .expect("register process_heap_mode_info");
        registry
            .register(Box::new(process_open_fds.clone()))
            .expect("register process_open_fds");
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
            .register(Box::new(process_malloc_trim_total.clone()))
            .expect("register process_malloc_trim_total");
        registry
            .register(Box::new(process_malloc_trim_errors_total.clone()))
            .expect("register process_malloc_trim_errors_total");
        registry
            .register(Box::new(process_malloc_trim_last_released_bytes.clone()))
            .expect("register process_malloc_trim_last_released_bytes");
        registry
            .register(Box::new(process_malloc_trim_last_bytes.clone()))
            .expect("register process_malloc_trim_last_bytes");
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

        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        allocator_info.with_label_values(&[ACTIVE_ALLOCATOR]).set(1);
        start_time_seconds.set(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        );

        Self {
            registry,
            build_info,
            allocator_info,
            start_time_seconds,
            socks_requests_total,
            sessions_active,
            session_duration_seconds,
            session_recent_p95_seconds,
            session_recent_samples,
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
            metrics_http_requests_total,
            process_resident_memory_bytes,
            process_virtual_memory_bytes,
            process_heap_memory_bytes,
            process_heap_allocated_bytes,
            process_heap_free_bytes,
            process_heap_mode_info,
            process_open_fds,
            process_fd_by_type,
            transport_connects_total,
            transport_connects_active,
            upstream_transports_total,
            upstream_transports_active,
            process_malloc_trim_total,
            process_malloc_trim_errors_total,
            process_malloc_trim_last_released_bytes,
            process_malloc_trim_last_bytes,
            tun_packets_total,
            tun_flows_total,
            tun_flow_duration_seconds,
            tun_flows_active,
            tun_icmp_local_replies_total,
            tun_udp_forward_errors_total,
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
            session_recent_windows: Mutex::new(HashMap::new()),
        }
    }

    fn record_session_sample(&self, protocol: &'static str, duration_seconds: f64) {
        let now = Instant::now();
        let mut windows = self
            .session_recent_windows
            .lock()
            .expect("session_recent_windows lock poisoned");
        let window = windows.entry(protocol).or_default();
        window.samples.push_back((now, duration_seconds));
        prune_session_window(window, now);
        while window.samples.len() > SESSION_RECENT_MAX_SAMPLES {
            window.samples.pop_front();
        }

        self.session_recent_samples
            .with_label_values(&[protocol])
            .set(i64::try_from(window.samples.len()).unwrap_or(i64::MAX));
        self.session_recent_p95_seconds
            .with_label_values(&[protocol])
            .set(session_window_p95(window));
    }

    fn update_snapshot_metrics(&self, snapshot: &UplinkManagerSnapshot) {
        self.uplink_health.reset();
        self.uplink_latency_seconds.reset();
        self.uplink_rtt_ewma_seconds.reset();
        self.uplink_penalty_seconds.reset();
        self.uplink_effective_latency_seconds.reset();
        self.uplink_score_seconds.reset();
        self.uplink_weight.reset();
        self.uplink_cooldown_seconds.reset();
        self.uplink_standby_ready.reset();
        self.sticky_routes_by_uplink.reset();
        self.sticky_routes_total
            .set(i64::try_from(snapshot.sticky_routes.len()).unwrap_or(i64::MAX));
        for mode in ["active_active", "active_passive"] {
            self.selection_mode_info.with_label_values(&[mode]).set(0);
        }
        self.selection_mode_info
            .with_label_values(&[&snapshot.load_balancing_mode])
            .set(1);
        for scope in ["per_flow", "per_uplink", "global"] {
            self.routing_scope_info.with_label_values(&[scope]).set(0);
        }
        self.routing_scope_info
            .with_label_values(&[&snapshot.routing_scope])
            .set(1);

        for uplink in &snapshot.uplinks {
            self.global_active_uplink_info
                .with_label_values(&[&uplink.name])
                .set(0);
            for proto in ["tcp", "udp"] {
                self.per_uplink_active_uplink_info
                    .with_label_values(&[proto, &uplink.name])
                    .set(0);
            }
            self.uplink_weight
                .with_label_values(&[&uplink.name])
                .set(uplink.weight);
            // Only export health when it is known — None (probe not yet run)
            // is left unexported so Grafana shows it as empty rather than 0,
            // which is indistinguishable from a confirmed-unhealthy uplink.
            if let Some(tcp_healthy) = uplink.tcp_healthy {
                self.uplink_health
                    .with_label_values(&["tcp", &uplink.name])
                    .set(if tcp_healthy { 1.0 } else { 0.0 });
            }
            if let Some(udp_healthy) = uplink.udp_healthy {
                self.uplink_health
                    .with_label_values(&["udp", &uplink.name])
                    .set(if udp_healthy { 1.0 } else { 0.0 });
            }

            if let Some(latency_ms) = uplink.tcp_latency_ms {
                self.uplink_latency_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_latency_ms {
                self.uplink_latency_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.tcp_rtt_ewma_ms {
                self.uplink_rtt_ewma_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_rtt_ewma_ms {
                self.uplink_rtt_ewma_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(penalty_ms) = uplink.tcp_penalty_ms {
                self.uplink_penalty_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(penalty_ms as f64 / 1000.0);
            }
            if let Some(penalty_ms) = uplink.udp_penalty_ms {
                self.uplink_penalty_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(penalty_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.tcp_effective_latency_ms {
                self.uplink_effective_latency_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_effective_latency_ms {
                self.uplink_effective_latency_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(score_ms) = uplink.tcp_score_ms {
                self.uplink_score_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(score_ms as f64 / 1000.0);
            }
            if let Some(score_ms) = uplink.udp_score_ms {
                self.uplink_score_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(score_ms as f64 / 1000.0);
            }
            if let Some(cooldown_ms) = uplink.cooldown_tcp_ms {
                self.uplink_cooldown_seconds
                    .with_label_values(&["tcp", &uplink.name])
                    .set(cooldown_ms as f64 / 1000.0);
            }
            if let Some(cooldown_ms) = uplink.cooldown_udp_ms {
                self.uplink_cooldown_seconds
                    .with_label_values(&["udp", &uplink.name])
                    .set(cooldown_ms as f64 / 1000.0);
            }

            self.uplink_standby_ready
                .with_label_values(&["tcp", &uplink.name])
                .set(i64::try_from(uplink.standby_tcp_ready).unwrap_or(i64::MAX));
            self.uplink_standby_ready
                .with_label_values(&["udp", &uplink.name])
                .set(i64::try_from(uplink.standby_udp_ready).unwrap_or(i64::MAX));
        }
        if let Some(global_active_uplink) = &snapshot.global_active_uplink {
            self.global_active_uplink_info
                .with_label_values(&[global_active_uplink])
                .set(1);
        }
        if let Some(tcp_active) = &snapshot.tcp_active_uplink {
            self.per_uplink_active_uplink_info
                .with_label_values(&["tcp", tcp_active])
                .set(1);
        }
        if let Some(udp_active) = &snapshot.udp_active_uplink {
            self.per_uplink_active_uplink_info
                .with_label_values(&["udp", udp_active])
                .set(1);
        }

        for sticky in &snapshot.sticky_routes {
            self.sticky_routes_by_uplink
                .with_label_values(&[&sticky.uplink_name])
                .inc();
        }
    }
}

pub fn init() {
    let _ = METRICS
        .build_info
        .with_label_values(&[env!("CARGO_PKG_VERSION")]);
    let _ = METRICS
        .allocator_info
        .with_label_values(&[ACTIVE_ALLOCATOR]);
    let _ = METRICS.start_time_seconds.get();
    let initial_sample = sample_process_memory();
    update_process_memory(
        initial_sample.rss_bytes,
        initial_sample.virtual_bytes,
        initial_sample.heap_bytes,
        initial_sample.heap_allocated_bytes,
        initial_sample.heap_free_bytes,
        initial_sample.heap_mode,
        initial_sample.open_fds,
        initial_sample.fd_snapshot,
    );
    for kind in ["socket", "pipe", "anon_inode", "regular_file", "other"] {
        METRICS
            .process_fd_by_type
            .with_label_values(&[kind])
            .set(0.0);
    }
    for source in [
        "direct",
        "socks_tcp",
        "socks_udp",
        "tun_udp",
        "tun_tcp",
        "standby_tcp",
        "standby_udp",
        "probe_ws",
        "probe_http",
        "probe_dns",
    ] {
        for mode in ["http1", "h2", "h3"] {
            METRICS
                .transport_connects_active
                .with_label_values(&[source, mode])
                .set(0);
            for result in ["started", "success", "error"] {
                let _ = METRICS
                    .transport_connects_total
                    .with_label_values(&[source, mode, result]);
            }
        }
    }
    for source in [
        "socks_tcp",
        "socks_udp",
        "tun_tcp",
        "tun_udp",
        "probe_http",
        "probe_dns",
    ] {
        for protocol in ["tcp", "udp"] {
            METRICS
                .upstream_transports_active
                .with_label_values(&[source, protocol])
                .set(0);
            for result in ["opened", "closed"] {
                let _ = METRICS
                    .upstream_transports_total
                    .with_label_values(&[source, protocol, result]);
            }
        }
    }
    for (reason, result) in [
        ("opportunistic", "success"),
        ("opportunistic", "noop"),
        ("periodic", "success"),
        ("periodic", "noop"),
    ] {
        let _ = METRICS
            .process_malloc_trim_total
            .with_label_values(&[reason, result]);
        let _ = METRICS
            .process_malloc_trim_errors_total
            .with_label_values(&[reason]);
    }
    for kind in ["rss", "heap"] {
        METRICS
            .process_malloc_trim_last_released_bytes
            .with_label_values(&[kind])
            .set(0.0);
        for stage in ["before", "after", "released"] {
            METRICS
                .process_malloc_trim_last_bytes
                .with_label_values(&[kind, stage])
                .set(0.0);
        }
    }
    for command in ["connect", "udp_associate"] {
        let _ = METRICS.socks_requests_total.with_label_values(&[command]);
    }
    for direction in ["incoming", "outgoing"] {
        let _ = METRICS
            .udp_oversized_dropped_total
            .with_label_values(&[direction]);
    }
    for protocol in ["tcp", "udp"] {
        let _ = METRICS.sessions_active.with_label_values(&[protocol]);
        METRICS
            .session_recent_p95_seconds
            .with_label_values(&[protocol])
            .set(0.0);
        METRICS
            .session_recent_samples
            .with_label_values(&[protocol])
            .set(0);
    }
    for mode in ["active_active", "active_passive"] {
        METRICS
            .selection_mode_info
            .with_label_values(&[mode])
            .set(0);
    }
    for scope in ["per_flow", "per_uplink", "global"] {
        METRICS
            .routing_scope_info
            .with_label_values(&[scope])
            .set(0);
    }
    for result in [
        "started",
        "connected",
        "cancelled",
        "failed",
        "timeout",
        "discarded_closed_flow",
    ] {
        let _ = METRICS
            .tun_tcp_async_connects_total
            .with_label_values(&[result]);
    }
    METRICS.tun_tcp_async_connects_active.set(0);
    for reason in [
        "all_uplinks_failed",
        "transport_error",
        "connect_failed",
        "other",
    ] {
        let _ = METRICS
            .tun_udp_forward_errors_total
            .with_label_values(&[reason]);
    }
    for ip_family in ["ipv4", "ipv6"] {
        let _ = METRICS
            .tun_icmp_local_replies_total
            .with_label_values(&[ip_family]);
    }
}

pub fn spawn_process_metrics_sampler() {
    tokio::spawn(async move {
        let mut sample_count: u64 = 0;
        loop {
            let sample = sample_process_memory();
            update_process_memory(
                sample.rss_bytes,
                sample.virtual_bytes,
                sample.heap_bytes,
                sample.heap_allocated_bytes,
                sample.heap_free_bytes,
                sample.heap_mode,
                sample.open_fds,
                sample.fd_snapshot,
            );
            sample_count = sample_count.saturating_add(1);
            if sample_count % 4 == 0 {
                crate::memory::log_process_fd_snapshot();
            }
            sleep(Duration::from_secs(15)).await;
        }
    });
}

pub fn update_process_memory(
    rss_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    heap_bytes: Option<u64>,
    heap_allocated_bytes: Option<u64>,
    heap_free_bytes: Option<u64>,
    heap_mode: &'static str,
    open_fds: Option<u64>,
    fd_snapshot: Option<ProcessFdSnapshot>,
) {
    METRICS
        .process_resident_memory_bytes
        .set(rss_bytes.unwrap_or(0) as f64);
    METRICS
        .process_virtual_memory_bytes
        .set(virtual_bytes.unwrap_or(0) as f64);
    METRICS
        .process_heap_memory_bytes
        .set(heap_bytes.unwrap_or(0) as f64);
    METRICS
        .process_heap_allocated_bytes
        .set(heap_allocated_bytes.unwrap_or(0) as f64);
    METRICS
        .process_heap_free_bytes
        .set(heap_free_bytes.unwrap_or(0) as f64);
    for mode in ["jemalloc", "exact", "estimated", "unavailable"] {
        METRICS
            .process_heap_mode_info
            .with_label_values(&[mode])
            .set(if mode == heap_mode { 1 } else { 0 });
    }
    METRICS.process_open_fds.set(open_fds.unwrap_or(0) as f64);
    let snapshot = fd_snapshot.unwrap_or_default();
    METRICS
        .process_fd_by_type
        .with_label_values(&["socket"])
        .set(snapshot.sockets as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["pipe"])
        .set(snapshot.pipes as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["anon_inode"])
        .set(snapshot.anon_inodes as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["regular_file"])
        .set(snapshot.regular_files as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["other"])
        .set(snapshot.other as f64);
}

pub fn record_malloc_trim(
    reason: &'static str,
    trimmed: bool,
    rss_before_bytes: Option<u64>,
    rss_after_bytes: Option<u64>,
    rss_released_bytes: Option<u64>,
    heap_before_bytes: Option<u64>,
    heap_after_bytes: Option<u64>,
    heap_released_bytes: Option<u64>,
) {
    METRICS
        .process_malloc_trim_total
        .with_label_values(&[reason, if trimmed { "success" } else { "noop" }])
        .inc();
    METRICS
        .process_malloc_trim_last_released_bytes
        .with_label_values(&["rss"])
        .set(rss_released_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["rss", "before"])
        .set(rss_before_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["rss", "after"])
        .set(rss_after_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["rss", "released"])
        .set(rss_released_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_released_bytes
        .with_label_values(&["heap"])
        .set(heap_released_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["heap", "before"])
        .set(heap_before_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["heap", "after"])
        .set(heap_after_bytes.unwrap_or(0) as f64);
    METRICS
        .process_malloc_trim_last_bytes
        .with_label_values(&["heap", "released"])
        .set(heap_released_bytes.unwrap_or(0) as f64);
}

pub fn record_malloc_trim_error(reason: &'static str) {
    METRICS
        .process_malloc_trim_errors_total
        .with_label_values(&[reason])
        .inc();
}

pub fn record_transport_connect(source: &'static str, mode: &'static str, result: &'static str) {
    METRICS
        .transport_connects_total
        .with_label_values(&[source, mode, result])
        .inc();
}

pub fn add_transport_connects_active(source: &'static str, mode: &'static str, delta: i64) {
    METRICS
        .transport_connects_active
        .with_label_values(&[source, mode])
        .add(delta);
}

pub fn record_upstream_transport(
    source: &'static str,
    protocol: &'static str,
    result: &'static str,
) {
    METRICS
        .upstream_transports_total
        .with_label_values(&[source, protocol, result])
        .inc();
}

pub fn add_upstream_transports_active(source: &'static str, protocol: &'static str, delta: i64) {
    METRICS
        .upstream_transports_active
        .with_label_values(&[source, protocol])
        .add(delta);
}

pub fn record_request(command: &'static str) {
    METRICS
        .socks_requests_total
        .with_label_values(&[command])
        .inc();
}

pub fn track_session(protocol: &'static str) -> SessionTracker {
    METRICS.sessions_active.with_label_values(&[protocol]).inc();
    SessionTracker {
        protocol,
        started_at: Instant::now(),
    }
}

impl SessionTracker {
    pub fn finish(self, success: bool) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        METRICS
            .sessions_active
            .with_label_values(&[self.protocol])
            .dec();
        METRICS
            .session_duration_seconds
            .with_label_values(&[self.protocol, if success { "success" } else { "error" }])
            .observe(elapsed);
        METRICS.record_session_sample(self.protocol, elapsed);
    }
}

pub fn add_bytes(protocol: &'static str, direction: &'static str, uplink: &str, bytes: usize) {
    METRICS
        .bytes_total
        .with_label_values(&[protocol, direction, uplink])
        .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
}

pub fn add_udp_datagram(direction: &'static str, uplink: &str) {
    METRICS
        .udp_datagrams_total
        .with_label_values(&[direction, uplink])
        .inc();
}

pub fn record_dropped_oversized_udp_packet(direction: &'static str) {
    METRICS
        .udp_oversized_dropped_total
        .with_label_values(&[direction])
        .inc();
}

pub fn record_uplink_selected(transport: &'static str, uplink: &str) {
    METRICS
        .uplink_selected_total
        .with_label_values(&[transport, uplink])
        .inc();
}

pub fn record_runtime_failure(transport: &'static str, uplink: &str) {
    METRICS
        .uplink_runtime_failures_total
        .with_label_values(&[transport, uplink])
        .inc();
}

pub fn record_runtime_failure_cause(transport: &'static str, uplink: &str, cause: &'static str) {
    METRICS
        .uplink_runtime_failure_causes_total
        .with_label_values(&[transport, uplink, cause])
        .inc();
}

pub fn record_runtime_failure_signature(
    transport: &'static str,
    uplink: &str,
    signature: &'static str,
) {
    METRICS
        .uplink_runtime_failure_signatures_total
        .with_label_values(&[transport, uplink, signature])
        .inc();
}

pub fn record_runtime_failure_other_detail(transport: &'static str, uplink: &str, detail: &str) {
    METRICS
        .uplink_runtime_failure_other_details_total
        .with_label_values(&[transport, uplink, detail])
        .inc();
}

pub fn record_runtime_failure_suppressed(transport: &'static str, uplink: &str) {
    METRICS
        .uplink_runtime_failures_suppressed_total
        .with_label_values(&[transport, uplink])
        .inc();
}

pub fn record_failover(transport: &'static str, from_uplink: &str, to_uplink: &str) {
    METRICS
        .uplink_failovers_total
        .with_label_values(&[transport, from_uplink, to_uplink])
        .inc();
}

pub fn record_probe(
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    success: bool,
    duration: Duration,
) {
    METRICS
        .probe_runs_total
        .with_label_values(&[
            uplink,
            transport,
            probe,
            if success { "success" } else { "error" },
        ])
        .inc();
    METRICS
        .probe_duration_seconds
        .with_label_values(&[uplink, transport, probe])
        .observe(duration.as_secs_f64());
}

pub fn add_probe_bytes(
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    direction: &'static str,
    bytes: usize,
) {
    METRICS
        .probe_bytes_total
        .with_label_values(&[uplink, transport, probe, direction])
        .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
}

pub fn record_probe_wakeup(
    uplink: &str,
    transport: &'static str,
    reason: &'static str,
    result: &'static str,
) {
    METRICS
        .probe_wakeups_total
        .with_label_values(&[uplink, transport, reason, result])
        .inc();
}

pub fn record_warm_standby_acquire(transport: &'static str, uplink: &str, outcome: &'static str) {
    METRICS
        .warm_standby_acquire_total
        .with_label_values(&[transport, uplink, outcome])
        .inc();
}

pub fn record_warm_standby_refill(transport: &'static str, uplink: &str, success: bool) {
    METRICS
        .warm_standby_refill_total
        .with_label_values(&[transport, uplink, if success { "success" } else { "error" }])
        .inc();
}

pub fn record_metrics_http_request(path: &str, status: u16) {
    let path = match path {
        "/metrics" => "/metrics",
        _ => "other",
    };
    let status = match status {
        200 => "200",
        404 => "404",
        _ => "500",
    };
    METRICS
        .metrics_http_requests_total
        .with_label_values(&[path, status])
        .inc();
}

pub fn record_tun_packet(direction: &'static str, ip_family: &'static str, outcome: &'static str) {
    METRICS
        .tun_packets_total
        .with_label_values(&[direction, ip_family, outcome])
        .inc();
}

pub fn record_tun_flow_created(uplink: &str) {
    METRICS
        .tun_flows_total
        .with_label_values(&["created", uplink])
        .inc();
    METRICS.tun_flows_active.with_label_values(&[uplink]).inc();
}

pub fn record_tun_flow_closed(uplink: &str, reason: &'static str, duration: Duration) {
    METRICS
        .tun_flows_total
        .with_label_values(&[reason, uplink])
        .inc();
    METRICS
        .tun_flow_duration_seconds
        .with_label_values(&[reason, uplink])
        .observe(duration.as_secs_f64());
    METRICS.tun_flows_active.with_label_values(&[uplink]).dec();
}

pub fn record_tun_icmp_local_reply(ip_family: &'static str) {
    METRICS
        .tun_icmp_local_replies_total
        .with_label_values(&[ip_family])
        .inc();
}

pub fn record_tun_udp_forward_error(reason: &'static str) {
    METRICS
        .tun_udp_forward_errors_total
        .with_label_values(&[reason])
        .inc();
}

pub fn set_tun_config(max_flows: usize, idle_timeout: Duration) {
    METRICS
        .tun_max_flows
        .set(i64::try_from(max_flows).unwrap_or(i64::MAX));
    METRICS
        .tun_idle_timeout_seconds
        .set(idle_timeout.as_secs_f64());
}

pub fn record_tun_tcp_event(uplink: &str, event: &'static str) {
    METRICS
        .tun_tcp_events_total
        .with_label_values(&[uplink, event])
        .inc();
}

pub fn record_tun_tcp_async_connect(result: &'static str) {
    METRICS
        .tun_tcp_async_connects_total
        .with_label_values(&[result])
        .inc();
}

pub fn add_tun_tcp_async_connects_active(delta: i64) {
    METRICS.tun_tcp_async_connects_active.add(delta);
}

pub fn add_tun_tcp_flows_active(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_flows_active
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_inflight_segments(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_inflight_segments
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_inflight_bytes(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_inflight_bytes
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_pending_server_bytes(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_pending_server_bytes
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_buffered_client_segments(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_buffered_client_segments
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_zero_window_flows(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_zero_window_flows
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_congestion_window_bytes(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_congestion_window_bytes
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_slow_start_threshold_bytes(uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_slow_start_threshold_bytes
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_retransmission_timeout_seconds(uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_retransmission_timeout_seconds
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn add_tun_tcp_smoothed_rtt_seconds(uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_smoothed_rtt_seconds
        .with_label_values(&[uplink])
        .add(delta);
}

pub fn render_prometheus(snapshot: &UplinkManagerSnapshot) -> Result<String> {
    METRICS.update_snapshot_metrics(snapshot);
    let metric_families = METRICS.registry.gather();
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .context("failed to encode prometheus metrics")?;
    String::from_utf8(buffer).context("failed to encode metrics output as UTF-8")
}

fn prune_session_window(window: &mut RecentSessionWindow, now: Instant) {
    while let Some((recorded_at, _)) = window.samples.front() {
        if now.duration_since(*recorded_at) <= SESSION_RECENT_WINDOW {
            break;
        }
        window.samples.pop_front();
    }
}

fn session_window_p95(window: &RecentSessionWindow) -> f64 {
    if window.samples.is_empty() {
        return 0.0;
    }

    let mut values: Vec<f64> = window.samples.iter().map(|(_, value)| *value).collect();
    values.sort_by(f64::total_cmp);
    let rank = ((values.len() as f64) * 0.95).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uplink::{UplinkManagerSnapshot, UplinkSnapshot};
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static METRICS_TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        match METRICS_TEST_GUARD.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn empty_snapshot() -> UplinkManagerSnapshot {
        UplinkManagerSnapshot {
            generated_at_unix_ms: 0,
            load_balancing_mode: "active_active".to_string(),
            routing_scope: "per_flow".to_string(),
            global_active_uplink: None,
            tcp_active_uplink: None,
            udp_active_uplink: None,
            uplinks: Vec::new(),
            sticky_routes: Vec::new(),
        }
    }

    fn snapshot_uplink(name: &str) -> UplinkSnapshot {
        UplinkSnapshot {
            index: 0,
            name: name.to_string(),
            weight: 1.0,
            tcp_healthy: None,
            udp_healthy: None,
            tcp_latency_ms: None,
            udp_latency_ms: None,
            tcp_rtt_ewma_ms: None,
            udp_rtt_ewma_ms: None,
            tcp_penalty_ms: None,
            udp_penalty_ms: None,
            tcp_effective_latency_ms: None,
            udp_effective_latency_ms: None,
            tcp_score_ms: None,
            udp_score_ms: None,
            cooldown_tcp_ms: None,
            cooldown_udp_ms: None,
            last_checked_ago_ms: None,
            last_error: None,
            standby_tcp_ready: 0,
            standby_udp_ready: 0,
            tcp_consecutive_failures: 0,
            udp_consecutive_failures: 0,
            h3_tcp_downgrade_until_ms: None,
            last_active_tcp_ago_ms: None,
            last_active_udp_ago_ms: None,
        }
    }

    #[test]
    fn render_prometheus_exports_session_histogram_and_recent_p95() {
        let _guard = test_guard();
        init();
        let session = track_session("tcp");
        session.finish(true);

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains("outline_ws_rust_session_duration_seconds_bucket"));
        assert!(rendered.contains("outline_ws_rust_session_recent_p95_seconds"));
        assert!(rendered.contains("outline_ws_rust_session_recent_samples"));
        assert!(rendered.contains("protocol=\"tcp\""));
        assert!(rendered.contains("result=\"success\""));
    }

    #[test]
    fn render_prometheus_exports_process_memory_metrics() {
        let _guard = test_guard();
        init();
        update_process_memory(
            Some(1234),
            Some(4321),
            Some(5678),
            Some(5678),
            Some(256),
            "jemalloc",
            Some(42),
            Some(ProcessFdSnapshot {
                total: 42,
                sockets: 20,
                pipes: 10,
                anon_inodes: 5,
                regular_files: 6,
                other: 1,
            }),
        );
        record_malloc_trim(
            "periodic",
            true,
            Some(4096),
            Some(3072),
            Some(1024),
            Some(8192),
            Some(6144),
            Some(2048),
        );

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains("outline_ws_rust_process_resident_memory_bytes 1234"));
        assert!(rendered.contains("outline_ws_rust_process_virtual_memory_bytes 4321"));
        assert!(rendered.contains("outline_ws_rust_process_heap_memory_bytes 5678"));
        assert!(rendered.contains("outline_ws_rust_process_heap_allocated_bytes 5678"));
        assert!(rendered.contains("outline_ws_rust_process_heap_free_bytes 256"));
        assert!(rendered.contains("outline_ws_rust_process_heap_mode_info{mode=\"jemalloc\"} 1"));
        assert!(rendered.contains("outline_ws_rust_process_open_fds 42"));
        assert!(rendered.contains("outline_ws_rust_process_fd_by_type{kind=\"socket\"} 20"));
        assert!(rendered.contains("outline_ws_rust_process_fd_by_type{kind=\"pipe\"} 10"));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_total{reason=\"periodic\",result=\"success\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_last_released_bytes{kind=\"rss\"} 1024"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_last_released_bytes{kind=\"heap\"} 2048"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_last_bytes{kind=\"rss\",stage=\"before\"} 4096"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_last_bytes{kind=\"rss\",stage=\"after\"} 3072"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_process_malloc_trim_last_bytes{kind=\"rss\",stage=\"released\"} 1024"
        ));
        assert!(rendered.contains(&format!(
            "outline_ws_rust_allocator_info{{allocator=\"{}\"}} 1",
            ACTIVE_ALLOCATOR
        )));
    }

    #[test]
    fn render_prometheus_exports_transport_connect_metrics() {
        let _guard = test_guard();
        init();
        add_transport_connects_active("tun_tcp", "h2", 2);
        record_transport_connect("tun_tcp", "h2", "started");
        record_transport_connect("tun_tcp", "h2", "success");
        record_transport_connect("probe_http", "h3", "error");
        record_runtime_failure_suppressed("udp", "primary");
        add_upstream_transports_active("tun_tcp", "tcp", 1);
        record_upstream_transport("tun_tcp", "tcp", "opened");
        record_upstream_transport("tun_tcp", "tcp", "closed");

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(
            rendered.contains(
                "outline_ws_rust_transport_connects_active{mode=\"h2\",source=\"tun_tcp\"}"
            )
        );
        assert!(rendered.contains(
            "outline_ws_rust_transport_connects_total{mode=\"h2\",result=\"started\",source=\"tun_tcp\"}"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_transport_connects_total{mode=\"h2\",result=\"success\",source=\"tun_tcp\"}"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_transport_connects_total{mode=\"h3\",result=\"error\",source=\"probe_http\"}"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_uplink_runtime_failures_suppressed_total{transport=\"udp\",uplink=\"primary\"}"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_upstream_transports_active{protocol=\"tcp\",source=\"tun_tcp\"}"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_upstream_transports_total{protocol=\"tcp\",result=\"opened\",source=\"tun_tcp\"}"
        ));
    }

    #[test]
    fn render_prometheus_exports_traffic_metrics_with_uplink_labels() {
        let _guard = test_guard();
        init();
        add_bytes("tcp", "client_to_upstream", "nuxt", 128);
        add_bytes("udp", "upstream_to_client", "senko", 256);
        add_probe_bytes("primary", "tcp", "http", "outgoing", 64);
        add_probe_bytes("primary", "udp", "dns", "incoming", 96);
        record_probe_wakeup("primary", "udp", "runtime_failure", "sent");
        record_probe_wakeup("primary", "udp", "runtime_failure", "suppressed");
        record_runtime_failure_cause("tcp", "primary", "timeout");
        record_runtime_failure_signature("tcp", "primary", "read_failed");
        record_runtime_failure_other_detail("tcp", "primary", "failed_to_read_chunk");
        add_udp_datagram("client_to_upstream", "nuxt");
        add_udp_datagram("upstream_to_client", "senko");
        record_dropped_oversized_udp_packet("incoming");

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains(
            "outline_ws_rust_bytes_total{direction=\"client_to_upstream\",protocol=\"tcp\",uplink=\"nuxt\"} 128"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_bytes_total{direction=\"upstream_to_client\",protocol=\"udp\",uplink=\"senko\"} 256"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_probe_bytes_total{direction=\"outgoing\",probe=\"http\",transport=\"tcp\",uplink=\"primary\"} 64"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_probe_bytes_total{direction=\"incoming\",probe=\"dns\",transport=\"udp\",uplink=\"primary\"} 96"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_probe_wakeups_total{reason=\"runtime_failure\",result=\"sent\",transport=\"udp\",uplink=\"primary\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_probe_wakeups_total{reason=\"runtime_failure\",result=\"suppressed\",transport=\"udp\",uplink=\"primary\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_uplink_runtime_failure_causes_total{cause=\"timeout\",transport=\"tcp\",uplink=\"primary\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_uplink_runtime_failure_signatures_total{signature=\"read_failed\",transport=\"tcp\",uplink=\"primary\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_uplink_runtime_failure_other_details_total{detail=\"failed_to_read_chunk\",transport=\"tcp\",uplink=\"primary\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_udp_datagrams_total{direction=\"client_to_upstream\",uplink=\"nuxt\"} 1"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_udp_datagrams_total{direction=\"upstream_to_client\",uplink=\"senko\"} 1"
        ));
        assert!(
            rendered
                .contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"incoming\"} 1")
        );
    }

    #[test]
    fn render_prometheus_exports_routing_selection_info() {
        let _guard = test_guard();
        init();

        let rendered = render_prometheus(&UplinkManagerSnapshot {
            generated_at_unix_ms: 0,
            load_balancing_mode: "active_passive".to_string(),
            routing_scope: "global".to_string(),
            global_active_uplink: Some("senko".to_string()),
            tcp_active_uplink: None,
            udp_active_uplink: None,
            uplinks: Vec::new(),
            sticky_routes: Vec::new(),
        })
        .expect("render metrics");

        assert!(
            rendered.contains("outline_ws_rust_selection_mode_info{mode=\"active_passive\"} 1")
        );
        assert!(rendered.contains("outline_ws_rust_routing_scope_info{scope=\"global\"} 1"));
        assert!(rendered.contains("outline_ws_rust_global_active_uplink_info{uplink=\"senko\"} 1"));
    }

    #[test]
    fn render_prometheus_clears_previous_global_active_uplink() {
        let _guard = test_guard();
        init();

        render_prometheus(&UplinkManagerSnapshot {
            generated_at_unix_ms: 0,
            load_balancing_mode: "active_passive".to_string(),
            routing_scope: "global".to_string(),
            global_active_uplink: Some("senko".to_string()),
            tcp_active_uplink: None,
            udp_active_uplink: None,
            uplinks: vec![snapshot_uplink("senko"), snapshot_uplink("nuxt")],
            sticky_routes: Vec::new(),
        })
        .expect("render first metrics");

        let rendered = render_prometheus(&UplinkManagerSnapshot {
            generated_at_unix_ms: 0,
            load_balancing_mode: "active_passive".to_string(),
            routing_scope: "global".to_string(),
            global_active_uplink: Some("nuxt".to_string()),
            tcp_active_uplink: None,
            udp_active_uplink: None,
            uplinks: vec![snapshot_uplink("senko"), snapshot_uplink("nuxt")],
            sticky_routes: Vec::new(),
        })
        .expect("render second metrics");

        assert!(rendered.contains("outline_ws_rust_global_active_uplink_info{uplink=\"senko\"} 0"));
        assert!(rendered.contains("outline_ws_rust_global_active_uplink_info{uplink=\"nuxt\"} 1"));
    }

    #[test]
    fn init_exports_zero_value_tun_udp_forward_error_series() {
        let _guard = test_guard();
        init();

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains(
            "outline_ws_rust_tun_udp_forward_errors_total{reason=\"all_uplinks_failed\"} 0"
        ));
        assert!(rendered.contains(
            "outline_ws_rust_tun_udp_forward_errors_total{reason=\"transport_error\"} 0"
        ));
        assert!(
            rendered.contains(
                "outline_ws_rust_tun_udp_forward_errors_total{reason=\"connect_failed\"} 0"
            )
        );
        assert!(
            rendered.contains("outline_ws_rust_tun_udp_forward_errors_total{reason=\"other\"} 0")
        );
        assert!(
            rendered.contains("outline_ws_rust_tun_icmp_local_replies_total{ip_family=\"ipv4\"} 0")
        );
        assert!(
            rendered.contains("outline_ws_rust_tun_icmp_local_replies_total{ip_family=\"ipv6\"} 0")
        );
    }

    #[test]
    fn init_exports_zero_value_request_and_session_series() {
        let _guard = test_guard();
        init();

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains("outline_ws_rust_requests_total{command=\"connect\"} 0"));
        assert!(rendered.contains("outline_ws_rust_requests_total{command=\"udp_associate\"} 0"));
        assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"tcp\"} 0"));
        assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"udp\"} 0"));
        assert!(
            rendered
                .contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"incoming\"} 0")
        );
        assert!(
            rendered
                .contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"outgoing\"} 0")
        );
    }

    #[test]
    fn session_window_p95_uses_nearest_rank() {
        let _guard = test_guard();
        let mut window = RecentSessionWindow::default();
        let now = Instant::now();
        for value in [0.1, 0.2, 0.3, 0.4, 0.9] {
            window.samples.push_back((now, value));
        }

        assert_eq!(session_window_p95(&window), 0.9);
    }
}
