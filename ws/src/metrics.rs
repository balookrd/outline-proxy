mod process;
mod registration;
mod session;
mod snapshot;
#[cfg(test)]
mod tests;
mod transport;
mod tun;

use once_cell::sync::Lazy;
use prometheus::{Gauge, GaugeVec, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use self::session::RecentSessionWindow;
pub(crate) use crate::memory::ACTIVE_ALLOCATOR;

pub use self::process::{init, spawn_process_metrics_sampler, update_process_memory};
pub use self::session::{SessionTracker, track_session};
pub use self::snapshot::render_prometheus;
pub use self::transport::{
    add_bytes, add_probe_bytes, add_transport_connects_active, add_udp_datagram,
    add_upstream_transports_active, record_dropped_oversized_udp_packet, record_failover,
    record_metrics_http_request, record_probe, record_probe_wakeup, record_request,
    record_runtime_failure, record_runtime_failure_cause, record_runtime_failure_other_detail,
    record_runtime_failure_signature, record_runtime_failure_suppressed, record_transport_connect,
    record_uplink_selected, record_upstream_transport, record_warm_standby_acquire,
    record_warm_standby_refill,
};
pub use self::tun::{
    add_tun_tcp_ack_progress_stall_flows, add_tun_tcp_ack_progress_stall_seconds,
    add_tun_tcp_async_connects_active, add_tun_tcp_backlog_pressure_flows,
    add_tun_tcp_backlog_pressure_seconds, add_tun_tcp_buffered_client_segments,
    add_tun_tcp_congestion_window_bytes, add_tun_tcp_flows_active, add_tun_tcp_inflight_bytes,
    add_tun_tcp_inflight_segments, add_tun_tcp_pending_server_bytes,
    add_tun_tcp_retransmission_timeout_seconds, add_tun_tcp_slow_start_threshold_bytes,
    add_tun_tcp_smoothed_rtt_seconds, add_tun_tcp_zero_window_flows, record_tun_flow_closed,
    record_tun_flow_created, record_tun_icmp_local_reply, record_tun_ip_fragment_received,
    record_tun_ip_reassembly, record_tun_packet, record_tun_tcp_async_connect,
    record_tun_tcp_event, record_tun_udp_forward_error, set_tun_config,
    set_tun_ip_fragment_sets_active,
};

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);
const SESSION_RECENT_WINDOW: Duration = Duration::from_secs(15 * 60);
const SESSION_RECENT_MAX_SAMPLES: usize = 4096;

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
    process_threads: Gauge,
    process_fd_by_type: GaugeVec,
    transport_connects_total: IntCounterVec,
    transport_connects_active: IntGaugeVec,
    upstream_transports_total: IntCounterVec,
    upstream_transports_active: IntGaugeVec,
    tun_packets_total: IntCounterVec,
    tun_flows_total: IntCounterVec,
    tun_flow_duration_seconds: HistogramVec,
    tun_flows_active: IntGaugeVec,
    tun_icmp_local_replies_total: IntCounterVec,
    tun_udp_forward_errors_total: IntCounterVec,
    tun_ip_fragments_total: IntCounterVec,
    tun_ip_reassemblies_total: IntCounterVec,
    tun_ip_fragment_sets_active: IntGaugeVec,
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
    tun_tcp_backlog_pressure_flows: IntGaugeVec,
    tun_tcp_backlog_pressure_seconds: GaugeVec,
    tun_tcp_ack_progress_stall_flows: IntGaugeVec,
    tun_tcp_ack_progress_stall_seconds: GaugeVec,
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
