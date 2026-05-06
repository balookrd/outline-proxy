//! Prometheus metrics facade for outline-ws-rust.
//!
//! The crate has one feature flag:
//!
//! * `prometheus` (default on) — real implementation. Emissions are recorded
//!   into a lazy global `prometheus::Registry`; all recording functions are
//!   inlineable and cheap.
//! * disabled — every recording function becomes a no-op. No prometheus
//!   dependency is linked in. Designed for router / minimal builds.
//!
//! Either way the crate exposes the same public function signatures, so
//! consumers (main binary + subcrates that only record metrics) compile
//! unchanged.

mod snapshot_types;
pub use snapshot_types::*;

#[cfg(feature = "prometheus")]
mod process;
#[cfg(feature = "prometheus")]
mod registration;
#[cfg(feature = "prometheus")]
mod session;
#[cfg(feature = "prometheus")]
mod snapshot;
#[cfg(feature = "prometheus")]
#[cfg(test)]
mod tests;
#[cfg(feature = "prometheus")]
mod transport;
#[cfg(all(feature = "prometheus", feature = "tun"))]
mod tun;

#[cfg(all(feature = "prometheus", feature = "tun"))]
use prometheus::IntGauge;
#[cfg(feature = "prometheus")]
use prometheus::{Gauge, GaugeVec, HistogramVec, IntCounterVec, IntGaugeVec, Registry};
#[cfg(feature = "prometheus")]
use std::sync::LazyLock;

#[cfg(feature = "prometheus")]
pub use self::process::{init, update_process_memory};
#[cfg(feature = "prometheus")]
pub use self::registration::uplink::normalize_other_runtime_failure_detail;
#[cfg(feature = "prometheus")]
pub use self::session::{SessionTracker, track_session};
#[cfg(feature = "prometheus")]
pub use self::snapshot::render_prometheus;
#[cfg(feature = "prometheus")]
pub use self::transport::{
    DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL, add_bytes, add_probe_bytes,
    add_transport_connects_active, add_udp_datagram, add_upstream_transports_active,
    record_dropped_oversized_udp_packet, record_failover, record_metrics_http_request,
    record_probe, record_probe_wakeup, record_request, record_runtime_failure,
    record_runtime_failure_cause, record_runtime_failure_other_detail,
    record_runtime_failure_signature, record_runtime_failure_suppressed, record_transport_connect,
    record_uplink_selected, record_upstream_transport, record_warm_standby_acquire,
    record_warm_standby_refill,
};
#[cfg(all(feature = "prometheus", feature = "tun"))]
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

#[cfg(feature = "prometheus")]
static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

#[cfg(feature = "prometheus")]
struct Metrics {
    registry: Registry,
    build_info: IntGaugeVec,

    start_time_seconds: Gauge,
    socks_requests_total: IntCounterVec,
    sessions_active: IntGaugeVec,
    session_duration_seconds: HistogramVec,
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
    process_resident_memory_bytes: Gauge,
    process_virtual_memory_bytes: Gauge,
    process_heap_allocated_bytes: Gauge,
    process_heap_mode_info: IntGaugeVec,
    process_open_fds: Gauge,
    process_threads: Gauge,
    process_fd_by_type: GaugeVec,
    process_sockets_by_state: IntGaugeVec,
    transport_connects_total: IntCounterVec,
    transport_connects_active: IntGaugeVec,
    upstream_transports_total: IntCounterVec,
    upstream_transports_active: IntGaugeVec,
    metrics_http_requests_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_packets_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_flows_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_flow_duration_seconds: HistogramVec,
    #[cfg(feature = "tun")]
    tun_flows_active: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_icmp_local_replies_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_udp_forward_errors_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_ip_fragments_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_ip_reassemblies_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_ip_fragment_sets_active: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_max_flows: IntGauge,
    #[cfg(feature = "tun")]
    tun_idle_timeout_seconds: Gauge,
    #[cfg(feature = "tun")]
    tun_tcp_events_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_tcp_async_connects_total: IntCounterVec,
    #[cfg(feature = "tun")]
    tun_tcp_async_connects_active: IntGauge,
    #[cfg(feature = "tun")]
    tun_tcp_flows_active: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_inflight_segments: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_inflight_bytes: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_pending_server_bytes: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_buffered_client_segments: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_zero_window_flows: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_backlog_pressure_flows: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_backlog_pressure_seconds: GaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_ack_progress_stall_flows: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_ack_progress_stall_seconds: GaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_congestion_window_bytes: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_slow_start_threshold_bytes: IntGaugeVec,
    #[cfg(feature = "tun")]
    tun_tcp_retransmission_timeout_seconds: GaugeVec,
    #[cfg(feature = "tun")]
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
    uplink_active_wire_index: IntGaugeVec,
    uplink_active_wire_pin_remaining_seconds: GaugeVec,
    uplink_configured_fallbacks_count: IntGaugeVec,
    selection_mode_info: IntGaugeVec,
    routing_scope_info: IntGaugeVec,
    global_active_uplink_info: IntGaugeVec,
    per_uplink_active_uplink_info: IntGaugeVec,
    sticky_routes_total: IntGaugeVec,
    sticky_routes_by_uplink: IntGaugeVec,
}

// ── Stub (prometheus feature disabled) ────────────────────────────────────

#[cfg(not(feature = "prometheus"))]
mod stub;
#[cfg(not(feature = "prometheus"))]
pub use stub::*;
