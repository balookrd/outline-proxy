// Stub metrics module used when the `metrics` feature is disabled.
// All functions are no-ops; types are zero-size. Callers need no changes.

use std::time::Duration;

use crate::memory::ProcessFdSnapshot;
use crate::uplink::UplinkManagerSnapshot;

pub const BYPASS_UPLINK_LABEL: &str = "bypass";
pub const BYPASS_GROUP_LABEL: &str = "direct";

// ── Process ──────────────────────────────────────────────────────────────────

pub fn init() {}
pub fn spawn_process_metrics_sampler() {}
#[allow(clippy::too_many_arguments)]
pub fn update_process_memory(
    _rss_bytes: Option<u64>,
    _virtual_bytes: Option<u64>,
    _heap_bytes: Option<u64>,
    _heap_allocated_bytes: Option<u64>,
    _heap_free_bytes: Option<u64>,
    _heap_mode: &'static str,
    _open_fds: Option<u64>,
    _thread_count: Option<u64>,
    _fd_snapshot: Option<ProcessFdSnapshot>,
) {
}

// ── Session ───────────────────────────────────────────────────────────────────

pub struct SessionTracker;

impl SessionTracker {
    pub fn finish(self, _success: bool) {}
}

pub fn track_session(_protocol: &'static str) -> SessionTracker {
    SessionTracker
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

pub fn render_prometheus(_: &[UplinkManagerSnapshot]) -> anyhow::Result<String> {
    Ok(String::new())
}

// ── Transport ─────────────────────────────────────────────────────────────────

pub fn record_transport_connect(_source: &'static str, _mode: &'static str, _result: &'static str) {
}
pub fn add_transport_connects_active(_source: &'static str, _mode: &'static str, _delta: i64) {}
pub fn record_upstream_transport(
    _source: &'static str,
    _protocol: &'static str,
    _result: &'static str,
) {
}
pub fn add_upstream_transports_active(_source: &'static str, _protocol: &'static str, _delta: i64) {
}
pub fn record_request(_command: &'static str) {}
pub fn add_bytes(
    _protocol: &'static str,
    _direction: &'static str,
    _group: &str,
    _uplink: &str,
    _bytes: usize,
) {
}
pub fn add_udp_datagram(_direction: &'static str, _group: &str, _uplink: &str) {}
pub fn record_dropped_oversized_udp_packet(_direction: &'static str) {}
pub fn record_uplink_selected(_transport: &'static str, _group: &str, _uplink: &str) {}
pub fn record_runtime_failure(_transport: &'static str, _group: &str, _uplink: &str) {}
pub fn record_runtime_failure_cause(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _cause: &'static str,
) {
}
pub fn record_runtime_failure_signature(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _signature: &'static str,
) {
}
pub fn record_runtime_failure_other_detail(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _detail: &str,
) {
}
pub fn record_runtime_failure_suppressed(_transport: &'static str, _group: &str, _uplink: &str) {}
pub fn record_failover(
    _transport: &'static str,
    _group: &str,
    _from_uplink: &str,
    _to_uplink: &str,
) {
}
pub fn record_probe(
    _group: &str,
    _uplink: &str,
    _transport: &'static str,
    _probe: &'static str,
    _success: bool,
    _duration: Duration,
) {
}
pub fn add_probe_bytes(
    _group: &str,
    _uplink: &str,
    _transport: &'static str,
    _protocol: &'static str,
    _direction: &'static str,
    _bytes: usize,
) {
}
pub fn record_probe_wakeup(
    _group: &str,
    _uplink: &str,
    _transport: &'static str,
    _reason: &'static str,
    _result: &'static str,
) {
}
pub fn record_warm_standby_acquire(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _outcome: &'static str,
) {
}
pub fn record_warm_standby_refill(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _success: bool,
) {
}
pub fn record_metrics_http_request(_path: &str, _status: u16) {}

// ── TUN ───────────────────────────────────────────────────────────────────────

pub fn record_tun_packet(
    _direction: &'static str,
    _ip_family: &'static str,
    _outcome: &'static str,
) {
}
pub fn record_tun_flow_created(_group: &str, _uplink: &str) {}
pub fn record_tun_flow_closed(
    _group: &str,
    _uplink: &str,
    _reason: &'static str,
    _duration: Duration,
) {
}
pub fn record_tun_icmp_local_reply(_ip_family: &'static str) {}
pub fn record_tun_udp_forward_error(_reason: &'static str) {}
pub fn record_tun_ip_fragment_received(_ip_family: &'static str) {}
pub fn record_tun_ip_reassembly(_ip_family: &'static str, _result: &'static str) {}
pub fn set_tun_ip_fragment_sets_active(_ip_family: &'static str, _count: usize) {}
pub fn set_tun_config(_max_flows: usize, _idle_timeout: Duration) {}
pub fn record_tun_tcp_event(_group: &str, _uplink: &str, _event: &'static str) {}
pub fn record_tun_tcp_async_connect(_result: &'static str) {}
pub fn add_tun_tcp_async_connects_active(_delta: i64) {}
pub fn add_tun_tcp_flows_active(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_inflight_segments(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_inflight_bytes(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_pending_server_bytes(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_buffered_client_segments(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_zero_window_flows(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_backlog_pressure_flows(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_backlog_pressure_seconds(_group: &str, _uplink: &str, _delta: f64) {}
pub fn add_tun_tcp_ack_progress_stall_flows(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_ack_progress_stall_seconds(_group: &str, _uplink: &str, _delta: f64) {}
pub fn add_tun_tcp_congestion_window_bytes(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_slow_start_threshold_bytes(_group: &str, _uplink: &str, _delta: i64) {}
pub fn add_tun_tcp_retransmission_timeout_seconds(_group: &str, _uplink: &str, _delta: f64) {}
pub fn add_tun_tcp_smoothed_rtt_seconds(_group: &str, _uplink: &str, _delta: f64) {}
