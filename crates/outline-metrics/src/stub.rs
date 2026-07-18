// Stub metrics module used when the `metrics` feature is disabled.
// All functions are no-ops; types are zero-size. Callers need no changes.

use std::time::Duration;

use crate::snapshot_types::ProcessFdSnapshot;
use crate::snapshot_types::UplinkManagerSnapshot;

pub const DIRECT_UPLINK_LABEL: &str = "direct";
pub const DIRECT_GROUP_LABEL: &str = "direct";

// ── Process ──────────────────────────────────────────────────────────────────

pub fn init() {}
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

pub struct SessionTracker {
    finished: bool,
}

impl SessionTracker {
    pub fn finish(mut self, _success: bool) {
        self.finished = true;
    }
}

impl Drop for SessionTracker {
    fn drop(&mut self) {}
}

pub fn track_session(_protocol: &'static str) -> SessionTracker {
    SessionTracker { finished: false }
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
pub fn add_uplink_open_connections(_group: &str, _transport: &str, _uplink: &str, _delta: i64) {}
pub fn record_uplink_connection_close(
    _group: &str,
    _transport: &str,
    _uplink: &str,
    _classification: &'static str,
) {
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

#[derive(Clone, Default)]
pub struct FlowBytesCounter;

impl FlowBytesCounter {
    #[inline]
    pub fn add(&self, _bytes: usize) {}
}

pub fn flow_bytes_counter(
    _protocol: &str,
    _direction: &str,
    _group: &str,
    _uplink: &str,
) -> FlowBytesCounter {
    FlowBytesCounter
}

#[derive(Clone, Default)]
pub struct UdpFlowCounters;

impl UdpFlowCounters {
    #[inline]
    pub fn record(&self, _bytes: usize) {}
}

pub fn udp_flow_counters(_direction: &str, _group: &str, _uplink: &str) -> UdpFlowCounters {
    UdpFlowCounters
}

static DIRECT_TCP_BYTES: FlowBytesCounter = FlowBytesCounter;
static DIRECT_UDP_COUNTERS: UdpFlowCounters = UdpFlowCounters;

pub fn direct_tcp_bytes(_direction: &str) -> &'static FlowBytesCounter {
    &DIRECT_TCP_BYTES
}

pub fn direct_udp_counters(_direction: &str) -> &'static UdpFlowCounters {
    &DIRECT_UDP_COUNTERS
}

pub fn record_dropped_oversized_udp_packet(_direction: &'static str, _cause: &'static str) {}
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
pub fn normalize_other_runtime_failure_detail(_error_text: &str) -> String {
    String::new()
}
pub fn record_runtime_failure_suppressed(_transport: &'static str, _group: &str, _uplink: &str) {}
pub fn record_failover(
    _transport: &'static str,
    _group: &str,
    _from_uplink: &str,
    _to_uplink: &str,
) {
}
pub fn record_socks_tcp_strict_abort(_group: &str, _uplink: &str, _reason: &'static str) {}
pub fn record_mid_session_retry(
    _transport: &'static str,
    _group: &str,
    _uplink: &str,
    _outcome: &'static str,
) {
}
pub fn record_soft_switch(_group: &str, _outcome: &'static str) {}
pub fn record_resume_lookup(_transport: &'static str, _scope: &'static str, _result: &'static str) {
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
pub fn record_metrics_http_request(_path: &'static str, _status: u16) {}

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
pub fn record_tun_tcp_sniff(_outcome: &'static str) {}
pub fn record_tun_udp_sniff(_outcome: &'static str) {}
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

#[derive(Clone, Debug, Default)]
pub struct TunFlowGaugeI64;

impl TunFlowGaugeI64 {
    #[inline]
    pub fn add(&self, _delta: i64) {}
}

#[derive(Clone, Debug, Default)]
pub struct TunFlowGaugeF64;

impl TunFlowGaugeF64 {
    #[inline]
    pub fn add(&self, _delta: f64) {}
}

#[derive(Clone, Debug, Default)]
pub struct TunFlowCounterU64;

impl TunFlowCounterU64 {
    #[inline]
    pub fn inc_by(&self, _delta: u64) {}
}

#[derive(Clone, Debug, Default)]
pub struct TunTcpFlowGauges {
    pub flows_active: TunFlowGaugeI64,
    pub inflight_segments: TunFlowGaugeI64,
    pub inflight_bytes: TunFlowGaugeI64,
    pub pending_server_bytes: TunFlowGaugeI64,
    pub buffered_client_segments: TunFlowGaugeI64,
    pub zero_window_flows: TunFlowGaugeI64,
    pub backlog_pressure_flows: TunFlowGaugeI64,
    pub ack_progress_stall_flows: TunFlowGaugeI64,
    pub congestion_window_bytes: TunFlowGaugeI64,
    pub slow_start_threshold_bytes: TunFlowGaugeI64,
    pub backlog_pressure_seconds: TunFlowGaugeF64,
    pub ack_progress_stall_seconds: TunFlowGaugeF64,
    pub retransmission_timeout_seconds: TunFlowGaugeF64,
    pub smoothed_rtt_seconds: TunFlowGaugeF64,
    pub bbr_btlbw_bytes_per_second: TunFlowGaugeI64,
    pub bbr_pacing_rate_bytes_per_second: TunFlowGaugeI64,
    pub bbr_loss_cap_bytes_per_second: TunFlowGaugeI64,
    pub bbr_inflight_hi_bytes: TunFlowGaugeI64,
    pub bbr_inflight_lo_bytes: TunFlowGaugeI64,
    pub bbr_loss_capped_flows: TunFlowGaugeI64,
    pub bbr_min_rtt_seconds: TunFlowGaugeF64,
    pub bbr_loss_episodes_total: TunFlowCounterU64,
}

pub fn tun_tcp_flow_gauges(_group: &str, _uplink: &str) -> TunTcpFlowGauges {
    TunTcpFlowGauges::default()
}
