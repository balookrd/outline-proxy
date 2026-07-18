use super::METRICS;
use std::time::Duration;

pub fn record_tun_packet(direction: &'static str, ip_family: &'static str, outcome: &'static str) {
    METRICS
        .tun_packets_total
        .with_label_values(&[direction, ip_family, outcome])
        .inc();
}

pub fn record_tun_flow_created(group: &str, uplink: &str) {
    METRICS
        .tun_flows_total
        .with_label_values(&["created", group, uplink])
        .inc();
    METRICS.tun_flows_active.with_label_values(&[group, uplink]).inc();
}

pub fn record_tun_flow_closed(group: &str, uplink: &str, reason: &'static str, duration: Duration) {
    METRICS
        .tun_flows_total
        .with_label_values(&[reason, group, uplink])
        .inc();
    METRICS
        .tun_flow_duration_seconds
        .with_label_values(&[reason, group, uplink])
        .observe(duration.as_secs_f64());
    METRICS.tun_flows_active.with_label_values(&[group, uplink]).dec();
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

pub fn record_tun_ip_fragment_received(ip_family: &'static str) {
    METRICS.tun_ip_fragments_total.with_label_values(&[ip_family]).inc();
}

pub fn record_tun_ip_reassembly(ip_family: &'static str, result: &'static str) {
    METRICS
        .tun_ip_reassemblies_total
        .with_label_values(&[ip_family, result])
        .inc();
}

pub fn set_tun_ip_fragment_sets_active(ip_family: &'static str, count: usize) {
    METRICS
        .tun_ip_fragment_sets_active
        .with_label_values(&[ip_family])
        .set(i64::try_from(count).unwrap_or(i64::MAX));
}

pub fn set_tun_config(max_flows: usize, idle_timeout: Duration) {
    METRICS
        .tun_max_flows
        .set(i64::try_from(max_flows).unwrap_or(i64::MAX));
    METRICS.tun_idle_timeout_seconds.set(idle_timeout.as_secs_f64());
}

pub fn record_tun_tcp_event(group: &str, uplink: &str, event: &'static str) {
    METRICS
        .tun_tcp_events_total
        .with_label_values(&[group, uplink, event])
        .inc();
}

pub fn record_tun_tcp_sniff(outcome: &'static str) {
    METRICS.tun_tcp_sniff_total.with_label_values(&[outcome]).inc();
}

pub fn record_tun_udp_sniff(outcome: &'static str) {
    METRICS.tun_udp_sniff_total.with_label_values(&[outcome]).inc();
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

pub fn add_tun_tcp_flows_active(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_flows_active
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_inflight_segments(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_inflight_segments
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_inflight_bytes(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_inflight_bytes
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_pending_server_bytes(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_pending_server_bytes
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_buffered_client_segments(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_buffered_client_segments
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_zero_window_flows(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_zero_window_flows
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_backlog_pressure_flows(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_backlog_pressure_flows
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_backlog_pressure_seconds(group: &str, uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_backlog_pressure_seconds
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_ack_progress_stall_flows(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_ack_progress_stall_flows
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_ack_progress_stall_seconds(group: &str, uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_ack_progress_stall_seconds
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_congestion_window_bytes(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_congestion_window_bytes
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_slow_start_threshold_bytes(group: &str, uplink: &str, delta: i64) {
    METRICS
        .tun_tcp_slow_start_threshold_bytes
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_retransmission_timeout_seconds(group: &str, uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_retransmission_timeout_seconds
        .with_label_values(&[group, uplink])
        .add(delta);
}

pub fn add_tun_tcp_smoothed_rtt_seconds(group: &str, uplink: &str, delta: f64) {
    METRICS
        .tun_tcp_smoothed_rtt_seconds
        .with_label_values(&[group, uplink])
        .add(delta);
}

// ── Pre-resolved per-flow gauge handles ────────────────────────────────────

/// Thin handle over a `(group, uplink)`-labelled integer gauge, hiding the
/// `prometheus` type from consumers so the crate's public surface stays
/// backend-agnostic.
#[derive(Clone, Debug)]
pub struct TunFlowGaugeI64(prometheus::IntGauge);

impl TunFlowGaugeI64 {
    #[inline]
    pub fn add(&self, delta: i64) {
        self.0.add(delta);
    }
}

/// Thin handle over a `(group, uplink)`-labelled float gauge.
#[derive(Clone, Debug)]
pub struct TunFlowGaugeF64(prometheus::Gauge);

impl TunFlowGaugeF64 {
    #[inline]
    pub fn add(&self, delta: f64) {
        self.0.add(delta);
    }
}

/// Thin handle over a `(group, uplink)`-labelled monotonic counter.
///
/// Counter-only by construction: histograms are the one metric kind under
/// idle-eviction, so caching a histogram handle across a flow's lifetime would
/// silently buffer samples into a series the renderer no longer drains.
#[derive(Clone, Debug)]
pub struct TunFlowCounterU64(prometheus::IntCounter);

impl TunFlowCounterU64 {
    #[inline]
    pub fn inc_by(&self, delta: u64) {
        self.0.inc_by(delta);
    }
}

/// Pre-resolved handles for the per-flow TUN TCP gauges (plus the one BBR
/// counter) of a single `(group, uplink)` pair.
///
/// `sync_flow_metrics` runs on every accepted TCP packet and touches all of
/// them; resolving each via `with_label_values` there hashes the
/// `(group, uplink)` label pair once per metric per packet — the dominant TUN
/// data-plane metrics cost. Resolve this once per flow (re-resolving only when
/// the flow fails over to a different uplink), then `.add()` / `.inc_by()`
/// straight into the atomic.
#[derive(Clone, Debug)]
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
    /// Monotonic: unlike the gauges, a closing flow must *not* unwind it.
    pub bbr_loss_episodes_total: TunFlowCounterU64,
}

/// Resolves the per-flow handles for `(group, uplink)`. The resulting series and
/// label values are identical to the per-call `add_tun_tcp_*` helpers — this
/// only pre-pays the registry lookup once instead of per packet.
pub fn tun_tcp_flow_gauges(group: &str, uplink: &str) -> TunTcpFlowGauges {
    let labels = [group, uplink];
    TunTcpFlowGauges {
        flows_active: TunFlowGaugeI64(METRICS.tun_tcp_flows_active.with_label_values(&labels)),
        inflight_segments: TunFlowGaugeI64(
            METRICS.tun_tcp_inflight_segments.with_label_values(&labels),
        ),
        inflight_bytes: TunFlowGaugeI64(METRICS.tun_tcp_inflight_bytes.with_label_values(&labels)),
        pending_server_bytes: TunFlowGaugeI64(
            METRICS.tun_tcp_pending_server_bytes.with_label_values(&labels),
        ),
        buffered_client_segments: TunFlowGaugeI64(
            METRICS.tun_tcp_buffered_client_segments.with_label_values(&labels),
        ),
        zero_window_flows: TunFlowGaugeI64(
            METRICS.tun_tcp_zero_window_flows.with_label_values(&labels),
        ),
        backlog_pressure_flows: TunFlowGaugeI64(
            METRICS.tun_tcp_backlog_pressure_flows.with_label_values(&labels),
        ),
        ack_progress_stall_flows: TunFlowGaugeI64(
            METRICS.tun_tcp_ack_progress_stall_flows.with_label_values(&labels),
        ),
        congestion_window_bytes: TunFlowGaugeI64(
            METRICS.tun_tcp_congestion_window_bytes.with_label_values(&labels),
        ),
        slow_start_threshold_bytes: TunFlowGaugeI64(
            METRICS.tun_tcp_slow_start_threshold_bytes.with_label_values(&labels),
        ),
        backlog_pressure_seconds: TunFlowGaugeF64(
            METRICS.tun_tcp_backlog_pressure_seconds.with_label_values(&labels),
        ),
        ack_progress_stall_seconds: TunFlowGaugeF64(
            METRICS.tun_tcp_ack_progress_stall_seconds.with_label_values(&labels),
        ),
        retransmission_timeout_seconds: TunFlowGaugeF64(
            METRICS
                .tun_tcp_retransmission_timeout_seconds
                .with_label_values(&labels),
        ),
        smoothed_rtt_seconds: TunFlowGaugeF64(
            METRICS.tun_tcp_smoothed_rtt_seconds.with_label_values(&labels),
        ),
        bbr_btlbw_bytes_per_second: TunFlowGaugeI64(
            METRICS.tun_tcp_bbr_btlbw_bytes_per_second.with_label_values(&labels),
        ),
        bbr_pacing_rate_bytes_per_second: TunFlowGaugeI64(
            METRICS
                .tun_tcp_bbr_pacing_rate_bytes_per_second
                .with_label_values(&labels),
        ),
        bbr_loss_cap_bytes_per_second: TunFlowGaugeI64(
            METRICS
                .tun_tcp_bbr_loss_cap_bytes_per_second
                .with_label_values(&labels),
        ),
        bbr_inflight_hi_bytes: TunFlowGaugeI64(
            METRICS.tun_tcp_bbr_inflight_hi_bytes.with_label_values(&labels),
        ),
        bbr_inflight_lo_bytes: TunFlowGaugeI64(
            METRICS.tun_tcp_bbr_inflight_lo_bytes.with_label_values(&labels),
        ),
        bbr_loss_capped_flows: TunFlowGaugeI64(
            METRICS.tun_tcp_bbr_loss_capped_flows.with_label_values(&labels),
        ),
        bbr_min_rtt_seconds: TunFlowGaugeF64(
            METRICS.tun_tcp_bbr_min_rtt_seconds.with_label_values(&labels),
        ),
        bbr_loss_episodes_total: TunFlowCounterU64(
            METRICS.tun_tcp_bbr_loss_episodes_total.with_label_values(&labels),
        ),
    }
}
