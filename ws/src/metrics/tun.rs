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

pub fn record_tun_flow_closed(
    group: &str,
    uplink: &str,
    reason: &'static str,
    duration: Duration,
) {
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
