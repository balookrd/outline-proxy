use super::METRICS;
use std::time::Duration;

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
    METRICS.socks_requests_total.with_label_values(&[command]).inc();
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
        .with_label_values(&[uplink, transport, probe, if success { "success" } else { "error" }])
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
