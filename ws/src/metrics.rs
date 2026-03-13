use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::uplink::UplinkManagerSnapshot;

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);
const SESSION_RECENT_WINDOW: Duration = Duration::from_secs(15 * 60);
const SESSION_RECENT_MAX_SAMPLES: usize = 4096;

struct Metrics {
    registry: Registry,
    build_info: IntGaugeVec,
    start_time_seconds: Gauge,
    socks_requests_total: IntCounterVec,
    sessions_active: IntGaugeVec,
    session_duration_seconds: HistogramVec,
    session_recent_p95_seconds: GaugeVec,
    session_recent_samples: IntGaugeVec,
    bytes_total: IntCounterVec,
    udp_datagrams_total: IntCounterVec,
    uplink_selected_total: IntCounterVec,
    uplink_runtime_failures_total: IntCounterVec,
    uplink_failovers_total: IntCounterVec,
    probe_runs_total: IntCounterVec,
    probe_duration_seconds: HistogramVec,
    warm_standby_acquire_total: IntCounterVec,
    warm_standby_refill_total: IntCounterVec,
    metrics_http_requests_total: IntCounterVec,
    tun_packets_total: IntCounterVec,
    tun_flows_total: IntCounterVec,
    tun_flow_duration_seconds: HistogramVec,
    tun_flows_active: IntGaugeVec,
    tun_max_flows: IntGauge,
    tun_idle_timeout_seconds: Gauge,
    tun_tcp_events_total: IntCounterVec,
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
                "Application payload bytes transferred.",
            ),
            &["protocol", "direction"],
        )
        .expect("bytes_total metric");
        let udp_datagrams_total = IntCounterVec::new(
            Opts::new(
                "outline_ws_rust_udp_datagrams_total",
                "UDP datagrams forwarded by direction.",
            ),
            &["direction"],
        )
        .expect("udp_datagrams_total metric");
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
            .register(Box::new(uplink_selected_total.clone()))
            .expect("register uplink_selected_total");
        registry
            .register(Box::new(uplink_runtime_failures_total.clone()))
            .expect("register uplink_runtime_failures_total");
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
            .register(Box::new(warm_standby_acquire_total.clone()))
            .expect("register warm_standby_acquire_total");
        registry
            .register(Box::new(warm_standby_refill_total.clone()))
            .expect("register warm_standby_refill_total");
        registry
            .register(Box::new(metrics_http_requests_total.clone()))
            .expect("register metrics_http_requests_total");
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
            .register(Box::new(tun_max_flows.clone()))
            .expect("register tun_max_flows");
        registry
            .register(Box::new(tun_idle_timeout_seconds.clone()))
            .expect("register tun_idle_timeout_seconds");
        registry
            .register(Box::new(tun_tcp_events_total.clone()))
            .expect("register tun_tcp_events_total");
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
            .register(Box::new(sticky_routes_total.clone()))
            .expect("register sticky_routes_total");
        registry
            .register(Box::new(sticky_routes_by_uplink.clone()))
            .expect("register sticky_routes_by_uplink");

        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
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
            session_recent_p95_seconds,
            session_recent_samples,
            bytes_total,
            udp_datagrams_total,
            uplink_selected_total,
            uplink_runtime_failures_total,
            uplink_failovers_total,
            probe_runs_total,
            probe_duration_seconds,
            warm_standby_acquire_total,
            warm_standby_refill_total,
            metrics_http_requests_total,
            tun_packets_total,
            tun_flows_total,
            tun_flow_duration_seconds,
            tun_flows_active,
            tun_max_flows,
            tun_idle_timeout_seconds,
            tun_tcp_events_total,
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

        for uplink in &snapshot.uplinks {
            self.uplink_weight
                .with_label_values(&[&uplink.name])
                .set(uplink.weight);
            self.uplink_health
                .with_label_values(&["tcp", &uplink.name])
                .set(bool_to_f64(uplink.tcp_healthy));
            self.uplink_health
                .with_label_values(&["udp", &uplink.name])
                .set(bool_to_f64(uplink.udp_healthy));

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

        for sticky in &snapshot.sticky_routes {
            self.sticky_routes_by_uplink
                .with_label_values(&[&sticky.uplink_name])
                .inc();
        }
    }
}

fn bool_to_f64(value: Option<bool>) -> f64 {
    match value {
        Some(true) => 1.0,
        Some(false) | None => 0.0,
    }
}

pub fn init() {
    let _ = METRICS
        .build_info
        .with_label_values(&[env!("CARGO_PKG_VERSION")]);
    let _ = METRICS.start_time_seconds.get();
    for command in ["connect", "udp_associate"] {
        let _ = METRICS.socks_requests_total.with_label_values(&[command]);
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

pub fn add_bytes(protocol: &'static str, direction: &'static str, bytes: usize) {
    METRICS
        .bytes_total
        .with_label_values(&[protocol, direction])
        .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
}

pub fn add_udp_datagram(direction: &'static str) {
    METRICS
        .udp_datagrams_total
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
    use crate::uplink::UplinkManagerSnapshot;

    fn empty_snapshot() -> UplinkManagerSnapshot {
        UplinkManagerSnapshot {
            generated_at_unix_ms: 0,
            uplinks: Vec::new(),
            sticky_routes: Vec::new(),
        }
    }

    #[test]
    fn render_prometheus_exports_session_histogram_and_recent_p95() {
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
    fn init_exports_zero_value_request_and_session_series() {
        init();

        let rendered = render_prometheus(&empty_snapshot()).expect("render metrics");
        assert!(rendered.contains("outline_ws_rust_requests_total{command=\"connect\"} 0"));
        assert!(rendered.contains(
            "outline_ws_rust_requests_total{command=\"udp_associate\"} 0"
        ));
        assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"tcp\"} 0"));
        assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"udp\"} 0"));
    }

    #[test]
    fn session_window_p95_uses_nearest_rank() {
        let mut window = RecentSessionWindow::default();
        let now = Instant::now();
        for value in [0.1, 0.2, 0.3, 0.4, 0.9] {
            window.samples.push_back((now, value));
        }

        assert_eq!(session_window_p95(&window), 0.9);
    }
}
