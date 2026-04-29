use std::time::Duration;

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{
    Matcher, PrometheusBuilder, PrometheusHandle, PrometheusRecorder,
};
use metrics_util::MetricKindMask;

const TCP_CONNECT_BUCKETS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const UDP_RELAY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const WS_SESSION_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 14400.0];
// Power-of-two ladder from 256 B to 64 KiB. The hot regime for diagnosing
// throughput issues is the 1–16 KiB band: a healthy bulk-relay session
// concentrates near the upper end (LEGACY_MAX_CHUNK_SIZE = 16383), while a
// non-batched relay smears down toward TCP-segment size (~1.4 KiB).
const WS_FRAME_SIZE_BUCKETS: &[f64] = &[
    256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0,
];
// `tuning.ws_data_channel_capacity` defaults to 128 (LARGE) and may be
// raised to 256/512 in pathological deployments. Buckets cover the
// full 0..max range with finer granularity near the saturation tail —
// that is where backpressure-induced stalls become visible.
const WS_DATA_CHANNEL_FILL_BUCKETS: &[f64] =
    &[0.0, 8.0, 32.0, 64.0, 96.0, 120.0, 128.0, 192.0, 256.0, 384.0, 512.0];

pub(super) fn build_recorder(idle_timeout: Duration) -> (PrometheusRecorder, PrometheusHandle) {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_tcp_upstream_connect_duration_seconds".into()),
            TCP_CONNECT_BUCKETS,
        )
        .expect("invalid TCP connect bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_udp_relay_duration_seconds".into()),
            UDP_RELAY_BUCKETS,
        )
        .expect("invalid UDP relay bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_websocket_session_duration_seconds".into()),
            WS_SESSION_BUCKETS,
        )
        .expect("invalid WebSocket session bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_websocket_frame_size_bytes".into()),
            WS_FRAME_SIZE_BUCKETS,
        )
        .expect("invalid WebSocket frame size bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_ws_data_channel_fill".into()),
            WS_DATA_CHANNEL_FILL_BUCKETS,
        )
        .expect("invalid WS data channel fill bucket config")
        .idle_timeout(MetricKindMask::ALL, Some(idle_timeout))
        .build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

pub(super) fn register_descriptions() {
    describe_gauge!("outline_ss_build_info", "Build metadata for the running binary.");
    describe_gauge!(
        "outline_ss_config_info",
        "Static server configuration flags exposed as labels."
    );
    describe_gauge!("outline_ss_uptime_seconds", "Seconds since the process started.");
    describe_counter!(
        "outline_ss_metrics_scrapes_total",
        "Number of successful Prometheus scrapes."
    );
    describe_counter!("outline_ss_websocket_upgrades_total", "Total accepted websocket upgrades.");
    describe_counter!(
        "outline_ss_websocket_disconnects_total",
        "Websocket session completions grouped by outcome."
    );
    describe_gauge!("outline_ss_active_websocket_sessions", "Currently active websocket sessions.");
    describe_histogram!(
        "outline_ss_websocket_session_duration_seconds",
        "Wall-clock websocket session duration."
    );
    describe_counter!("outline_ss_websocket_frames_total", "Binary websocket frames transferred.");
    describe_counter!(
        "outline_ss_websocket_bytes_total",
        "Encrypted websocket payload bytes transferred."
    );
    describe_histogram!(
        "outline_ss_websocket_frame_size_bytes",
        "Distribution of binary websocket frame payload sizes by app_protocol/direction."
    );
    describe_counter!(
        "outline_ss_websocket_pong_deadline_total",
        "Sessions torn down by the server because no inbound frame arrived within the pong deadline."
    );
    describe_histogram!(
        "outline_ss_ws_data_channel_fill",
        "Depth of the upstream→ws-writer mpsc channel sampled at every push, by app_protocol/transport."
    );
    describe_counter!(
        "outline_ss_client_sessions_total",
        "Authenticated client sessions by user, transport and protocol."
    );
    describe_gauge!(
        "outline_ss_client_last_seen_seconds",
        "Unix timestamp of the most recent successful client activity by user."
    );
    describe_gauge!(
        "outline_ss_client_active",
        "Client active state by user using the configured TTL."
    );
    describe_gauge!(
        "outline_ss_client_up",
        "Alias of outline_ss_client_active for online-state dashboards."
    );
    describe_counter!(
        "outline_ss_tcp_authenticated_sessions_total",
        "Authenticated TCP relay sessions by user and client protocol."
    );
    describe_counter!(
        "outline_ss_tcp_upstream_connects_total",
        "TCP upstream connect attempts by result."
    );
    describe_gauge!(
        "outline_ss_active_tcp_upstream_connections",
        "Currently active outbound TCP connections."
    );
    describe_histogram!(
        "outline_ss_tcp_upstream_connect_duration_seconds",
        "TCP upstream connect latency."
    );
    describe_counter!(
        "outline_ss_tcp_payload_bytes_total",
        "Plain TCP payload bytes relayed after Shadowsocks decryption."
    );
    describe_counter!("outline_ss_udp_requests_total", "UDP relay requests by result.");
    describe_histogram!(
        "outline_ss_udp_relay_duration_seconds",
        "End-to-end UDP request handling duration."
    );
    describe_counter!(
        "outline_ss_udp_payload_bytes_total",
        "Plain UDP payload bytes relayed after Shadowsocks decryption."
    );
    describe_counter!(
        "outline_ss_udp_response_datagrams_total",
        "UDP response datagrams sent back to the client."
    );
    describe_counter!(
        "outline_ss_udp_relay_drops_total",
        "UDP datagrams dropped before relay because of transport backpressure or concurrency limits."
    );
    describe_counter!(
        "outline_ss_udp_oversized_datagrams_dropped_total",
        "UDP datagrams dropped because they exceeded the maximum payload size supported by the transport path."
    );
    describe_gauge!(
        "outline_ss_udp_nat_active_entries",
        "Current number of active UDP NAT table entries."
    );
    describe_counter!(
        "outline_ss_udp_nat_entries_created_total",
        "Total UDP NAT table entries ever created."
    );
    describe_counter!(
        "outline_ss_udp_nat_entries_evicted_total",
        "Total UDP NAT table entries evicted due to idle timeout."
    );
    describe_counter!(
        "outline_ss_udp_nat_responses_dropped_total",
        "UDP upstream responses dropped because no WebSocket session was registered."
    );
    describe_counter!(
        "outline_ss_maintenance_task_panics_total",
        "Background maintenance tasks that panicked and triggered server shutdown."
    );
    describe_counter!(
        "outline_ss_orphan_park_total",
        "Sessions moved into the cross-transport resumption orphan registry, by kind."
    );
    describe_counter!(
        "outline_ss_orphan_resume_hit_total",
        "Successful cross-transport session resumes, by parked-payload kind."
    );
    describe_counter!(
        "outline_ss_orphan_resume_miss_total",
        "Failed cross-transport session resumes, by reason."
    );
    describe_counter!(
        "outline_ss_orphan_evicted_total",
        "Orphan entries evicted before being resumed, by kind and reason."
    );
    describe_gauge!(
        "outline_ss_orphan_current",
        "Currently parked orphan sessions awaiting cross-transport resumption, by kind."
    );
}
