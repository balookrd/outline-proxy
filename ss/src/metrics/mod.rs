mod process_memory;

pub use process_memory::ProcessMemorySnapshot;
use process_memory::{append_to_prometheus_output, sample as sample_process_memory};

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;
use metrics::{
    counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
    with_local_recorder,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use parking_lot::RwLock;
use tokio::time::{Duration, MissedTickBehavior};

const TCP_CONNECT_BUCKETS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const UDP_RELAY_BUCKETS: &[f64] =
    &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const WS_SESSION_BUCKETS: &[f64] =
    &[1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 14400.0];
const PROCESS_MEMORY_SAMPLING_INTERVAL_SECS: u64 = 15;

// ── Public label enums ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
    Socket,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
            Self::Socket => "socket",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum DisconnectReason {
    Normal,
    ClientDisconnect,
    Error,
}

impl DisconnectReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ClientDisconnect => "client_disconnect",
            Self::Error => "error",
        }
    }
}

// ── Metrics ────────────────────────────────────────────────────────────────────

pub struct Metrics {
    started_at: Instant,
    method: String,
    tcp_tls_enabled: bool,
    h3_enabled: bool,
    client_active_ttl_secs: u64,
    /// Cached /proc snapshot; updated every 15 s on Linux.
    process_memory_snapshot: RwLock<Option<ProcessMemorySnapshot>>,
    /// Tracks last-seen timestamps so we can compute `client_active` / `client_up`
    /// at render time without reading back from the Prometheus recorder.
    client_last_seen: RwLock<HashMap<Arc<str>, i64>>,
    recorder: PrometheusRecorder,
    handle: PrometheusHandle,
}

impl Metrics {
    pub fn new(config: &Config) -> Arc<Self> {
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
            .build_recorder();

        let handle = recorder.handle();
        let metrics = Arc::new(Self {
            started_at: Instant::now(),
            method: config.method.as_str().to_owned(),
            tcp_tls_enabled: config.tcp_tls_enabled(),
            h3_enabled: config.h3_enabled(),
            client_active_ttl_secs: config.client_active_ttl_secs,
            process_memory_snapshot: RwLock::new(sample_process_memory()),
            client_last_seen: RwLock::new(HashMap::new()),
            recorder,
            handle,
        });

        with_local_recorder(&metrics.recorder, || {
            Self::register_descriptions();
            // Static info gauges — set once; value is always 1.
            gauge!("outline_ss_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
            gauge!(
                "outline_ss_config_info",
                "method"   => metrics.method.clone(),
                "tcp_tls"  => bool_label(metrics.tcp_tls_enabled),
                "http3"    => bool_label(metrics.h3_enabled)
            )
            .set(1.0);
        });

        metrics
    }

    fn register_descriptions() {
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
        describe_counter!(
            "outline_ss_websocket_upgrades_total",
            "Total accepted websocket upgrades."
        );
        describe_counter!(
            "outline_ss_websocket_disconnects_total",
            "Websocket session completions grouped by outcome."
        );
        describe_gauge!(
            "outline_ss_active_websocket_sessions",
            "Currently active websocket sessions."
        );
        describe_histogram!(
            "outline_ss_websocket_session_duration_seconds",
            "Wall-clock websocket session duration."
        );
        describe_counter!("outline_ss_websocket_frames_total", "Binary websocket frames transferred.");
        describe_counter!(
            "outline_ss_websocket_bytes_total",
            "Encrypted websocket payload bytes transferred."
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
        describe_counter!(
            "outline_ss_client_payload_bytes_total",
            "Plain payload bytes relayed for each client across TCP and UDP."
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
    }

    // ── Session guards ─────────────────────────────────────────────────────────

    pub fn open_websocket_session(
        self: &Arc<Self>,
        transport: Transport,
        protocol: Protocol,
    ) -> WebSocketSessionGuard {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_websocket_upgrades_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
            )
            .increment(1);
            gauge!(
                "outline_ss_active_websocket_sessions",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
            )
            .increment(1.0);
        });
        WebSocketSessionGuard {
            metrics: self.clone(),
            transport,
            protocol,
            started_at: Instant::now(),
            finished: false,
        }
    }

    pub fn open_tcp_upstream_connection(
        self: &Arc<Self>,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
    ) -> TcpUpstreamGuard {
        let user_id: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            gauge!(
                "outline_ss_active_tcp_upstream_connections",
                "user"     => Arc::clone(&user_id),
                "protocol" => protocol.as_str()
            )
            .increment(1.0);
        });
        TcpUpstreamGuard { metrics: self.clone(), user_id, protocol, finished: false }
    }

    // ── Recording methods ──────────────────────────────────────────────────────

    pub fn start_process_memory_sampler(self: &Arc<Self>) {
        let metrics = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(PROCESS_MEMORY_SAMPLING_INTERVAL_SECS));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                metrics.refresh_process_memory_snapshot().await;
            }
        });
    }

    pub fn record_websocket_binary_frame(
        &self,
        transport: Transport,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_websocket_frames_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str(),
                "direction" => direction
            )
            .increment(1);
            counter!(
                "outline_ss_websocket_bytes_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str(),
                "direction" => direction
            )
            .increment(bytes as u64);
        });
    }

    pub fn record_tcp_authenticated_session(&self, user: impl Into<Arc<str>>, protocol: Protocol) {
        let user: Arc<str> = user.into();
        self.record_client_session(Arc::clone(&user), protocol, Transport::Tcp);
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tcp_authenticated_sessions_total",
                "user"     => user,
                "protocol" => protocol.as_str()
            )
            .increment(1);
        });
    }

    pub fn record_client_session(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        transport: Transport,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_client_sessions_total",
                "user"      => Arc::clone(&user),
                "protocol"  => protocol.as_str(),
                "transport" => transport.as_str()
            )
            .increment(1);
        });
        self.record_client_last_seen(user);
    }

    pub fn record_client_last_seen(&self, user: impl Into<Arc<str>>) {
        let user: Arc<str> = user.into();
        let ts = unix_timestamp_seconds();
        *self.client_last_seen.write().entry(Arc::clone(&user)).or_insert(0) = ts;
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_client_last_seen_seconds", "user" => user).set(ts as f64);
        });
    }

    pub fn record_tcp_connect(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tcp_upstream_connects_total",
                "user"     => Arc::clone(&user),
                "protocol" => protocol.as_str(),
                "result"   => result
            )
            .increment(1);
            histogram!(
                "outline_ss_tcp_upstream_connect_duration_seconds",
                "user"     => user,
                "protocol" => protocol.as_str(),
                "result"   => result
            )
            .record(duration_seconds);
        });
    }

    pub fn record_tcp_payload_bytes(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tcp_payload_bytes_total",
                "user"      => Arc::clone(&user),
                "protocol"  => protocol.as_str(),
                "direction" => direction
            )
            .increment(bytes as u64);
            counter!(
                "outline_ss_client_payload_bytes_total",
                "user"      => user,
                "protocol"  => protocol.as_str(),
                "transport" => Transport::Tcp.as_str(),
                "direction" => direction
            )
            .increment(bytes as u64);
        });
    }

    pub fn record_udp_request(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_requests_total",
                "user"     => Arc::clone(&user),
                "protocol" => protocol.as_str(),
                "result"   => result
            )
            .increment(1);
            histogram!(
                "outline_ss_udp_relay_duration_seconds",
                "user"     => user,
                "protocol" => protocol.as_str(),
                "result"   => result
            )
            .record(duration_seconds);
        });
    }

    pub fn record_udp_payload_bytes(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_payload_bytes_total",
                "user"      => Arc::clone(&user),
                "protocol"  => protocol.as_str(),
                "direction" => direction
            )
            .increment(bytes as u64);
            counter!(
                "outline_ss_client_payload_bytes_total",
                "user"      => user,
                "protocol"  => protocol.as_str(),
                "transport" => Transport::Udp.as_str(),
                "direction" => direction
            )
            .increment(bytes as u64);
        });
    }

    pub fn record_udp_response_datagrams(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        count: usize,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_response_datagrams_total",
                "user"     => user,
                "protocol" => protocol.as_str()
            )
            .increment(count as u64);
        });
    }

    pub fn record_udp_relay_drop(
        &self,
        transport: Transport,
        protocol: Protocol,
        reason: &'static str,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_relay_drops_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str(),
                "reason"    => reason
            )
            .increment(1);
        });
    }

    pub fn record_udp_oversized_datagram_dropped(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_oversized_datagrams_dropped_total",
                "user"      => user,
                "protocol"  => protocol.as_str(),
                "direction" => direction
            )
            .increment(1);
        });
    }

    pub fn record_udp_nat_entry_created(&self) {
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_udp_nat_active_entries").increment(1.0);
            counter!("outline_ss_udp_nat_entries_created_total").increment(1);
        });
    }

    pub fn record_udp_nat_entries_evicted(&self, count: usize) {
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_udp_nat_active_entries").decrement(count as f64);
            counter!("outline_ss_udp_nat_entries_evicted_total").increment(count as u64);
        });
    }

    pub fn record_udp_nat_response_dropped(&self) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_udp_nat_responses_dropped_total").increment(1);
        });
    }

    // ── Rendering ──────────────────────────────────────────────────────────────

    pub fn render_prometheus(&self) -> String {
        // Snapshot client_last_seen before taking any other locks.
        let now = unix_timestamp_seconds();
        let ttl = self.client_active_ttl_secs as i64;
        let seen_snapshot: Vec<(Arc<str>, i64)> = self
            .client_last_seen
            .read()
            .iter()
            .map(|(k, v)| (Arc::clone(k), *v))
            .collect();

        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_metrics_scrapes_total").increment(1);
            gauge!("outline_ss_uptime_seconds").set(self.started_at.elapsed().as_secs_f64());
            // Compute and push client_active / client_up derived gauges.
            for (user, seen_at) in &seen_snapshot {
                let active =
                    if *seen_at > 0 && now.saturating_sub(*seen_at) <= ttl { 1.0 } else { 0.0 };
                gauge!("outline_ss_client_active", "user" => Arc::clone(user)).set(active);
                gauge!("outline_ss_client_up", "user" => Arc::clone(user)).set(active);
            }
        });

        let mut out = self.handle.render();

        // Append custom process-memory section (uses /proc on Linux; None elsewhere).
        if let Some(snapshot) = self.cached_process_memory_snapshot() {
            append_to_prometheus_output(&mut out, &snapshot);
        }

        out
    }

    fn cached_process_memory_snapshot(&self) -> Option<ProcessMemorySnapshot> {
        self.process_memory_snapshot.read().clone()
    }

    async fn refresh_process_memory_snapshot(self: &Arc<Self>) {
        #[cfg(target_os = "linux")]
        let snapshot = match tokio::task::spawn_blocking(sample_process_memory).await {
            Ok(snapshot) => snapshot,
            Err(_) => return,
        };

        #[cfg(not(target_os = "linux"))]
        let snapshot = sample_process_memory();

        *self.process_memory_snapshot.write() = snapshot;
    }
}

// ── RAII session guards ────────────────────────────────────────────────────────

pub struct WebSocketSessionGuard {
    metrics: Arc<Metrics>,
    transport: Transport,
    protocol: Protocol,
    started_at: Instant,
    finished: bool,
}

impl WebSocketSessionGuard {
    pub fn finish(mut self, reason: DisconnectReason) {
        if !self.finished {
            self.close(reason);
        }
    }

    fn close(&mut self, reason: DisconnectReason) {
        self.finished = true;
        let duration = self.started_at.elapsed().as_secs_f64();
        let transport = self.transport;
        let protocol = self.protocol;
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_websocket_sessions",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
            )
            .decrement(1.0);
            counter!(
                "outline_ss_websocket_disconnects_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str(),
                "reason"    => reason.as_str()
            )
            .increment(1);
            histogram!(
                "outline_ss_websocket_session_duration_seconds",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
            )
            .record(duration);
        });
    }
}

impl Drop for WebSocketSessionGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.close(DisconnectReason::Error);
        }
    }
}

pub struct TcpUpstreamGuard {
    metrics: Arc<Metrics>,
    user_id: Arc<str>,
    protocol: Protocol,
    finished: bool,
}

impl TcpUpstreamGuard {
    pub fn finish(mut self) {
        if !self.finished {
            self.close();
        }
    }

    fn close(&mut self) {
        self.finished = true;
        let user = Arc::clone(&self.user_id);
        let protocol = self.protocol;
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_tcp_upstream_connections",
                "user"     => user,
                "protocol" => protocol.as_str()
            )
            .decrement(1.0);
        });
    }
}

impl Drop for TcpUpstreamGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.close();
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::{DisconnectReason, Metrics, Protocol, Transport};

    fn test_config() -> Config {
        Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
            metrics_path: "/metrics".to_owned(),
            prefer_ipv4_upstream: false,
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".to_owned(),
            ws_path_udp: "/udp".to_owned(),
            http_root_auth: false,
            http_root_realm: "Authorization required".to_owned(),
            password: Some("secret".to_owned()),
            fwmark: None,
            users: vec![],
            method: crate::config::CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
            udp_max_concurrent_relay_tasks:
                crate::config::default_udp_max_concurrent_relay_tasks(),
        }
    }

    #[test]
    fn renders_prometheus_metrics() {
        let metrics = Metrics::new(&test_config());
        let session = metrics.open_websocket_session(Transport::Tcp, Protocol::Http2);
        metrics.record_websocket_binary_frame(Transport::Tcp, Protocol::Http2, "in", 123);
        metrics.record_tcp_authenticated_session("default", Protocol::Http2);
        metrics.record_tcp_connect("default", Protocol::Http2, "success", 0.015);
        metrics.record_tcp_payload_bytes("default", Protocol::Http2, "client_to_target", 32);
        metrics.record_udp_payload_bytes("default", Protocol::Http2, "target_to_client", 16);
        metrics.record_udp_relay_drop(Transport::Udp, Protocol::Http2, "concurrency_limit");
        metrics.record_client_session("default", Protocol::Http2, Transport::Udp);
        session.finish(DisconnectReason::Normal);

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("outline_ss_websocket_upgrades_total"));
        assert!(rendered.contains("transport=\"tcp\",protocol=\"http2\""));
        assert!(rendered.contains("user=\"default\",protocol=\"http2\""));
        assert!(rendered.contains("outline_ss_tcp_upstream_connect_duration_seconds_bucket"));
        assert!(rendered.contains("outline_ss_client_payload_bytes_total"));
        assert!(rendered.contains("outline_ss_client_sessions_total"));
        assert!(rendered.contains("outline_ss_client_last_seen_seconds"));
        assert!(rendered.contains("outline_ss_client_active"));
        assert!(rendered.contains("outline_ss_client_up"));
        assert!(rendered.contains("outline_ss_udp_relay_drops_total"));
        assert!(rendered.contains(
            "outline_ss_udp_relay_drops_total{transport=\"udp\",protocol=\"http2\",reason=\"concurrency_limit\"} 1"
        ));
        assert!(rendered.contains("transport=\"udp\",direction=\"target_to_client\""));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_resident_memory_bytes"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_threads"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_virtual_anon_private_bytes"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_virtual_file_private_bytes"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_virtual_top_mapping_size_bytes"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_virtual_top_mapping_gap_bytes"));
    }
}
