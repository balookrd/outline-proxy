use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};

const TCP_CONNECT_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const UDP_RELAY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const WS_SESSION_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 14400.0];
static ALLOCATOR_TRIM_RUNS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_TRIM_RELEASE_EVENTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_TRIM_ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_TRIM_LAST_RUN_SECONDS: AtomicI64 = AtomicI64::new(0);
static ALLOCATOR_TRIM_LAST_RSS_BEFORE_BYTES: AtomicI64 = AtomicI64::new(0);
static ALLOCATOR_TRIM_LAST_RSS_AFTER_BYTES: AtomicI64 = AtomicI64::new(0);
static ALLOCATOR_TRIM_LAST_RSS_RELEASED_BYTES: AtomicI64 = AtomicI64::new(0);
static ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_BEFORE_BYTES: AtomicI64 = AtomicI64::new(0);
static ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_AFTER_BYTES: AtomicI64 = AtomicI64::new(0);

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMemorySnapshot {
    pub resident_memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub heap_allocated_bytes: Option<u64>,
    pub heap_free_bytes: Option<u64>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn record_allocator_trim_run(
    before: Option<ProcessMemorySnapshot>,
    after: Option<ProcessMemorySnapshot>,
    release_event: bool,
) {
    ALLOCATOR_TRIM_RUNS_TOTAL.fetch_add(1, Ordering::Relaxed);
    if release_event {
        ALLOCATOR_TRIM_RELEASE_EVENTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    ALLOCATOR_TRIM_LAST_RUN_SECONDS.store(unix_timestamp_seconds(), Ordering::Relaxed);

    let rss_before = before.map(|snapshot| snapshot.resident_memory_bytes).unwrap_or(0);
    let rss_after = after.map(|snapshot| snapshot.resident_memory_bytes).unwrap_or(0);
    let released = rss_before.saturating_sub(rss_after);
    ALLOCATOR_TRIM_LAST_RSS_BEFORE_BYTES.store(rss_before as i64, Ordering::Relaxed);
    ALLOCATOR_TRIM_LAST_RSS_AFTER_BYTES.store(rss_after as i64, Ordering::Relaxed);
    ALLOCATOR_TRIM_LAST_RSS_RELEASED_BYTES.store(released as i64, Ordering::Relaxed);
    ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_BEFORE_BYTES.store(
        before
            .and_then(|snapshot| snapshot.heap_allocated_bytes)
            .unwrap_or(0) as i64,
        Ordering::Relaxed,
    );
    ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_AFTER_BYTES.store(
        after.and_then(|snapshot| snapshot.heap_allocated_bytes)
            .unwrap_or(0) as i64,
        Ordering::Relaxed,
    );
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn record_allocator_trim_error() {
    ALLOCATOR_TRIM_ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn process_memory_snapshot() -> Option<ProcessMemorySnapshot> {
    process_memory_snapshot_impl()
}

#[cfg(target_os = "linux")]
pub fn trim_allocator() -> Result<bool> {
    jemalloc_trim_allocator()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
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

pub struct Metrics {
    started_at: Instant,
    method: String,
    tcp_tls_enabled: bool,
    h3_enabled: bool,
    client_active_ttl_secs: u64,
    scrapes_total: AtomicU64,
    websocket_upgrades_total: CounterVec<WsLabels>,
    websocket_disconnects_total: CounterVec<WsDisconnectLabels>,
    active_websocket_sessions: GaugeVec<WsLabels>,
    websocket_session_duration_seconds: HistogramVec<WsLabels>,
    websocket_frames_total: CounterVec<WsDirectionLabels>,
    websocket_bytes_total: CounterVec<WsDirectionLabels>,
    client_sessions_total: CounterVec<UserProtocolTransportLabels>,
    client_last_seen_seconds: GaugeVec<UserLabels>,
    tcp_authenticated_sessions_total: CounterVec<UserProtocolLabels>,
    tcp_upstream_connects_total: CounterVec<UserProtocolResultLabels>,
    active_tcp_upstream_connections: GaugeVec<UserProtocolLabels>,
    tcp_upstream_connect_duration_seconds: HistogramVec<UserProtocolResultLabels>,
    tcp_payload_bytes_total: CounterVec<UserProtocolDirectionLabels>,
    client_payload_bytes_total: CounterVec<UserProtocolTransportDirectionLabels>,
    udp_requests_total: CounterVec<UserProtocolResultLabels>,
    udp_relay_duration_seconds: HistogramVec<UserProtocolResultLabels>,
    udp_payload_bytes_total: CounterVec<UserProtocolDirectionLabels>,
    udp_response_datagrams_total: CounterVec<UserProtocolLabels>,
}

impl Metrics {
    pub fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            method: config.method.as_str().to_owned(),
            tcp_tls_enabled: config.tcp_tls_enabled(),
            h3_enabled: config.h3_enabled(),
            client_active_ttl_secs: config.client_active_ttl_secs,
            scrapes_total: AtomicU64::new(0),
            websocket_upgrades_total: CounterVec::default(),
            websocket_disconnects_total: CounterVec::default(),
            active_websocket_sessions: GaugeVec::default(),
            websocket_session_duration_seconds: HistogramVec::new(WS_SESSION_BUCKETS),
            websocket_frames_total: CounterVec::default(),
            websocket_bytes_total: CounterVec::default(),
            client_sessions_total: CounterVec::default(),
            client_last_seen_seconds: GaugeVec::default(),
            tcp_authenticated_sessions_total: CounterVec::default(),
            tcp_upstream_connects_total: CounterVec::default(),
            active_tcp_upstream_connections: GaugeVec::default(),
            tcp_upstream_connect_duration_seconds: HistogramVec::new(TCP_CONNECT_BUCKETS),
            tcp_payload_bytes_total: CounterVec::default(),
            client_payload_bytes_total: CounterVec::default(),
            udp_requests_total: CounterVec::default(),
            udp_relay_duration_seconds: HistogramVec::new(UDP_RELAY_BUCKETS),
            udp_payload_bytes_total: CounterVec::default(),
            udp_response_datagrams_total: CounterVec::default(),
        })
    }

    pub fn open_websocket_session(
        self: &Arc<Self>,
        transport: Transport,
        protocol: Protocol,
    ) -> WebSocketSessionGuard {
        let labels = WsLabels { transport, protocol };
        self.websocket_upgrades_total.inc(labels.clone(), 1);
        self.active_websocket_sessions.inc(labels.clone(), 1);
        WebSocketSessionGuard {
            metrics: self.clone(),
            labels,
            started_at: Instant::now(),
            finished: false,
        }
    }

    pub fn record_websocket_binary_frame(
        &self,
        transport: Transport,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        let labels = WsDirectionLabels {
            transport,
            protocol,
            direction,
        };
        self.websocket_frames_total.inc(labels.clone(), 1);
        self.websocket_bytes_total.inc(labels, bytes as u64);
    }

    pub fn record_tcp_authenticated_session(&self, user: &str, protocol: Protocol) {
        self.record_client_session(user, protocol, Transport::Tcp);
        self.tcp_authenticated_sessions_total.inc(
            UserProtocolLabels::new(user, protocol),
            1,
        );
    }

    pub fn record_client_session(&self, user: &str, protocol: Protocol, transport: Transport) {
        self.client_sessions_total.inc(
            UserProtocolTransportLabels::new(user, protocol, transport),
            1,
        );
        self.record_client_last_seen(user);
    }

    pub fn record_client_last_seen(&self, user: &str) {
        self.client_last_seen_seconds.set(
            UserLabels::new(user),
            unix_timestamp_seconds(),
        );
    }

    pub fn record_tcp_connect(
        &self,
        user: &str,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let labels = UserProtocolResultLabels::new(user, protocol, result);
        self.tcp_upstream_connects_total.inc(labels.clone(), 1);
        self.tcp_upstream_connect_duration_seconds
            .observe(labels, duration_seconds);
    }

    pub fn open_tcp_upstream_connection(
        self: &Arc<Self>,
        user: &str,
        protocol: Protocol,
    ) -> TcpUpstreamGuard {
        let labels = UserProtocolLabels::new(user, protocol);
        self.active_tcp_upstream_connections.inc(labels.clone(), 1);
        TcpUpstreamGuard {
            metrics: self.clone(),
            labels,
            finished: false,
        }
    }

    pub fn record_tcp_payload_bytes(
        &self,
        user: &str,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        self.tcp_payload_bytes_total.inc(
            UserProtocolDirectionLabels::new(user, protocol, direction),
            bytes as u64,
        );
        self.client_payload_bytes_total.inc(
            UserProtocolTransportDirectionLabels::new(user, protocol, Transport::Tcp, direction),
            bytes as u64,
        );
    }

    pub fn record_udp_request(
        &self,
        user: &str,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let labels = UserProtocolResultLabels::new(user, protocol, result);
        self.udp_requests_total.inc(labels.clone(), 1);
        self.udp_relay_duration_seconds
            .observe(labels, duration_seconds);
    }

    pub fn record_udp_payload_bytes(
        &self,
        user: &str,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        self.udp_payload_bytes_total.inc(
            UserProtocolDirectionLabels::new(user, protocol, direction),
            bytes as u64,
        );
        self.client_payload_bytes_total.inc(
            UserProtocolTransportDirectionLabels::new(user, protocol, Transport::Udp, direction),
            bytes as u64,
        );
    }

    pub fn record_udp_response_datagrams(&self, user: &str, protocol: Protocol, count: usize) {
        self.udp_response_datagrams_total.inc(
            UserProtocolLabels::new(user, protocol),
            count as u64,
        );
    }

    pub fn render_prometheus(&self) -> String {
        self.scrapes_total.fetch_add(1, Ordering::Relaxed);
        let mut out = String::with_capacity(32 * 1024);

        write_help(&mut out, "outline_ss_build_info", "Build metadata for the running binary.");
        write_type(&mut out, "outline_ss_build_info", "gauge");
        writeln!(
            out,
            "outline_ss_build_info{{version=\"{}\"}} 1",
            escape_label_value(env!("CARGO_PKG_VERSION"))
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_config_info",
            "Static server configuration flags exposed as labels.",
        );
        write_type(&mut out, "outline_ss_config_info", "gauge");
        writeln!(
            out,
            "outline_ss_config_info{{method=\"{}\",tcp_tls=\"{}\",http3=\"{}\"}} 1",
            escape_label_value(&self.method),
            bool_label(self.tcp_tls_enabled),
            bool_label(self.h3_enabled)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_uptime_seconds",
            "Seconds since the process started.",
        );
        write_type(&mut out, "outline_ss_uptime_seconds", "gauge");
        writeln!(
            out,
            "outline_ss_uptime_seconds {:.3}",
            self.started_at.elapsed().as_secs_f64()
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_metrics_scrapes_total",
            "Number of successful Prometheus scrapes.",
        );
        write_type(&mut out, "outline_ss_metrics_scrapes_total", "counter");
        writeln!(
            out,
            "outline_ss_metrics_scrapes_total {}",
            self.scrapes_total.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_heap_metrics_supported",
            "Allocator heap metrics mode: 0=unsupported, 1=exact allocator metrics.",
        );
        write_type(&mut out, "outline_ss_allocator_heap_metrics_supported", "gauge");
        writeln!(
            out,
            "outline_ss_allocator_heap_metrics_supported {}",
            allocator_heap_metrics_support_level()
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_supported",
            "Whether periodic allocator trimming is supported on this build/runtime.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_supported", "gauge");
        writeln!(
            out,
            "outline_ss_allocator_trim_supported {}",
            if allocator_trim_supported() { 1 } else { 0 }
        )
        .ok();

        if let Some(snapshot) = process_memory_snapshot() {
            write_help(
                &mut out,
                "outline_ss_process_resident_memory_bytes",
                "Resident set size of the outline-ss-rust process.",
            );
            write_type(&mut out, "outline_ss_process_resident_memory_bytes", "gauge");
            writeln!(
                out,
                "outline_ss_process_resident_memory_bytes {}",
                snapshot.resident_memory_bytes
            )
            .ok();

            write_help(
                &mut out,
                "outline_ss_process_virtual_memory_bytes",
                "Virtual memory size of the outline-ss-rust process.",
            );
            write_type(&mut out, "outline_ss_process_virtual_memory_bytes", "gauge");
            writeln!(
                out,
                "outline_ss_process_virtual_memory_bytes {}",
                snapshot.virtual_memory_bytes
            )
            .ok();

            if let Some(heap_allocated_bytes) = snapshot.heap_allocated_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_heap_allocated_bytes",
                    "Bytes currently allocated from the glibc heap arenas.",
                );
                write_type(&mut out, "outline_ss_process_heap_allocated_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_heap_allocated_bytes {}",
                    heap_allocated_bytes
                )
                .ok();
            }

            if let Some(heap_free_bytes) = snapshot.heap_free_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_heap_free_bytes",
                    "Bytes currently free inside the glibc heap arenas.",
                );
                write_type(&mut out, "outline_ss_process_heap_free_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_heap_free_bytes {}",
                    heap_free_bytes
                )
                .ok();
            }
        }

        write_help(
            &mut out,
            "outline_ss_allocator_trim_runs_total",
            "Total allocator trim attempts.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_runs_total", "counter");
        writeln!(
            out,
            "outline_ss_allocator_trim_runs_total {}",
            ALLOCATOR_TRIM_RUNS_TOTAL.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_release_events_total",
            "Allocator trim attempts that observed memory release.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_release_events_total", "counter");
        writeln!(
            out,
            "outline_ss_allocator_trim_release_events_total {}",
            ALLOCATOR_TRIM_RELEASE_EVENTS_TOTAL.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_errors_total",
            "Allocator trim task errors.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_errors_total", "counter");
        writeln!(
            out,
            "outline_ss_allocator_trim_errors_total {}",
            ALLOCATOR_TRIM_ERRORS_TOTAL.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_run_seconds",
            "Unix timestamp of the most recent allocator trim attempt.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_last_run_seconds", "gauge");
        writeln!(
            out,
            "outline_ss_allocator_trim_last_run_seconds {}",
            ALLOCATOR_TRIM_LAST_RUN_SECONDS.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_rss_before_bytes",
            "RSS measured immediately before the most recent allocator trim.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_last_rss_before_bytes", "gauge");
        writeln!(
            out,
            "outline_ss_allocator_trim_last_rss_before_bytes {}",
            ALLOCATOR_TRIM_LAST_RSS_BEFORE_BYTES.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_rss_after_bytes",
            "RSS measured immediately after the most recent allocator trim.",
        );
        write_type(&mut out, "outline_ss_allocator_trim_last_rss_after_bytes", "gauge");
        writeln!(
            out,
            "outline_ss_allocator_trim_last_rss_after_bytes {}",
            ALLOCATOR_TRIM_LAST_RSS_AFTER_BYTES.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_rss_released_bytes",
            "RSS delta released by the most recent allocator trim.",
        );
        write_type(
            &mut out,
            "outline_ss_allocator_trim_last_rss_released_bytes",
            "gauge",
        );
        writeln!(
            out,
            "outline_ss_allocator_trim_last_rss_released_bytes {}",
            ALLOCATOR_TRIM_LAST_RSS_RELEASED_BYTES.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_heap_allocated_before_bytes",
            "Heap-allocated bytes measured before the most recent allocator trim.",
        );
        write_type(
            &mut out,
            "outline_ss_allocator_trim_last_heap_allocated_before_bytes",
            "gauge",
        );
        writeln!(
            out,
            "outline_ss_allocator_trim_last_heap_allocated_before_bytes {}",
            ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_BEFORE_BYTES.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_allocator_trim_last_heap_allocated_after_bytes",
            "Heap-allocated bytes measured after the most recent allocator trim.",
        );
        write_type(
            &mut out,
            "outline_ss_allocator_trim_last_heap_allocated_after_bytes",
            "gauge",
        );
        writeln!(
            out,
            "outline_ss_allocator_trim_last_heap_allocated_after_bytes {}",
            ALLOCATOR_TRIM_LAST_HEAP_ALLOCATED_AFTER_BYTES.load(Ordering::Relaxed)
        )
        .ok();

        render_counter_family(
            &mut out,
            "outline_ss_websocket_upgrades_total",
            "Total accepted websocket upgrades.",
            &self.websocket_upgrades_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_websocket_disconnects_total",
            "Websocket session completions grouped by outcome.",
            &self.websocket_disconnects_total,
        );
        render_gauge_family(
            &mut out,
            "outline_ss_active_websocket_sessions",
            "Currently active websocket sessions.",
            &self.active_websocket_sessions,
        );
        render_histogram_family(
            &mut out,
            "outline_ss_websocket_session_duration_seconds",
            "Wall-clock websocket session duration.",
            &self.websocket_session_duration_seconds,
        );
        render_counter_family(
            &mut out,
            "outline_ss_websocket_frames_total",
            "Binary websocket frames transferred.",
            &self.websocket_frames_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_websocket_bytes_total",
            "Encrypted websocket payload bytes transferred.",
            &self.websocket_bytes_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_client_sessions_total",
            "Authenticated client sessions by user, transport and protocol.",
            &self.client_sessions_total,
        );
        render_gauge_family(
            &mut out,
            "outline_ss_client_last_seen_seconds",
            "Unix timestamp of the most recent successful client activity by user.",
            &self.client_last_seen_seconds,
        );
        render_gauge_snapshots(
            &mut out,
            "outline_ss_client_active",
            "Client active state by user using the configured TTL.",
            client_active_snapshots(
                &self.client_last_seen_seconds,
                self.client_active_ttl_secs,
            ),
        );
        render_gauge_snapshots(
            &mut out,
            "outline_ss_client_up",
            "Alias of outline_ss_client_active for online-state dashboards.",
            client_active_snapshots(
                &self.client_last_seen_seconds,
                self.client_active_ttl_secs,
            ),
        );
        render_counter_family(
            &mut out,
            "outline_ss_tcp_authenticated_sessions_total",
            "Authenticated TCP relay sessions by user and client protocol.",
            &self.tcp_authenticated_sessions_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_tcp_upstream_connects_total",
            "TCP upstream connect attempts by result.",
            &self.tcp_upstream_connects_total,
        );
        render_gauge_family(
            &mut out,
            "outline_ss_active_tcp_upstream_connections",
            "Currently active outbound TCP connections.",
            &self.active_tcp_upstream_connections,
        );
        render_histogram_family(
            &mut out,
            "outline_ss_tcp_upstream_connect_duration_seconds",
            "TCP upstream connect latency.",
            &self.tcp_upstream_connect_duration_seconds,
        );
        render_counter_family(
            &mut out,
            "outline_ss_tcp_payload_bytes_total",
            "Plain TCP payload bytes relayed after Shadowsocks decryption.",
            &self.tcp_payload_bytes_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_client_payload_bytes_total",
            "Plain payload bytes relayed for each client across TCP and UDP.",
            &self.client_payload_bytes_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_udp_requests_total",
            "UDP relay requests by result.",
            &self.udp_requests_total,
        );
        render_histogram_family(
            &mut out,
            "outline_ss_udp_relay_duration_seconds",
            "End-to-end UDP request handling duration.",
            &self.udp_relay_duration_seconds,
        );
        render_counter_family(
            &mut out,
            "outline_ss_udp_payload_bytes_total",
            "Plain UDP payload bytes relayed after Shadowsocks decryption.",
            &self.udp_payload_bytes_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_udp_response_datagrams_total",
            "UDP response datagrams sent back to the client.",
            &self.udp_response_datagrams_total,
        );

        out
    }
}

pub struct WebSocketSessionGuard {
    metrics: Arc<Metrics>,
    labels: WsLabels,
    started_at: Instant,
    finished: bool,
}

impl WebSocketSessionGuard {
    pub fn finish(mut self, reason: DisconnectReason) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.metrics
            .active_websocket_sessions
            .inc(self.labels.clone(), -1);
        self.metrics.websocket_disconnects_total.inc(
            WsDisconnectLabels {
                transport: self.labels.transport,
                protocol: self.labels.protocol,
                reason,
            },
            1,
        );
        self.metrics
            .websocket_session_duration_seconds
            .observe(self.labels.clone(), self.started_at.elapsed().as_secs_f64());
    }
}

impl Drop for WebSocketSessionGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics
                .active_websocket_sessions
                .inc(self.labels.clone(), -1);
            self.metrics.websocket_disconnects_total.inc(
                WsDisconnectLabels {
                    transport: self.labels.transport,
                    protocol: self.labels.protocol,
                    reason: DisconnectReason::Error,
                },
                1,
            );
            self.metrics
                .websocket_session_duration_seconds
                .observe(self.labels.clone(), self.started_at.elapsed().as_secs_f64());
            self.finished = true;
        }
    }
}

pub struct TcpUpstreamGuard {
    metrics: Arc<Metrics>,
    labels: UserProtocolLabels,
    finished: bool,
}

impl TcpUpstreamGuard {
    pub fn finish(mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.metrics
            .active_tcp_upstream_connections
            .inc(self.labels.clone(), -1);
    }
}

impl Drop for TcpUpstreamGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics
                .active_tcp_upstream_connections
                .inc(self.labels.clone(), -1);
            self.finished = true;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct WsLabels {
    transport: Transport,
    protocol: Protocol,
}

impl PrometheusLabels for WsLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("transport", self.transport.as_str().to_owned()),
            ("protocol", self.protocol.as_str().to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct WsDisconnectLabels {
    transport: Transport,
    protocol: Protocol,
    reason: DisconnectReason,
}

impl PrometheusLabels for WsDisconnectLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("transport", self.transport.as_str().to_owned()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("reason", self.reason.as_str().to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct WsDirectionLabels {
    transport: Transport,
    protocol: Protocol,
    direction: &'static str,
}

impl PrometheusLabels for WsDirectionLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("transport", self.transport.as_str().to_owned()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("direction", self.direction.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserProtocolLabels {
    user: String,
    protocol: Protocol,
}

impl UserProtocolLabels {
    fn new(user: &str, protocol: Protocol) -> Self {
        Self {
            user: user.to_owned(),
            protocol,
        }
    }
}

impl PrometheusLabels for UserProtocolLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.clone()),
            ("protocol", self.protocol.as_str().to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserLabels {
    user: String,
}

impl UserLabels {
    fn new(user: &str) -> Self {
        Self {
            user: user.to_owned(),
        }
    }
}

impl PrometheusLabels for UserLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![("user", self.user.clone())]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserProtocolTransportLabels {
    user: String,
    protocol: Protocol,
    transport: Transport,
}

impl UserProtocolTransportLabels {
    fn new(user: &str, protocol: Protocol, transport: Transport) -> Self {
        Self {
            user: user.to_owned(),
            protocol,
            transport,
        }
    }
}

impl PrometheusLabels for UserProtocolTransportLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.clone()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("transport", self.transport.as_str().to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserProtocolResultLabels {
    user: String,
    protocol: Protocol,
    result: &'static str,
}

impl UserProtocolResultLabels {
    fn new(user: &str, protocol: Protocol, result: &'static str) -> Self {
        Self {
            user: user.to_owned(),
            protocol,
            result,
        }
    }
}

impl PrometheusLabels for UserProtocolResultLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.clone()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("result", self.result.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserProtocolDirectionLabels {
    user: String,
    protocol: Protocol,
    direction: &'static str,
}

impl UserProtocolDirectionLabels {
    fn new(user: &str, protocol: Protocol, direction: &'static str) -> Self {
        Self {
            user: user.to_owned(),
            protocol,
            direction,
        }
    }
}

impl PrometheusLabels for UserProtocolDirectionLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.clone()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("direction", self.direction.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct UserProtocolTransportDirectionLabels {
    user: String,
    protocol: Protocol,
    transport: Transport,
    direction: &'static str,
}

impl UserProtocolTransportDirectionLabels {
    fn new(user: &str, protocol: Protocol, transport: Transport, direction: &'static str) -> Self {
        Self {
            user: user.to_owned(),
            protocol,
            transport,
            direction,
        }
    }
}

impl PrometheusLabels for UserProtocolTransportDirectionLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.clone()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("transport", self.transport.as_str().to_owned()),
            ("direction", self.direction.to_owned()),
        ]
    }
}

trait PrometheusLabels {
    fn labels(&self) -> Vec<(&'static str, String)>;
}

struct CounterVec<L> {
    values: RwLock<BTreeMap<L, Arc<AtomicU64>>>,
}

impl<L> Default for CounterVec<L> {
    fn default() -> Self {
        Self {
            values: RwLock::new(BTreeMap::new()),
        }
    }
}

impl<L> CounterVec<L>
where
    L: Clone + Ord,
{
    fn inc(&self, labels: L, value: u64) {
        {
            let values = self.values.read().expect("counter vec poisoned");
            if let Some(cell) = values.get(&labels) {
                cell.fetch_add(value, Ordering::Relaxed);
                return;
            }
        }
        let cell = {
            let mut values = self.values.write().expect("counter vec poisoned");
            values
                .entry(labels)
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .clone()
        };
        cell.fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(L, u64)> {
        self.values
            .read()
            .expect("counter vec poisoned")
            .iter()
            .map(|(labels, value)| (labels.clone(), value.load(Ordering::Relaxed)))
            .collect()
    }
}

struct GaugeVec<L> {
    values: RwLock<BTreeMap<L, Arc<AtomicI64>>>,
}

impl<L> Default for GaugeVec<L> {
    fn default() -> Self {
        Self {
            values: RwLock::new(BTreeMap::new()),
        }
    }
}

impl<L> GaugeVec<L>
where
    L: Clone + Ord,
{
    fn set(&self, labels: L, value: i64) {
        {
            let values = self.values.read().expect("gauge vec poisoned");
            if let Some(cell) = values.get(&labels) {
                cell.store(value, Ordering::Relaxed);
                return;
            }
        }
        let cell = {
            let mut values = self.values.write().expect("gauge vec poisoned");
            values
                .entry(labels)
                .or_insert_with(|| Arc::new(AtomicI64::new(0)))
                .clone()
        };
        cell.store(value, Ordering::Relaxed);
    }

    fn inc(&self, labels: L, value: i64) {
        {
            let values = self.values.read().expect("gauge vec poisoned");
            if let Some(cell) = values.get(&labels) {
                cell.fetch_add(value, Ordering::Relaxed);
                return;
            }
        }
        let cell = {
            let mut values = self.values.write().expect("gauge vec poisoned");
            values
                .entry(labels)
                .or_insert_with(|| Arc::new(AtomicI64::new(0)))
                .clone()
        };
        cell.fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(L, i64)> {
        self.values
            .read()
            .expect("gauge vec poisoned")
            .iter()
            .map(|(labels, value)| (labels.clone(), value.load(Ordering::Relaxed)))
            .collect()
    }
}

struct HistogramVec<L> {
    buckets: &'static [f64],
    values: RwLock<BTreeMap<L, Arc<Mutex<HistogramState>>>>,
}

impl<L> HistogramVec<L>
where
    L: Clone + Ord,
{
    fn new(buckets: &'static [f64]) -> Self {
        Self {
            buckets,
            values: RwLock::new(BTreeMap::new()),
        }
    }

    fn observe(&self, labels: L, value: f64) {
        {
            let values = self.values.read().expect("histogram vec poisoned");
            if let Some(state) = values.get(&labels) {
                state.lock().expect("histogram state poisoned").observe(self.buckets, value);
                return;
            }
        }
        let state = {
            let mut values = self.values.write().expect("histogram vec poisoned");
            values
                .entry(labels)
                .or_insert_with(|| Arc::new(Mutex::new(HistogramState::new(self.buckets))))
                .clone()
        };
        state.lock().expect("histogram state poisoned").observe(self.buckets, value);
    }

    fn snapshot(&self) -> Vec<(L, HistogramSnapshot)> {
        self.values
            .read()
            .expect("histogram vec poisoned")
            .iter()
            .map(|(labels, state)| {
                let snapshot = state
                    .lock()
                    .expect("histogram state poisoned")
                    .snapshot(self.buckets);
                (labels.clone(), snapshot)
            })
            .collect()
    }
}

struct HistogramState {
    bucket_counts: Vec<u64>,
    count: u64,
    sum: f64,
}

impl HistogramState {
    fn new(buckets: &[f64]) -> Self {
        Self {
            bucket_counts: vec![0; buckets.len()],
            count: 0,
            sum: 0.0,
        }
    }

    fn observe(&mut self, buckets: &[f64], value: f64) {
        self.count += 1;
        self.sum += value;
        for (index, upper_bound) in buckets.iter().enumerate() {
            if value <= *upper_bound {
                self.bucket_counts[index] += 1;
                return;
            }
        }
    }

    fn snapshot(&self, buckets: &[f64]) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: buckets.to_vec(),
            bucket_counts: self.bucket_counts.clone(),
            count: self.count,
            sum: self.sum,
        }
    }
}

struct HistogramSnapshot {
    buckets: Vec<f64>,
    bucket_counts: Vec<u64>,
    count: u64,
    sum: f64,
}

fn render_counter_family<L>(
    out: &mut String,
    name: &str,
    help: &str,
    metric: &CounterVec<L>,
) where
    L: PrometheusLabels + Clone + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "counter");
    for (labels, value) in metric.snapshot() {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_gauge_family<L>(
    out: &mut String,
    name: &str,
    help: &str,
    metric: &GaugeVec<L>,
) where
    L: PrometheusLabels + Clone + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "gauge");
    for (labels, value) in metric.snapshot() {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_gauge_snapshots<L>(out: &mut String, name: &str, help: &str, snapshots: Vec<(L, i64)>)
where
    L: PrometheusLabels + Clone + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "gauge");
    for (labels, value) in snapshots {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_histogram_family<L>(
    out: &mut String,
    name: &str,
    help: &str,
    metric: &HistogramVec<L>,
) where
    L: PrometheusLabels + Clone + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "histogram");
    for (labels, snapshot) in metric.snapshot() {
        let base_labels = labels.labels();
        let mut cumulative = 0_u64;
        for (idx, upper_bound) in snapshot.buckets.iter().enumerate() {
            cumulative += snapshot.bucket_counts[idx];
            let mut bucket_labels = base_labels.clone();
            bucket_labels.push(("le", upper_bound.to_string()));
            write_metric_line(out, &format!("{name}_bucket"), &bucket_labels, cumulative.to_string());
        }
        let mut inf_labels = base_labels.clone();
        inf_labels.push(("le", "+Inf".to_owned()));
        write_metric_line(out, &format!("{name}_bucket"), &inf_labels, snapshot.count.to_string());
        write_metric_line(out, &format!("{name}_sum"), &base_labels, format!("{:.6}", snapshot.sum));
        write_metric_line(out, &format!("{name}_count"), &base_labels, snapshot.count.to_string());
    }
}

fn write_help(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
}

fn write_type(out: &mut String, name: &str, metric_type: &str) {
    writeln!(out, "# TYPE {name} {metric_type}").ok();
}

fn write_metric_line(out: &mut String, name: &str, labels: &[(&'static str, String)], value: String) {
    if labels.is_empty() {
        writeln!(out, "{name} {value}").ok();
        return;
    }

    out.push_str(name);
    out.push('{');
    for (index, (key, label_value)) in labels.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(key);
        out.push_str("=\"");
        out.push_str(&escape_label_value(label_value));
        out.push('"');
    }
    out.push('}');
    out.push(' ');
    out.push_str(&value);
    out.push('\n');
}

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn unix_timestamp_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn client_active_snapshots(
    last_seen: &GaugeVec<UserLabels>,
    ttl_secs: u64,
) -> Vec<(UserLabels, i64)> {
    let now = unix_timestamp_seconds();
    last_seen
        .snapshot()
        .into_iter()
        .map(|(labels, seen_at)| {
            let active = if seen_at > 0 && now.saturating_sub(seen_at) <= ttl_secs as i64 {
                1
            } else {
                0
            };
            (labels, active)
        })
        .collect()
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

const fn allocator_heap_metrics_support_level() -> i64 {
    if cfg!(target_os = "linux") {
        1
    } else {
        0
    }
}

const fn allocator_trim_supported() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
fn process_memory_snapshot_impl() -> Option<ProcessMemorySnapshot> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let resident_memory_bytes = proc_status_value_bytes(&status, "VmRSS:")?;
    let virtual_memory_bytes = proc_status_value_bytes(&status, "VmSize:")?;
    let (heap_allocated_bytes, heap_free_bytes) = allocator_heap_snapshot();
    Some(ProcessMemorySnapshot {
        resident_memory_bytes,
        virtual_memory_bytes,
        heap_allocated_bytes,
        heap_free_bytes,
    })
}

#[cfg(not(target_os = "linux"))]
fn process_memory_snapshot_impl() -> Option<ProcessMemorySnapshot> {
    None
}

#[cfg(target_os = "linux")]
fn proc_status_value_bytes(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        let kib = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kib * 1024)
    })
}

#[cfg(target_os = "linux")]
fn allocator_heap_snapshot() -> (Option<u64>, Option<u64>) {
    jemalloc_heap_snapshot().unwrap_or_else(|_| procfs_heap_snapshot())
}

#[cfg(target_os = "linux")]
fn procfs_heap_snapshot() -> (Option<u64>, Option<u64>) {
    let smaps = match std::fs::read_to_string("/proc/self/smaps") {
        Ok(smaps) => smaps,
        Err(_) => return (None, None),
    };

    let mut heap_size_kib = 0_u64;
    let mut heap_rss_kib = 0_u64;
    let mut in_heap_region = false;

    for line in smaps.lines() {
        if is_smaps_mapping_header(line) {
            in_heap_region = line.ends_with("[heap]");
            continue;
        }
        if !in_heap_region {
            continue;
        }

        if let Some(value_kib) = smaps_value_kib(line, "Size:") {
            heap_size_kib = heap_size_kib.saturating_add(value_kib);
        } else if let Some(value_kib) = smaps_value_kib(line, "Rss:") {
            heap_rss_kib = heap_rss_kib.saturating_add(value_kib);
        }
    }

    if heap_size_kib == 0 && heap_rss_kib == 0 {
        return (None, None);
    }

    let heap_mapped_bytes = heap_size_kib.saturating_mul(1024);
    let heap_resident_bytes = heap_rss_kib.saturating_mul(1024);
    (
        Some(heap_resident_bytes),
        Some(heap_mapped_bytes.saturating_sub(heap_resident_bytes)),
    )
}

#[cfg(target_os = "linux")]
fn jemalloc_heap_snapshot() -> Result<(Option<u64>, Option<u64>)> {
    let epoch = tikv_jemalloc_ctl::epoch::mib().context("failed to create jemalloc epoch MIB")?;
    epoch.advance().context("failed to advance jemalloc epoch")?;

    let allocated = tikv_jemalloc_ctl::stats::allocated::mib()
        .context("failed to create jemalloc allocated MIB")?
        .read()
        .context("failed to read jemalloc allocated stats")?;
    let active = tikv_jemalloc_ctl::stats::active::mib()
        .context("failed to create jemalloc active MIB")?
        .read()
        .context("failed to read jemalloc active stats")?;
    let allocated = allocated as u64;
    let active = active as u64;

    Ok((
        Some(allocated),
        Some(active.saturating_sub(allocated)),
    ))
}

#[cfg(target_os = "linux")]
fn jemalloc_trim_allocator() -> Result<bool> {
    let background_threads_enabled = tikv_jemalloc_ctl::background_thread::read()
        .context("failed to read jemalloc background_thread state")?;
    if !background_threads_enabled {
        tikv_jemalloc_ctl::background_thread::write(true)
            .context("failed to enable jemalloc background_thread")?;
    }

    tikv_jemalloc_ctl::epoch::advance().context("failed to advance jemalloc epoch")?;
    Ok(false)
}

#[cfg(target_os = "linux")]
fn is_smaps_mapping_header(line: &str) -> bool {
    line.split_once('-')
        .and_then(|(start, _)| start.chars().next())
        .is_some_and(|ch| ch.is_ascii_hexdigit())
}

#[cfg(target_os = "linux")]
fn smaps_value_kib(line: &str, key: &str) -> Option<u64> {
    let rest = line.strip_prefix(key)?.trim();
    let kib = rest.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(kib)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::{DisconnectReason, Metrics, Protocol, Transport, record_allocator_trim_run};

    #[test]
    fn renders_prometheus_metrics() {
        let config = Config {
            listen: "127.0.0.1:3000".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
            metrics_path: "/metrics".to_owned(),
            client_active_ttl_secs: 300,
            memory_trim_interval_secs: 60,
            ws_path_tcp: "/tcp".to_owned(),
            ws_path_udp: "/udp".to_owned(),
            public_host: None,
            public_scheme: "wss".to_owned(),
            access_key_url_base: None,
            print_access_keys: false,
            password: Some("secret".to_owned()),
            fwmark: None,
            users: vec![],
            method: crate::config::CipherKind::Chacha20IetfPoly1305,
        };
        let metrics = Metrics::new(&config);
        let session = metrics.open_websocket_session(Transport::Tcp, Protocol::Http2);
        metrics.record_websocket_binary_frame(Transport::Tcp, Protocol::Http2, "in", 123);
        metrics.record_tcp_authenticated_session("default", Protocol::Http2);
        metrics.record_tcp_connect("default", Protocol::Http2, "success", 0.015);
        metrics.record_tcp_payload_bytes("default", Protocol::Http2, "client_to_target", 32);
        metrics.record_udp_payload_bytes("default", Protocol::Http2, "target_to_client", 16);
        metrics.record_client_session("default", Protocol::Http2, Transport::Udp);
        record_allocator_trim_run(None, None, false);
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
        assert!(rendered.contains("outline_ss_allocator_trim_runs_total"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("outline_ss_process_resident_memory_bytes"));
        assert!(rendered.contains("transport=\"udp\",direction=\"target_to_client\""));
    }
}
