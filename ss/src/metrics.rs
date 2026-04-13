use std::{
    collections::HashMap,
    fmt::Write,
    hash::Hash,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;
use tokio::time::{Duration, MissedTickBehavior};

const TCP_CONNECT_BUCKETS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const UDP_RELAY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const WS_SESSION_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 14400.0];
const PROCESS_MEMORY_SAMPLING_INTERVAL_SECS: u64 = 15;

#[derive(Clone, Debug, Default)]
pub struct ProcessMemorySnapshot {
    pub resident_memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub thread_count: Option<u64>,
    pub virtual_stack_bytes: Option<u64>,
    pub virtual_anon_private_bytes: Option<u64>,
    pub virtual_anon_shared_bytes: Option<u64>,
    pub virtual_file_private_bytes: Option<u64>,
    pub virtual_file_shared_bytes: Option<u64>,
    pub virtual_special_bytes: Option<u64>,
    pub top_virtual_mappings: Vec<TopVirtualMapping>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopVirtualMapping {
    pub kind: &'static str,
    pub perms: String,
    pub name: String,
    pub size_bytes: u64,
    pub rss_bytes: u64,
}

pub fn process_memory_snapshot() -> Option<ProcessMemorySnapshot> {
    process_memory_snapshot_impl()
}

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

pub struct Metrics {
    started_at: Instant,
    method: String,
    tcp_tls_enabled: bool,
    h3_enabled: bool,
    client_active_ttl_secs: u64,
    process_memory_snapshot: RwLock<Option<ProcessMemorySnapshot>>,
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
    udp_relay_drops_total: CounterVec<ProtocolTransportReasonLabels>,
    udp_oversized_datagrams_dropped_total: CounterVec<UserProtocolDirectionLabels>,
    udp_nat_active_entries: AtomicI64,
    udp_nat_entries_created_total: AtomicU64,
    udp_nat_entries_evicted_total: AtomicU64,
    udp_nat_responses_dropped_total: AtomicU64,
}

impl Metrics {
    pub fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            method: config.method.as_str().to_owned(),
            tcp_tls_enabled: config.tcp_tls_enabled(),
            h3_enabled: config.h3_enabled(),
            client_active_ttl_secs: config.client_active_ttl_secs,
            process_memory_snapshot: RwLock::new(process_memory_snapshot()),
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
            udp_relay_drops_total: CounterVec::default(),
            udp_oversized_datagrams_dropped_total: CounterVec::default(),
            udp_nat_active_entries: AtomicI64::new(0),
            udp_nat_entries_created_total: AtomicU64::new(0),
            udp_nat_entries_evicted_total: AtomicU64::new(0),
            udp_nat_responses_dropped_total: AtomicU64::new(0),
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
        let labels = WsDirectionLabels { transport, protocol, direction };
        self.websocket_frames_total.inc(labels.clone(), 1);
        self.websocket_bytes_total.inc(labels, bytes as u64);
    }

    pub fn record_tcp_authenticated_session(&self, user: impl Into<Arc<str>>, protocol: Protocol) {
        let user = user.into();
        self.record_client_session(Arc::clone(&user), protocol, Transport::Tcp);
        self.tcp_authenticated_sessions_total
            .inc(UserProtocolLabels::new(user, protocol), 1);
    }

    pub fn record_client_session(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        transport: Transport,
    ) {
        let user = user.into();
        self.client_sessions_total
            .inc(UserProtocolTransportLabels::new(Arc::clone(&user), protocol, transport), 1);
        self.record_client_last_seen(user);
    }

    pub fn record_client_last_seen(&self, user: impl Into<Arc<str>>) {
        self.client_last_seen_seconds
            .set(UserLabels::new(user.into()), unix_timestamp_seconds());
    }

    pub fn record_tcp_connect(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user = user.into();
        let labels = UserProtocolResultLabels::new(user, protocol, result);
        self.tcp_upstream_connects_total.inc(labels.clone(), 1);
        self.tcp_upstream_connect_duration_seconds.observe(labels, duration_seconds);
    }

    pub fn open_tcp_upstream_connection(
        self: &Arc<Self>,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
    ) -> TcpUpstreamGuard {
        let user = user.into();
        let labels = UserProtocolLabels::new(user, protocol);
        self.active_tcp_upstream_connections.inc(labels.clone(), 1);
        TcpUpstreamGuard { metrics: self.clone(), labels, finished: false }
    }

    pub fn record_tcp_payload_bytes(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        let user = user.into();
        self.tcp_payload_bytes_total.inc(
            UserProtocolDirectionLabels::new(Arc::clone(&user), protocol, direction),
            bytes as u64,
        );
        self.client_payload_bytes_total.inc(
            UserProtocolTransportDirectionLabels::new(user, protocol, Transport::Tcp, direction),
            bytes as u64,
        );
    }

    pub fn record_udp_request(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user = user.into();
        let labels = UserProtocolResultLabels::new(user, protocol, result);
        self.udp_requests_total.inc(labels.clone(), 1);
        self.udp_relay_duration_seconds.observe(labels, duration_seconds);
    }

    pub fn record_udp_payload_bytes(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
        bytes: usize,
    ) {
        let user = user.into();
        self.udp_payload_bytes_total.inc(
            UserProtocolDirectionLabels::new(Arc::clone(&user), protocol, direction),
            bytes as u64,
        );
        self.client_payload_bytes_total.inc(
            UserProtocolTransportDirectionLabels::new(user, protocol, Transport::Udp, direction),
            bytes as u64,
        );
    }

    pub fn record_udp_response_datagrams(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        count: usize,
    ) {
        self.udp_response_datagrams_total
            .inc(UserProtocolLabels::new(user.into(), protocol), count as u64);
    }

    pub fn record_udp_relay_drop(
        &self,
        transport: Transport,
        protocol: Protocol,
        reason: &'static str,
    ) {
        self.udp_relay_drops_total
            .inc(ProtocolTransportReasonLabels { transport, protocol, reason }, 1);
    }

    pub fn record_udp_oversized_datagram_dropped(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        direction: &'static str,
    ) {
        self.udp_oversized_datagrams_dropped_total
            .inc(UserProtocolDirectionLabels::new(user.into(), protocol, direction), 1);
    }

    pub fn record_udp_nat_entry_created(&self) {
        self.udp_nat_active_entries.fetch_add(1, Ordering::Relaxed);
        self.udp_nat_entries_created_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_nat_entries_evicted(&self, count: usize) {
        self.udp_nat_active_entries.fetch_sub(count as i64, Ordering::Relaxed);
        self.udp_nat_entries_evicted_total.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn record_udp_nat_response_dropped(&self) {
        self.udp_nat_responses_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    fn cached_process_memory_snapshot(&self) -> Option<ProcessMemorySnapshot> {
        self.process_memory_snapshot
            .read()
            .expect("process memory snapshot poisoned")
            .clone()
    }

    async fn refresh_process_memory_snapshot(self: &Arc<Self>) {
        #[cfg(target_os = "linux")]
        let snapshot = match tokio::task::spawn_blocking(process_memory_snapshot).await {
            Ok(snapshot) => snapshot,
            Err(_) => return,
        };

        #[cfg(not(target_os = "linux"))]
        let snapshot = process_memory_snapshot();

        *self.process_memory_snapshot.write().expect("process memory snapshot poisoned") = snapshot;
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

        write_help(&mut out, "outline_ss_uptime_seconds", "Seconds since the process started.");
        write_type(&mut out, "outline_ss_uptime_seconds", "gauge");
        writeln!(out, "outline_ss_uptime_seconds {:.3}", self.started_at.elapsed().as_secs_f64())
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

        if let Some(snapshot) = self.cached_process_memory_snapshot() {
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

            if let Some(thread_count) = snapshot.thread_count {
                write_help(
                    &mut out,
                    "outline_ss_process_threads",
                    "Thread count of the outline-ss-rust process.",
                );
                write_type(&mut out, "outline_ss_process_threads", "gauge");
                writeln!(out, "outline_ss_process_threads {}", thread_count).ok();
            }

            if let Some(virtual_stack_bytes) = snapshot.virtual_stack_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_stack_bytes",
                    "Virtual memory bytes currently reserved by process stacks.",
                );
                write_type(&mut out, "outline_ss_process_virtual_stack_bytes", "gauge");
                writeln!(out, "outline_ss_process_virtual_stack_bytes {}", virtual_stack_bytes)
                    .ok();
            }

            if let Some(virtual_anon_private_bytes) = snapshot.virtual_anon_private_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_anon_private_bytes",
                    "Virtual memory bytes in anonymous private mappings.",
                );
                write_type(&mut out, "outline_ss_process_virtual_anon_private_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_virtual_anon_private_bytes {}",
                    virtual_anon_private_bytes
                )
                .ok();
            }

            if let Some(virtual_anon_shared_bytes) = snapshot.virtual_anon_shared_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_anon_shared_bytes",
                    "Virtual memory bytes in anonymous shared mappings.",
                );
                write_type(&mut out, "outline_ss_process_virtual_anon_shared_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_virtual_anon_shared_bytes {}",
                    virtual_anon_shared_bytes
                )
                .ok();
            }

            if let Some(virtual_file_private_bytes) = snapshot.virtual_file_private_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_file_private_bytes",
                    "Virtual memory bytes in file-backed private mappings.",
                );
                write_type(&mut out, "outline_ss_process_virtual_file_private_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_virtual_file_private_bytes {}",
                    virtual_file_private_bytes
                )
                .ok();
            }

            if let Some(virtual_file_shared_bytes) = snapshot.virtual_file_shared_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_file_shared_bytes",
                    "Virtual memory bytes in file-backed shared mappings.",
                );
                write_type(&mut out, "outline_ss_process_virtual_file_shared_bytes", "gauge");
                writeln!(
                    out,
                    "outline_ss_process_virtual_file_shared_bytes {}",
                    virtual_file_shared_bytes
                )
                .ok();
            }

            if let Some(virtual_special_bytes) = snapshot.virtual_special_bytes {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_special_bytes",
                    "Virtual memory bytes in special kernel/runtime mappings such as [vdso] or [vvar].",
                );
                write_type(&mut out, "outline_ss_process_virtual_special_bytes", "gauge");
                writeln!(out, "outline_ss_process_virtual_special_bytes {}", virtual_special_bytes)
                    .ok();
            }

            if !snapshot.top_virtual_mappings.is_empty() {
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_top_mapping_size_bytes",
                    "Top virtual memory mappings by reserved size from /proc/self/smaps.",
                );
                write_type(&mut out, "outline_ss_process_virtual_top_mapping_size_bytes", "gauge");
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_top_mapping_rss_bytes",
                    "RSS contribution of the top virtual memory mappings from /proc/self/smaps.",
                );
                write_type(&mut out, "outline_ss_process_virtual_top_mapping_rss_bytes", "gauge");
                write_help(
                    &mut out,
                    "outline_ss_process_virtual_top_mapping_gap_bytes",
                    "Reserved but currently non-resident bytes of the top virtual memory mappings from /proc/self/smaps.",
                );
                write_type(&mut out, "outline_ss_process_virtual_top_mapping_gap_bytes", "gauge");

                for (index, mapping) in snapshot.top_virtual_mappings.iter().enumerate() {
                    let rank = index + 1;
                    writeln!(
                        out,
                        "outline_ss_process_virtual_top_mapping_size_bytes{{rank=\"{}\",kind=\"{}\",perms=\"{}\",name=\"{}\"}} {}",
                        rank,
                        escape_label_value(mapping.kind),
                        escape_label_value(&mapping.perms),
                        escape_label_value(&mapping.name),
                        mapping.size_bytes
                    )
                    .ok();
                    writeln!(
                        out,
                        "outline_ss_process_virtual_top_mapping_rss_bytes{{rank=\"{}\",kind=\"{}\",perms=\"{}\",name=\"{}\"}} {}",
                        rank,
                        escape_label_value(mapping.kind),
                        escape_label_value(&mapping.perms),
                        escape_label_value(&mapping.name),
                        mapping.rss_bytes
                    )
                    .ok();
                    writeln!(
                        out,
                        "outline_ss_process_virtual_top_mapping_gap_bytes{{rank=\"{}\",kind=\"{}\",perms=\"{}\",name=\"{}\"}} {}",
                        rank,
                        escape_label_value(mapping.kind),
                        escape_label_value(&mapping.perms),
                        escape_label_value(&mapping.name),
                        mapping.size_bytes.saturating_sub(mapping.rss_bytes)
                    )
                    .ok();
                }
            }
        }

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
        let client_active =
            client_active_snapshots(&self.client_last_seen_seconds, self.client_active_ttl_secs);
        render_gauge_snapshots(
            &mut out,
            "outline_ss_client_active",
            "Client active state by user using the configured TTL.",
            client_active.clone(),
        );
        render_gauge_snapshots(
            &mut out,
            "outline_ss_client_up",
            "Alias of outline_ss_client_active for online-state dashboards.",
            client_active,
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
        render_counter_family(
            &mut out,
            "outline_ss_udp_relay_drops_total",
            "UDP datagrams dropped before relay because of transport backpressure or concurrency limits.",
            &self.udp_relay_drops_total,
        );
        render_counter_family(
            &mut out,
            "outline_ss_udp_oversized_datagrams_dropped_total",
            "UDP datagrams dropped because they exceeded the maximum payload size supported by the transport path.",
            &self.udp_oversized_datagrams_dropped_total,
        );

        write_help(
            &mut out,
            "outline_ss_udp_nat_active_entries",
            "Current number of active UDP NAT table entries.",
        );
        write_type(&mut out, "outline_ss_udp_nat_active_entries", "gauge");
        writeln!(
            out,
            "outline_ss_udp_nat_active_entries {}",
            self.udp_nat_active_entries.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_udp_nat_entries_created_total",
            "Total UDP NAT table entries ever created.",
        );
        write_type(&mut out, "outline_ss_udp_nat_entries_created_total", "counter");
        writeln!(
            out,
            "outline_ss_udp_nat_entries_created_total {}",
            self.udp_nat_entries_created_total.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_udp_nat_entries_evicted_total",
            "Total UDP NAT table entries evicted due to idle timeout.",
        );
        write_type(&mut out, "outline_ss_udp_nat_entries_evicted_total", "counter");
        writeln!(
            out,
            "outline_ss_udp_nat_entries_evicted_total {}",
            self.udp_nat_entries_evicted_total.load(Ordering::Relaxed)
        )
        .ok();

        write_help(
            &mut out,
            "outline_ss_udp_nat_responses_dropped_total",
            "UDP upstream responses dropped because no WebSocket session was registered.",
        );
        write_type(&mut out, "outline_ss_udp_nat_responses_dropped_total", "counter");
        writeln!(
            out,
            "outline_ss_udp_nat_responses_dropped_total {}",
            self.udp_nat_responses_dropped_total.load(Ordering::Relaxed)
        )
        .ok();

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
        self.metrics.active_websocket_sessions.inc(self.labels.clone(), -1);
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
            self.metrics.active_websocket_sessions.inc(self.labels.clone(), -1);
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
        self.metrics.active_tcp_upstream_connections.inc(self.labels.clone(), -1);
    }
}

impl Drop for TcpUpstreamGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.active_tcp_upstream_connections.inc(self.labels.clone(), -1);
            self.finished = true;
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct ProtocolTransportReasonLabels {
    transport: Transport,
    protocol: Protocol,
    reason: &'static str,
}

impl PrometheusLabels for ProtocolTransportReasonLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("transport", self.transport.as_str().to_owned()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("reason", self.reason.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserProtocolLabels {
    user: Arc<str>,
    protocol: Protocol,
}

impl UserProtocolLabels {
    fn new(user: Arc<str>, protocol: Protocol) -> Self {
        Self { user, protocol }
    }
}

impl PrometheusLabels for UserProtocolLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![("user", self.user.to_string()), ("protocol", self.protocol.as_str().to_owned())]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserLabels {
    user: Arc<str>,
}

impl UserLabels {
    fn new(user: Arc<str>) -> Self {
        Self { user }
    }
}

impl PrometheusLabels for UserLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![("user", self.user.to_string())]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserProtocolTransportLabels {
    user: Arc<str>,
    protocol: Protocol,
    transport: Transport,
}

impl UserProtocolTransportLabels {
    fn new(user: Arc<str>, protocol: Protocol, transport: Transport) -> Self {
        Self { user, protocol, transport }
    }
}

impl PrometheusLabels for UserProtocolTransportLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.to_string()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("transport", self.transport.as_str().to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserProtocolResultLabels {
    user: Arc<str>,
    protocol: Protocol,
    result: &'static str,
}

impl UserProtocolResultLabels {
    fn new(user: Arc<str>, protocol: Protocol, result: &'static str) -> Self {
        Self { user, protocol, result }
    }
}

impl PrometheusLabels for UserProtocolResultLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.to_string()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("result", self.result.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserProtocolDirectionLabels {
    user: Arc<str>,
    protocol: Protocol,
    direction: &'static str,
}

impl UserProtocolDirectionLabels {
    fn new(user: Arc<str>, protocol: Protocol, direction: &'static str) -> Self {
        Self { user, protocol, direction }
    }
}

impl PrometheusLabels for UserProtocolDirectionLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.to_string()),
            ("protocol", self.protocol.as_str().to_owned()),
            ("direction", self.direction.to_owned()),
        ]
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
struct UserProtocolTransportDirectionLabels {
    user: Arc<str>,
    protocol: Protocol,
    transport: Transport,
    direction: &'static str,
}

impl UserProtocolTransportDirectionLabels {
    fn new(
        user: Arc<str>,
        protocol: Protocol,
        transport: Transport,
        direction: &'static str,
    ) -> Self {
        Self { user, protocol, transport, direction }
    }
}

impl PrometheusLabels for UserProtocolTransportDirectionLabels {
    fn labels(&self) -> Vec<(&'static str, String)> {
        vec![
            ("user", self.user.to_string()),
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
    values: RwLock<HashMap<L, Arc<AtomicU64>>>,
}

impl<L> Default for CounterVec<L> {
    fn default() -> Self {
        Self { values: RwLock::new(HashMap::new()) }
    }
}

impl<L> CounterVec<L>
where
    L: Clone + Eq + Hash + Ord,
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
            values.entry(labels).or_insert_with(|| Arc::new(AtomicU64::new(0))).clone()
        };
        cell.fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(L, u64)> {
        let mut snapshot = self
            .values
            .read()
            .expect("counter vec poisoned")
            .iter()
            .map(|(labels, value)| (labels.clone(), value.load(Ordering::Relaxed)))
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }
}

struct GaugeVec<L> {
    values: RwLock<HashMap<L, Arc<AtomicI64>>>,
}

impl<L> Default for GaugeVec<L> {
    fn default() -> Self {
        Self { values: RwLock::new(HashMap::new()) }
    }
}

impl<L> GaugeVec<L>
where
    L: Clone + Eq + Hash + Ord,
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
            values.entry(labels).or_insert_with(|| Arc::new(AtomicI64::new(0))).clone()
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
            values.entry(labels).or_insert_with(|| Arc::new(AtomicI64::new(0))).clone()
        };
        cell.fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(L, i64)> {
        let mut snapshot = self
            .values
            .read()
            .expect("gauge vec poisoned")
            .iter()
            .map(|(labels, value)| (labels.clone(), value.load(Ordering::Relaxed)))
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }
}

struct HistogramVec<L> {
    buckets: &'static [f64],
    values: RwLock<HashMap<L, Arc<Mutex<HistogramState>>>>,
}

impl<L> HistogramVec<L>
where
    L: Clone + Eq + Hash + Ord,
{
    fn new(buckets: &'static [f64]) -> Self {
        Self { buckets, values: RwLock::new(HashMap::new()) }
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
        let mut snapshot = self
            .values
            .read()
            .expect("histogram vec poisoned")
            .iter()
            .map(|(labels, state)| {
                let snapshot =
                    state.lock().expect("histogram state poisoned").snapshot(self.buckets);
                (labels.clone(), snapshot)
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    }
}

struct HistogramState {
    bucket_counts: Vec<u64>,
    count: u64,
    sum: f64,
}

impl HistogramState {
    fn new(buckets: &[f64]) -> Self {
        Self { bucket_counts: vec![0; buckets.len()], count: 0, sum: 0.0 }
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

fn render_counter_family<L>(out: &mut String, name: &str, help: &str, metric: &CounterVec<L>)
where
    L: PrometheusLabels + Clone + Eq + Hash + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "counter");
    for (labels, value) in metric.snapshot() {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_gauge_family<L>(out: &mut String, name: &str, help: &str, metric: &GaugeVec<L>)
where
    L: PrometheusLabels + Clone + Eq + Hash + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "gauge");
    for (labels, value) in metric.snapshot() {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_gauge_snapshots<L>(out: &mut String, name: &str, help: &str, snapshots: Vec<(L, i64)>)
where
    L: PrometheusLabels + Clone + Eq + Hash + Ord,
{
    write_help(out, name, help);
    write_type(out, name, "gauge");
    for (labels, value) in snapshots {
        write_metric_line(out, name, &labels.labels(), value.to_string());
    }
}

fn render_histogram_family<L>(out: &mut String, name: &str, help: &str, metric: &HistogramVec<L>)
where
    L: PrometheusLabels + Clone + Eq + Hash + Ord,
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
            write_metric_line(
                out,
                &format!("{name}_bucket"),
                &bucket_labels,
                cumulative.to_string(),
            );
        }
        let mut inf_labels = base_labels.clone();
        inf_labels.push(("le", "+Inf".to_owned()));
        write_metric_line(out, &format!("{name}_bucket"), &inf_labels, snapshot.count.to_string());
        write_metric_line(
            out,
            &format!("{name}_sum"),
            &base_labels,
            format!("{:.6}", snapshot.sum),
        );
        write_metric_line(out, &format!("{name}_count"), &base_labels, snapshot.count.to_string());
    }
}

fn write_help(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
}

fn write_type(out: &mut String, name: &str, metric_type: &str) {
    writeln!(out, "# TYPE {name} {metric_type}").ok();
}

fn write_metric_line(
    out: &mut String,
    name: &str,
    labels: &[(&'static str, String)],
    value: String,
) {
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
            let active =
                if seen_at > 0 && now.saturating_sub(seen_at) <= ttl_secs as i64 { 1 } else { 0 };
            (labels, active)
        })
        .collect()
}

fn escape_label_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"")
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
struct VirtualMemoryBreakdown {
    stack_bytes: Option<u64>,
    anon_private_bytes: Option<u64>,
    anon_shared_bytes: Option<u64>,
    file_private_bytes: Option<u64>,
    file_shared_bytes: Option<u64>,
    special_bytes: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default)]
struct VirtualMemoryDiagnostics {
    breakdown: VirtualMemoryBreakdown,
    top_mappings: Vec<TopVirtualMapping>,
}

#[cfg(target_os = "linux")]
fn process_memory_snapshot_impl() -> Option<ProcessMemorySnapshot> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let resident_memory_bytes = proc_status_value_bytes(&status, "VmRSS:")?;
    let virtual_memory_bytes = proc_status_value_bytes(&status, "VmSize:")?;
    let thread_count = proc_status_value_u64(&status, "Threads:");
    let virtual_diagnostics = procfs_virtual_memory_diagnostics();
    let virtual_breakdown = &virtual_diagnostics.breakdown;
    Some(ProcessMemorySnapshot {
        resident_memory_bytes,
        virtual_memory_bytes,
        thread_count,
        virtual_stack_bytes: virtual_breakdown.stack_bytes,
        virtual_anon_private_bytes: virtual_breakdown.anon_private_bytes,
        virtual_anon_shared_bytes: virtual_breakdown.anon_shared_bytes,
        virtual_file_private_bytes: virtual_breakdown.file_private_bytes,
        virtual_file_shared_bytes: virtual_breakdown.file_shared_bytes,
        virtual_special_bytes: virtual_breakdown.special_bytes,
        top_virtual_mappings: virtual_diagnostics.top_mappings,
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
fn proc_status_value_u64(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

#[cfg(target_os = "linux")]
fn procfs_virtual_memory_diagnostics() -> VirtualMemoryDiagnostics {
    let smaps = match std::fs::read_to_string("/proc/self/smaps") {
        Ok(smaps) => smaps,
        Err(_) => return VirtualMemoryDiagnostics::default(),
    };

    let mut diagnostics = VirtualMemoryDiagnostics::default();
    let mut current_mapping = None;
    let mut current_size_kib = 0_u64;
    let mut current_rss_kib = 0_u64;

    for line in smaps.lines() {
        if is_smaps_mapping_header(line) {
            finalize_virtual_mapping(
                &mut diagnostics,
                current_mapping.take(),
                current_size_kib,
                current_rss_kib,
            );
            current_mapping = parse_smaps_mapping_header(line);
            current_size_kib = 0;
            current_rss_kib = 0;
            continue;
        }

        if smaps_value_kib(line, "Size:").is_some() {
            current_size_kib = smaps_value_kib(line, "Size:").unwrap_or(0);
        } else if smaps_value_kib(line, "Rss:").is_some() {
            current_rss_kib = smaps_value_kib(line, "Rss:").unwrap_or(0);
        }
    }

    finalize_virtual_mapping(&mut diagnostics, current_mapping, current_size_kib, current_rss_kib);
    diagnostics.top_mappings.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| right.rss_bytes.cmp(&left.rss_bytes))
    });
    diagnostics.top_mappings.truncate(8);
    diagnostics
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

#[cfg(target_os = "linux")]
fn add_optional_u64(slot: &mut Option<u64>, value: u64) {
    *slot = Some(slot.unwrap_or(0).saturating_add(value));
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum MappingKind {
    Heap,
    Stack,
    AnonPrivate,
    AnonShared,
    FilePrivate,
    FileShared,
    Special,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct SmapsMappingHeader<'a> {
    kind: MappingKind,
    perms: &'a str,
    pathname: Option<&'a str>,
}

#[cfg(target_os = "linux")]
impl<'a> SmapsMappingHeader<'a> {
    fn classify(shared: bool, pathname: Option<&str>) -> MappingKind {
        match pathname {
            Some("[heap]") => MappingKind::Heap,
            Some(path) if path.starts_with("[stack") => MappingKind::Stack,
            Some(path) if path.starts_with("[anon") => {
                if shared {
                    MappingKind::AnonShared
                } else {
                    MappingKind::AnonPrivate
                }
            }
            Some(path) if path.starts_with('[') => MappingKind::Special,
            Some(_) => {
                if shared {
                    MappingKind::FileShared
                } else {
                    MappingKind::FilePrivate
                }
            }
            None => {
                if shared {
                    MappingKind::AnonShared
                } else {
                    MappingKind::AnonPrivate
                }
            }
        }
    }

    fn kind_label(self) -> &'static str {
        match self.kind {
            MappingKind::Heap => "heap",
            MappingKind::Stack => "stack",
            MappingKind::AnonPrivate => "anon_private",
            MappingKind::AnonShared => "anon_shared",
            MappingKind::FilePrivate => "file_private",
            MappingKind::FileShared => "file_shared",
            MappingKind::Special => "special",
        }
    }

    fn display_name(self) -> String {
        match self.pathname {
            Some(path) => truncate_metric_label_value(path, 96),
            None => "[anonymous]".to_owned(),
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_smaps_mapping_header(line: &str) -> Option<SmapsMappingHeader<'_>> {
    let mut fields = line.split_whitespace();
    fields.next()?;
    let perms = fields.next()?;
    fields.next()?;
    fields.next()?;
    fields.next()?;
    let pathname = fields.next();
    let shared = perms.contains('s');

    Some(SmapsMappingHeader {
        kind: SmapsMappingHeader::classify(shared, pathname),
        perms,
        pathname,
    })
}

#[cfg(target_os = "linux")]
fn finalize_virtual_mapping(
    diagnostics: &mut VirtualMemoryDiagnostics,
    mapping: Option<SmapsMappingHeader<'_>>,
    size_kib: u64,
    rss_kib: u64,
) {
    let Some(mapping) = mapping else {
        return;
    };
    if size_kib == 0 {
        return;
    }

    let size_bytes = size_kib.saturating_mul(1024);
    let rss_bytes = rss_kib.saturating_mul(1024);

    match mapping.kind {
        MappingKind::Heap => {}
        MappingKind::Stack => add_optional_u64(&mut diagnostics.breakdown.stack_bytes, size_bytes),
        MappingKind::AnonPrivate => {
            add_optional_u64(&mut diagnostics.breakdown.anon_private_bytes, size_bytes)
        }
        MappingKind::AnonShared => {
            add_optional_u64(&mut diagnostics.breakdown.anon_shared_bytes, size_bytes)
        }
        MappingKind::FilePrivate => {
            add_optional_u64(&mut diagnostics.breakdown.file_private_bytes, size_bytes)
        }
        MappingKind::FileShared => {
            add_optional_u64(&mut diagnostics.breakdown.file_shared_bytes, size_bytes)
        }
        MappingKind::Special => {
            add_optional_u64(&mut diagnostics.breakdown.special_bytes, size_bytes)
        }
    }

    diagnostics.top_mappings.push(TopVirtualMapping {
        kind: mapping.kind_label(),
        perms: mapping.perms.to_owned(),
        name: mapping.display_name(),
        size_bytes,
        rss_bytes,
    });
}

#[cfg(target_os = "linux")]
fn truncate_metric_label_value(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }

    let mut truncated = String::new();
    for ch in value.chars().take(limit.saturating_sub(3)) {
        truncated.push(ch);
    }
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::{DisconnectReason, Metrics, Protocol, Transport};

    #[test]
    fn renders_prometheus_metrics() {
        let config = Config {
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
            public_host: None,
            public_scheme: "wss".to_owned(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".to_owned(),
            print_access_keys: false,
            write_access_keys_dir: None,
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
        assert!(rendered.contains("transport=\"udp\",direction=\"target_to_client\""));
    }
}
