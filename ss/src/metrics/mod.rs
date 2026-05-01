mod guards;
mod labels;
mod process_memory;
mod registry;
mod render;
mod sampler;
mod user_counters;

pub use guards::{TcpUpstreamGuard, WebSocketSessionGuard};
pub use labels::{AppProtocol, DisconnectReason, Protocol, Transport};
pub use process_memory::ProcessMemorySnapshot;
pub use user_counters::PerUserCounters;

use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use metrics::{counter, gauge, histogram, with_local_recorder};
use metrics_exporter_prometheus::{PrometheusHandle, PrometheusRecorder};
use parking_lot::RwLock;

use crate::config::Config;

/// Maximum number of distinct SNI label values kept on
/// `outline_ss_tls_handshake_no_cert_chain_total`. A scanner can cycle
/// through arbitrary `*.example` names and each one would otherwise add
/// a new Prometheus time-series — at the storage layer that cost is
/// permanent for the retention window. Cap at 64; everything above
/// folds into the `<overflow>` bucket and the operator gets a single
/// signal to either widen the cap or harden `match_sni`.
const TLS_NO_CERT_CHAIN_SNI_CAP: usize = 64;

pub struct Metrics {
    pub(super) started_at: Instant,
    method: String,
    tcp_tls_enabled: bool,
    h3_enabled: bool,
    pub(super) client_active_ttl_secs: u64,
    pub(super) process_memory_snapshot: RwLock<Option<ProcessMemorySnapshot>>,
    pub(super) client_last_seen: DashMap<Arc<str>, AtomicI64>,
    pub(super) user_counters_cache: DashMap<Arc<str>, Arc<PerUserCounters>>,
    /// Set of distinct SNIs already observed for the
    /// `outline_ss_tls_handshake_no_cert_chain_total` metric. We cache
    /// the `Arc<str>` so repeat hits on the same SNI reuse the same
    /// label value (no allocation per record), and we bound the set
    /// at [`TLS_NO_CERT_CHAIN_SNI_CAP`] so a flood of attacker-chosen
    /// SNIs cannot blow up Prometheus cardinality. Once full, every
    /// new SNI is folded into a single `<overflow>` bucket.
    pub(super) tls_no_cert_chain_snis: DashMap<Arc<str>, ()>,
    pub(super) recorder: PrometheusRecorder,
    pub(super) handle: PrometheusHandle,
}

impl Metrics {
    pub fn new(config: &Config) -> Arc<Self> {
        let idle_timeout = Duration::from_secs(config.tuning.client_active_ttl_secs);
        let (recorder, handle) = registry::build_recorder(idle_timeout);
        let metrics = Arc::new(Self {
            started_at: Instant::now(),
            method: config.method.as_str().to_owned(),
            tcp_tls_enabled: config.tcp_tls_enabled(),
            h3_enabled: config.h3_enabled(),
            client_active_ttl_secs: config.tuning.client_active_ttl_secs,
            process_memory_snapshot: RwLock::new(process_memory::sample()),
            client_last_seen: DashMap::new(),
            user_counters_cache: DashMap::new(),
            tls_no_cert_chain_snis: DashMap::new(),
            recorder,
            handle,
        });

        with_local_recorder(&metrics.recorder, || {
            registry::register_descriptions();
        });
        metrics.touch_static_info();

        metrics
    }

    /// Re-asserts the static `build_info` and `config_info` gauges so that
    /// the recorder's idle-timeout cannot evict them. Called from `Metrics::new`
    /// at startup and from `render_prometheus` on every scrape — both write
    /// the same constant value, so the only effect of repeated calls is
    /// keeping the time-series alive past `client_active_ttl_secs`.
    pub(super) fn touch_static_info(&self) {
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
            gauge!(
                "outline_ss_config_info",
                "method"   => self.method.clone(),
                "tcp_tls"  => bool_label(self.tcp_tls_enabled),
                "http3"    => bool_label(self.h3_enabled)
            )
            .set(1.0);
        });
    }

    // ── Session guards ─────────────────────────────────────────────────────────

    pub fn open_websocket_session(
        self: &Arc<Self>,
        transport: Transport,
        protocol: Protocol,
        app_protocol: AppProtocol,
    ) -> WebSocketSessionGuard {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_websocket_upgrades_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1);
            gauge!(
                "outline_ss_active_websocket_sessions",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1.0);
        });
        WebSocketSessionGuard {
            metrics: self.clone(),
            transport,
            protocol,
            app_protocol,
            started_at: Instant::now(),
            finished: false,
        }
    }

    pub fn open_tcp_upstream_connection(
        self: &Arc<Self>,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
    ) -> TcpUpstreamGuard {
        let user_id: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            gauge!(
                "outline_ss_active_tcp_upstream_connections",
                "user"         => Arc::clone(&user_id),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1.0);
        });
        TcpUpstreamGuard {
            metrics: self.clone(),
            user_id,
            protocol,
            app_protocol,
            finished: false,
        }
    }

    // ── Recording methods ──────────────────────────────────────────────────────

    pub fn start_process_memory_sampler(self: &Arc<Self>) {
        sampler::spawn(Arc::clone(self));
    }

    pub fn record_maintenance_task_panic(&self, task: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_maintenance_task_panics_total", "task" => task).increment(1);
        });
    }

    /// Counts a websocket session that the server tore down because no
    /// inbound frame had been seen for `WS_PONG_DEADLINE_MULTIPLIER ×
    /// WS_TCP_KEEPALIVE_PING_INTERVAL_SECS`. Without this counter
    /// pong-deadline closures are indistinguishable from peer-initiated
    /// `DisconnectReason::Normal` in the disconnect histogram, hiding a
    /// throughput-degrading symptom (server cuts a slow but live client
    /// because keepalive pings can't traverse a saturated client-side
    /// TLS write half).
    pub fn record_pong_deadline_disconnect(
        &self,
        transport: Transport,
        app_protocol: AppProtocol,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_websocket_pong_deadline_total",
                "transport"    => transport.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1);
        });
    }

    /// Observes the current depth of the upstream→ws-writer mpsc
    /// channel. Sampled at every `tx.send` call-site so a reader that
    /// stalls behind the WS-writer shows up as a saturated histogram
    /// rather than as opaque throughput loss. `used` is
    /// `tx.max_capacity() - tx.capacity()`.
    pub fn observe_ws_data_channel_fill(
        &self,
        transport: Transport,
        app_protocol: AppProtocol,
        used: usize,
    ) {
        with_local_recorder(&self.recorder, || {
            histogram!(
                "outline_ss_ws_data_channel_fill",
                "transport"    => transport.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .record(used as f64);
        });
    }

    pub fn record_websocket_binary_frame(
        &self,
        transport: Transport,
        protocol: Protocol,
        app_protocol: AppProtocol,
        direction: &'static str,
        bytes: usize,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_websocket_frames_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
            )
            .increment(1);
            counter!(
                "outline_ss_websocket_bytes_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
            )
            .increment(bytes as u64);
            histogram!(
                "outline_ss_websocket_frame_size_bytes",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
            )
            .record(bytes as f64);
        });
    }

    pub fn record_tcp_authenticated_session(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
    ) {
        let user: Arc<str> = user.into();
        self.record_client_session(Arc::clone(&user), protocol, Transport::Tcp, app_protocol);
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tcp_authenticated_sessions_total",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1);
        });
    }

    pub fn record_client_session(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        transport: Transport,
        app_protocol: AppProtocol,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_client_sessions_total",
                "user"         => Arc::clone(&user),
                "protocol"     => protocol.as_str(),
                "transport"    => transport.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(1);
        });
        self.record_client_last_seen(user);
    }

    pub fn record_client_last_seen(&self, user: impl Into<Arc<str>>) {
        let user: Arc<str> = user.into();
        let ts = render::unix_timestamp_seconds();
        if let Some(cell) = self.client_last_seen.get(&user) {
            cell.store(ts, Ordering::Relaxed);
        } else {
            self.client_last_seen
                .entry(Arc::clone(&user))
                .or_insert_with(|| AtomicI64::new(0))
                .store(ts, Ordering::Relaxed);
        }
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_client_last_seen_seconds", "user" => user).set(ts as f64);
        });
    }

    pub fn record_tcp_connect(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tcp_upstream_connects_total",
                "user"         => Arc::clone(&user),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "result"       => result
            )
            .increment(1);
            histogram!(
                "outline_ss_tcp_upstream_connect_duration_seconds",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "result"       => result
            )
            .record(duration_seconds);
        });
    }

    /// Returns pre-resolved per-user counter handles, creating them on first
    /// access.  Use this to avoid `counter!()` lookups and `Arc::clone(&user)`
    /// in hot relay loops — resolve once per session, then call
    /// `.tcp_out(protocol).increment(n)` in the loop.
    pub fn user_counters(&self, user: &Arc<str>) -> Arc<PerUserCounters> {
        if let Some(existing) = self.user_counters_cache.get(user) {
            return Arc::clone(existing.value());
        }
        let counters = self
            .user_counters_cache
            .entry(Arc::clone(user))
            .or_insert_with(|| Arc::new(PerUserCounters::new(&self.recorder, Arc::clone(user))));
        Arc::clone(counters.value())
    }

    pub fn record_udp_request(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        result: &'static str,
        duration_seconds: f64,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_requests_total",
                "user"         => Arc::clone(&user),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "result"       => result
            )
            .increment(1);
            histogram!(
                "outline_ss_udp_relay_duration_seconds",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "result"       => result
            )
            .record(duration_seconds);
        });
    }

    pub fn record_udp_response_datagrams(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        count: usize,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_response_datagrams_total",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .increment(count as u64);
        });
    }

    pub fn record_udp_relay_drop(
        &self,
        transport: Transport,
        protocol: Protocol,
        app_protocol: AppProtocol,
        reason: &'static str,
    ) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_relay_drops_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "reason"       => reason
            )
            .increment(1);
        });
    }

    pub fn record_udp_oversized_datagram_dropped(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        direction: &'static str,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_oversized_datagrams_dropped_total",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
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

    /// SS-2022 anti-replay drop. Replay protection is Shadowsocks-only,
    /// so the metric is always tagged `app_protocol="shadowsocks"`. The
    /// label is added anyway for query symmetry with the rest of the
    /// payload-level metrics.
    pub fn record_udp_replay_dropped(&self, user: impl Into<Arc<str>>, protocol: Protocol) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_replay_dropped_total",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => AppProtocol::Shadowsocks.as_str()
            )
            .increment(1);
        });
    }

    pub fn record_udp_replay_store_full_dropped(
        &self,
        user: impl Into<Arc<str>>,
        protocol: Protocol,
    ) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_replay_store_full_dropped_total",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => AppProtocol::Shadowsocks.as_str()
            )
            .increment(1);
        });
    }

    pub fn record_udp_nat_response_dropped(&self) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_udp_nat_responses_dropped_total").increment(1);
        });
    }

    // ── Session-resumption metrics ─────────────────────────────────────────────

    /// Counts a session that was just moved into the orphan registry. The
    /// `kind` label matches `Parked::kind()` (`tcp`, `udp_single`, etc.).
    pub fn record_orphan_parked(&self, kind: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_orphan_park_total", "kind" => kind).increment(1);
        });
    }

    /// Counts a successful resume. `kind` is the orphan's payload kind.
    pub fn record_orphan_resume_hit(&self, kind: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_orphan_resume_hit_total", "kind" => kind).increment(1);
        });
    }

    /// Counts a failed resume attempt by reason (`unknown`, `disabled`).
    pub fn record_orphan_resume_miss(&self, reason: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_orphan_resume_miss_total", "reason" => reason).increment(1);
        });
    }

    /// Counts an eviction from the orphan registry by reason
    /// (`ttl_expired`, `per_user_cap`, `global_cap`).
    pub fn record_orphan_evicted(&self, kind: &'static str, reason: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_orphan_evicted_total",
                "kind"   => kind,
                "reason" => reason
            )
            .increment(1);
        });
    }

    /// Sets the gauge tracking the current count of parked entries by kind.
    pub fn set_orphan_current(&self, kind: &'static str, count: f64) {
        with_local_recorder(&self.recorder, || {
            gauge!("outline_ss_orphan_current", "kind" => kind).set(count);
        });
    }

    // ── TLS handshake failures ────────────────────────────────────────────────

    /// Counts a TLS handshake that failed before the application got a
    /// usable stream. `reason` is one of:
    /// - `no_cert_chain` — `ResolvesServerCert::resolve()` returned
    ///   `None` (SNI without a registered cert and no default).
    /// - `closed_early` — the peer aborted the connection before we
    ///   could complete the handshake (RST/FIN/EOF).
    /// - `protocol_error` — rustls rejected the ClientHello / record
    ///   stream (malformed TLS, unsupported version, bad MAC, …).
    /// - `io_error` — anything else surfaced as `io::Error` from the
    ///   acceptor (filesystem-style errors are not expected here, but
    ///   we keep the bucket so unknown variants still get counted).
    pub fn record_tls_handshake_failed(&self, reason: &'static str) {
        with_local_recorder(&self.recorder, || {
            counter!("outline_ss_tls_handshake_failed_total", "reason" => reason).increment(1);
        });
    }

    /// Counts a `no_cert_chain` failure broken down by the rejected
    /// SNI. Companion to [`Self::record_tls_handshake_failed`] —
    /// `failed_total{reason="no_cert_chain"}` always equals the sum of
    /// this counter, but this one carries the actual hostname so the
    /// operator can see *which* SNI is missing a cert.
    ///
    /// SNI input is normalised before it ever becomes a label value:
    /// - `None` → `<none>` (no `server_name` extension).
    /// - non-ASCII / control bytes → `<invalid>` (rustls already
    ///   accepted it, but we still don't trust attacker-controlled
    ///   bytes in metric labels).
    /// - longer than 253 chars (RFC 1035 hostname cap) → `<long>`.
    /// - over [`TLS_NO_CERT_CHAIN_SNI_CAP`] distinct SNIs → fold into
    ///   `<overflow>` so cardinality stays bounded.
    pub fn record_tls_handshake_no_cert_chain(&self, sni: Option<&str>) {
        let sni_label = self.intern_no_cert_chain_sni(sni);
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_tls_handshake_no_cert_chain_total",
                "sni" => sni_label
            )
            .increment(1);
        });
    }

    fn intern_no_cert_chain_sni(&self, sni: Option<&str>) -> Arc<str> {
        let Some(raw) = sni else {
            return Arc::from("<none>");
        };
        // Hostnames are ASCII (with IDN already punycode-encoded by
        // the client). Anything else here is either a buggy peer or an
        // attempt to inject log/label noise — fold to a static bucket.
        if !raw.bytes().all(is_safe_sni_byte) {
            return Arc::from("<invalid>");
        }
        if raw.len() > 253 {
            return Arc::from("<long>");
        }
        let normalized = raw.to_ascii_lowercase();

        if let Some(existing) = self.tls_no_cert_chain_snis.get(normalized.as_str()) {
            return Arc::clone(existing.key());
        }

        // Bound the cardinality: if the table is already at the cap,
        // skip the insert and return the static `<overflow>` label.
        // The size check races with concurrent inserts, so the table
        // can briefly grow a few entries past the cap — that's fine,
        // the goal is preventing unbounded growth, not a hard ceiling.
        if self.tls_no_cert_chain_snis.len() >= TLS_NO_CERT_CHAIN_SNI_CAP {
            return Arc::from("<overflow>");
        }

        let arc: Arc<str> = Arc::from(normalized);
        self.tls_no_cert_chain_snis.insert(Arc::clone(&arc), ());
        arc
    }

    // ── Rendering ──────────────────────────────────────────────────────────────

    pub fn render_prometheus(&self) -> String {
        render::render_prometheus(self)
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// ASCII bytes accepted in a hostname-like SNI metric label without
/// triggering the `<invalid>` fallback. Allows the chars actually
/// present in real-world SNIs (DNS names plus the `:port`/`%zone`
/// forms TLS sometimes sees) and rejects everything else.
fn is_safe_sni_byte(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b':'
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
