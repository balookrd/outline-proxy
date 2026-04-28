mod guards;
mod labels;
mod process_memory;
mod registry;
mod render;
mod sampler;
mod user_counters;

pub use guards::{TcpUpstreamGuard, WebSocketSessionGuard};
pub use labels::{DisconnectReason, Protocol, Transport};
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

pub struct Metrics {
    pub(super) started_at: Instant,
    method: String,
    tcp_tls_enabled: bool,
    h3_enabled: bool,
    pub(super) client_active_ttl_secs: u64,
    pub(super) process_memory_snapshot: RwLock<Option<ProcessMemorySnapshot>>,
    pub(super) client_last_seen: DashMap<Arc<str>, AtomicI64>,
    pub(super) user_counters_cache: DashMap<Arc<str>, Arc<PerUserCounters>>,
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
            recorder,
            handle,
        });

        with_local_recorder(&metrics.recorder, || {
            registry::register_descriptions();
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
        TcpUpstreamGuard {
            metrics: self.clone(),
            user_id,
            protocol,
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

    pub fn record_udp_replay_dropped(&self, user: impl Into<Arc<str>>, protocol: Protocol) {
        let user: Arc<str> = user.into();
        with_local_recorder(&self.recorder, || {
            counter!(
                "outline_ss_udp_replay_dropped_total",
                "user"     => user,
                "protocol" => protocol.as_str()
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
                "user"     => user,
                "protocol" => protocol.as_str()
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

    // ── Rendering ──────────────────────────────────────────────────────────────

    pub fn render_prometheus(&self) -> String {
        render::render_prometheus(self)
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
