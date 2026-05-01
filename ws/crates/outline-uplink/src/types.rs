use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex as SyncMutex;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, watch};
use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, ProbeConfig, TransportMode, UplinkConfig};
use outline_transport::TransportStream;
use socks5_proto::TargetAddr;

use super::routing_key::transport_key_prefix;
use super::state::StateStore;

/// Runtime handle for a configured uplink. Cheap to clone (shared `Arc`).
/// Exists to distinguish a runtime-attached uplink reference from the raw
/// [`UplinkConfig`] DTO at call sites. Field access goes through `Deref`.
#[derive(Clone, Debug)]
pub struct Uplink(Arc<UplinkConfig>);

impl Uplink {
    pub fn new(config: UplinkConfig) -> Self {
        Self(Arc::new(config))
    }
}

impl From<UplinkConfig> for Uplink {
    fn from(config: UplinkConfig) -> Self {
        Self::new(config)
    }
}

impl std::ops::Deref for Uplink {
    type Target = UplinkConfig;
    fn deref(&self) -> &UplinkConfig {
        &self.0
    }
}

#[derive(Clone)]
pub struct UplinkManager {
    pub(crate) inner: Arc<UplinkManagerInner>,
}

impl std::fmt::Debug for UplinkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UplinkManager")
            .field("group", &self.inner.group_name)
            .field("uplinks", &self.inner.uplinks.len())
            .finish()
    }
}

/// Combined active-uplink selection state.  All three indices are written
/// together on selection events and read together in snapshots, so a single
/// lock is cheaper than three.
#[derive(Clone, Default)]
pub(crate) struct ActiveUplinks {
    /// Global active index (used in `strict_global_active` mode).
    pub(crate) global: Option<usize>,
    pub(crate) global_reason: Option<String>,
    /// Per-transport TCP active index (used in `strict_per_uplink` mode).
    pub(crate) tcp: Option<usize>,
    pub(crate) tcp_reason: Option<String>,
    /// Per-transport UDP active index (used in `strict_per_uplink` mode).
    pub(crate) udp: Option<usize>,
    pub(crate) udp_reason: Option<String>,
}

pub(crate) struct UplinkManagerInner {
    /// Name of the group this manager represents. Surfaced as the `group`
    /// Prometheus label on every uplink-scoped metric emitted from within.
    pub(crate) group_name: String,
    pub(crate) uplinks: Vec<Uplink>,
    pub(crate) probe: ProbeConfig,
    pub(crate) load_balancing: LoadBalancingConfig,
    /// Per-uplink status guarded by an individual sync lock. Length is fixed
    /// at construction and matches `uplinks`, so indices are stable and no
    /// outer lock is needed. Using per-element locks lets a probe/reporting
    /// mutation touch only the affected index in O(1) instead of cloning the
    /// entire Vec. Critical sections are short and never cross `.await`.
    pub(crate) statuses: Box<[SyncMutex<UplinkStatus>]>,
    pub(crate) active_uplinks: RwLock<ActiveUplinks>,
    pub(crate) sticky_routes: RwLock<HashMap<RoutingKey, StickyRoute>>,
    pub(crate) standby_pools: Vec<StandbyPool>,
    pub(crate) probe_execution_limit: Arc<Semaphore>,
    pub(crate) probe_dial_limit: Arc<Semaphore>,
    /// Notified when a runtime failure sets a fresh cooldown, so the probe
    /// loop wakes up immediately instead of waiting for the next interval.
    pub(crate) probe_wakeup: Arc<Notify>,
    /// Optional persistent state store.  When `Some`, active-uplink changes
    /// are flushed to disk so they survive process restarts.
    pub(crate) state_store: Option<Arc<StateStore>>,
    /// Shared DNS cache used by all transport resolve paths (probe, standby,
    /// reconnect). Owned at app scope by `AppConfig::dns_cache` and cloned
    /// into every manager at construction time.
    pub(crate) dns_cache: Arc<outline_transport::DnsCache>,
    /// Signals background loops (probe, warm-standby, keepalive) to stop.
    /// Call `shutdown_tx.send(true)` or use `UplinkManager::shutdown()`.
    pub(crate) shutdown_tx: watch::Sender<bool>,
}

impl UplinkManagerInner {
    /// Mutate a single uplink status under its own lock. Non-async: the
    /// critical section must not cross `.await`.
    pub(crate) fn with_status_mut<R>(
        &self,
        index: usize,
        f: impl FnOnce(&mut UplinkStatus) -> R,
    ) -> R {
        let mut guard = self.statuses[index].lock();
        f(&mut guard)
    }

    /// Read-only snapshot of a single uplink status.
    pub(crate) fn read_status(&self, index: usize) -> UplinkStatus {
        self.statuses[index].lock().clone()
    }

    /// Clone every uplink status into a flat Vec for multi-index iteration.
    /// Each element is cloned under its own lock, so the resulting Vec is
    /// eventually-consistent across indices (any single index is coherent).
    pub(crate) fn snapshot_statuses(&self) -> Vec<UplinkStatus> {
        self.statuses.iter().map(|m| m.lock().clone()).collect()
    }
}

/// All per-transport runtime state for a single uplink.
///
/// [`UplinkStatus`] holds one instance for TCP and one for UDP, eliminating
/// the previous flat `tcp_*/udp_*` field pairs and the accompanying
/// `match transport { Tcp => self.tcp_x, Udp => self.udp_x }` repetition.
/// Use [`UplinkStatus::of`] to select the right half by a [`TransportKind`] variable.
#[derive(Clone, Debug, Default)]
pub(crate) struct PerTransportStatus {
    pub(crate) healthy: Option<bool>,
    pub(crate) latency: Option<Duration>,
    pub(crate) rtt_ewma: Option<Duration>,
    pub(crate) penalty: PenaltyState,
    pub(crate) cooldown_until: Option<Instant>,
    pub(crate) consecutive_failures: u32,
    pub(crate) consecutive_successes: u32,
    /// Consecutive data-plane (runtime) failures observed by the dispatch
    /// path on this transport. Separate from `consecutive_failures`, which
    /// counts probe outcomes — runtime failures are noisier and should not
    /// share a counter with the authoritative probe signal. Used in strict
    /// global + probe-enabled mode to flip `healthy = Some(false)` after
    /// `probe.min_failures` consecutive runtime failures, without waiting
    /// for the next probe cycle.
    pub(crate) consecutive_runtime_failures: u32,
    /// When set, connections must use a lower-rank carrier than the
    /// configured one until this instant because the configured one
    /// (H3, raw QUIC, XHTTP-H3, XHTTP-H2) produced repeated transport
    /// errors. Cleared by a successful explicit H3 re-probe (WS path)
    /// or by natural TTL expiry (XHTTP path — no recovery probe).
    /// Always paired with [`Self::mode_downgrade_capped_to`]: either
    /// both are `Some` or both are `None`.
    pub(crate) mode_downgrade_until: Option<Instant>,
    /// Family-aware ceiling for the downgrade window — what
    /// `effective_*_mode` returns while [`Self::mode_downgrade_until`]
    /// is in the future. Set alongside the deadline so the
    /// reader does not need to know which family the configured mode
    /// belongs to (`WsH3` → `WsH2`, `XhttpH3` → `XhttpH2`,
    /// `XhttpH2` → `XhttpH1`, `Quic` → `WsH2`). Updates monotonically
    /// downward inside an active window: a second failure on the
    /// already-capped carrier (e.g. `XhttpH2` after a previous
    /// `XhttpH3` → `XhttpH2` cap) lowers the ceiling but never
    /// raises it, so multi-step downgrades preserve the deepest
    /// failure observed during the window.
    pub(crate) mode_downgrade_capped_to: Option<TransportMode>,
    /// Timestamp of the most recent real data transfer on this transport.
    /// Used to skip probe cycles when the uplink is actively carrying traffic.
    pub(crate) last_active: Option<Instant>,
    /// Timestamp of the most recent early probe wakeup caused by a runtime
    /// failure. Rate-limits wakeups to one per `PROBE_WAKEUP_MIN_INTERVAL`.
    pub(crate) last_probe_wakeup: Option<Instant>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UplinkStatus {
    pub(crate) tcp: PerTransportStatus,
    pub(crate) udp: PerTransportStatus,
    pub(crate) last_error: Option<String>,
    pub(crate) last_checked: Option<Instant>,
}

impl UplinkStatus {
    /// Borrow the per-transport status for the given transport kind.
    pub(crate) fn of(&self, kind: TransportKind) -> &PerTransportStatus {
        match kind {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PenaltyState {
    pub(crate) value_secs: f64,
    pub(crate) updated_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(crate) struct StickyRoute {
    pub(crate) uplink_index: usize,
    pub(crate) expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct UplinkCandidate {
    pub index: usize,
    pub uplink: Uplink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RoutingKey {
    Global,
    TransportGlobal(TransportKind),
    Target {
        transport: TransportKind,
        target: TargetAddr,
    },
    Default(TransportKind),
}

impl fmt::Display for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::TransportGlobal(transport) => {
                write!(f, "{}:global", transport_key_prefix(*transport))
            },
            Self::Target { transport, target } => {
                write!(f, "{}:{target}", transport_key_prefix(*transport))
            },
            Self::Default(transport) => write!(f, "{}:default", transport_key_prefix(*transport)),
        }
    }
}

// Snapshot data types live in the `outline-metrics` crate (they cross the
// producer/consumer boundary between the uplink manager here and the
// prometheus renderer); re-exported so existing `crate::uplink::*Snapshot`
// imports keep working.
pub use outline_metrics::{StickyRouteSnapshot, UplinkManagerSnapshot, UplinkSnapshot};

/// Deque guarded by an async `Mutex` that also maintains an `AtomicUsize`
/// length counter. The counter is refreshed on `Drop` of the lock guard so
/// observers that only need a size hint (e.g. `/metrics` scrapes) can read
/// it without contending with hot-path mutations.
pub(crate) struct TrackedDeque {
    deque: Mutex<VecDeque<TransportStream>>,
    len: AtomicUsize,
}

impl TrackedDeque {
    pub(crate) fn new() -> Self {
        Self {
            deque: Mutex::new(VecDeque::new()),
            len: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn lock(&self) -> TrackedDequeGuard<'_> {
        TrackedDequeGuard {
            guard: self.deque.lock().await,
            len: &self.len,
        }
    }

    pub(crate) fn len_hint(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }
}

pub(crate) struct TrackedDequeGuard<'a> {
    guard: tokio::sync::MutexGuard<'a, VecDeque<TransportStream>>,
    len: &'a AtomicUsize,
}

impl Deref for TrackedDequeGuard<'_> {
    type Target = VecDeque<TransportStream>;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for TrackedDequeGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for TrackedDequeGuard<'_> {
    fn drop(&mut self) {
        self.len.store(self.guard.len(), Ordering::Relaxed);
    }
}

pub(crate) struct StandbyPool {
    pub(crate) tcp: TrackedDeque,
    pub(crate) udp: TrackedDeque,
    pub(crate) tcp_refill: Mutex<()>,
    pub(crate) udp_refill: Mutex<()>,
}

impl StandbyPool {
    pub(crate) fn new() -> Self {
        Self {
            tcp: TrackedDeque::new(),
            udp: TrackedDeque::new(),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProbeOutcome {
    pub(crate) tcp_ok: bool,
    /// false when the uplink has no `udp_ws_url` — means "UDP not applicable",
    /// not "UDP probe failed".  Health and standby tracking are skipped in
    /// this case so that Grafana shows empty (unknown) rather than red (0).
    pub(crate) udp_ok: bool,
    pub(crate) udp_applicable: bool,
    pub(crate) tcp_latency: Option<Duration>,
    pub(crate) udp_latency: Option<Duration>,
    /// `Some(requested)` when any TCP probe sub-attempt produced a stream
    /// at a lower mode than asked for (host-level `ws_mode_cache` clamp or
    /// inline H3→H2/H1 fallback inside `connect_websocket_with_resume`).
    /// `None` when the dial path matched the requested mode. Surfaced from
    /// the probe layer so the manager mirrors the downgrade into the
    /// per-uplink `mode_downgrade_until` window even when the probe itself
    /// succeeded — without this, `effective_*_ws_mode` would silently lag
    /// behind the actual transport state.
    pub(crate) tcp_downgraded_from: Option<crate::config::TransportMode>,
    pub(crate) udp_downgraded_from: Option<crate::config::TransportMode>,
}

#[derive(Clone)]
pub(crate) struct CandidateState {
    pub(crate) index: usize,
    pub(crate) uplink: Uplink,
    pub(crate) healthy: bool,
    pub(crate) score: Option<Duration>,
    pub(crate) status: UplinkStatus,
}
