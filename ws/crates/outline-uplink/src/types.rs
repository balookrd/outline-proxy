use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};
use outline_transport::WsTransportStream;
use socks5_proto::TargetAddr;

use super::state::StateStore;
use super::utils::transport_key_prefix;

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
    /// Per-transport TCP active index (used in `strict_per_uplink` mode).
    pub(crate) tcp: Option<usize>,
    /// Per-transport UDP active index (used in `strict_per_uplink` mode).
    pub(crate) udp: Option<usize>,
}

pub(crate) struct UplinkManagerInner {
    /// Name of the group this manager represents. Surfaced as the `group`
    /// Prometheus label on every uplink-scoped metric emitted from within.
    pub(crate) group_name: String,
    pub(crate) uplinks: Vec<Arc<UplinkConfig>>,
    pub(crate) probe: ProbeConfig,
    pub(crate) load_balancing: LoadBalancingConfig,
    pub(crate) statuses: RwLock<Arc<Vec<UplinkStatus>>>,
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
}

impl UplinkManagerInner {
    /// Clone-modify-replace: the only correct way to mutate statuses.
    /// Clones the current Vec, applies `f`, wraps in a new Arc.
    /// Callers never mutate through an Arc (which would be shared), only
    /// through the owned clone.
    pub(crate) async fn modify_statuses<F>(&self, f: F)
    where
        F: FnOnce(&mut Vec<UplinkStatus>),
    {
        let mut lock = self.statuses.write().await;
        let mut new = (**lock).clone();
        f(&mut new);
        *lock = Arc::new(new);
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
    /// When set, connections must use H2 instead of H3 until this instant
    /// because H3 produced repeated APPLICATION_CLOSE or other transport
    /// errors. Cleared by a successful explicit H3 re-probe.
    pub(crate) h3_downgrade_until: Option<Instant>,
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
    pub uplink: Arc<UplinkConfig>,
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


pub(crate) struct StandbyPool {
    pub(crate) tcp: Mutex<VecDeque<WsTransportStream>>,
    pub(crate) udp: Mutex<VecDeque<WsTransportStream>>,
    pub(crate) tcp_refill: Mutex<()>,
    pub(crate) udp_refill: Mutex<()>,
}

impl StandbyPool {
    pub(crate) fn new() -> Self {
        Self {
            tcp: Mutex::new(VecDeque::new()),
            udp: Mutex::new(VecDeque::new()),
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
}

#[derive(Clone)]
pub(crate) struct CandidateState {
    pub(crate) index: usize,
    pub(crate) uplink: Arc<UplinkConfig>,
    pub(crate) healthy: bool,
    pub(crate) score: Option<Duration>,
}
