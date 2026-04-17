use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};
use crate::transport::AnyWsStream;
use crate::types::TargetAddr;

use super::state::StateStore;
use super::utils::transport_key_prefix;

#[derive(Clone)]
pub struct UplinkManager {
    pub(super) inner: Arc<UplinkManagerInner>,
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
pub(super) struct ActiveUplinks {
    /// Global active index (used in `strict_global_active` mode).
    pub(super) global: Option<usize>,
    /// Per-transport TCP active index (used in `strict_per_uplink` mode).
    pub(super) tcp: Option<usize>,
    /// Per-transport UDP active index (used in `strict_per_uplink` mode).
    pub(super) udp: Option<usize>,
}

pub(super) struct UplinkManagerInner {
    /// Name of the group this manager represents. Surfaced as the `group`
    /// Prometheus label on every uplink-scoped metric emitted from within.
    pub(super) group_name: String,
    pub(super) uplinks: Vec<Arc<UplinkConfig>>,
    pub(super) probe: ProbeConfig,
    pub(super) load_balancing: LoadBalancingConfig,
    pub(super) statuses: RwLock<Vec<UplinkStatus>>,
    pub(super) active_uplinks: RwLock<ActiveUplinks>,
    pub(super) sticky_routes: RwLock<HashMap<RoutingKey, StickyRoute>>,
    pub(super) standby_pools: Vec<StandbyPool>,
    pub(super) probe_execution_limit: Arc<Semaphore>,
    pub(super) probe_dial_limit: Arc<Semaphore>,
    /// Notified when a runtime failure sets a fresh cooldown, so the probe
    /// loop wakes up immediately instead of waiting for the next interval.
    pub(super) probe_wakeup: Arc<Notify>,
    /// Optional persistent state store.  When `Some`, active-uplink changes
    /// are flushed to disk so they survive process restarts.
    pub(super) state_store: Option<Arc<StateStore>>,
}

/// All per-transport runtime state for a single uplink.
///
/// [`UplinkStatus`] holds one instance for TCP and one for UDP, eliminating
/// the previous flat `tcp_*/udp_*` field pairs and the accompanying
/// `match transport { Tcp => self.tcp_x, Udp => self.udp_x }` repetition.
/// Use [`UplinkStatus::of`] to select the right half by a [`TransportKind`] variable.
#[derive(Clone, Debug, Default)]
pub(super) struct PerTransportStatus {
    pub(super) healthy: Option<bool>,
    pub(super) latency: Option<Duration>,
    pub(super) rtt_ewma: Option<Duration>,
    pub(super) penalty: PenaltyState,
    pub(super) cooldown_until: Option<Instant>,
    pub(super) consecutive_failures: u32,
    pub(super) consecutive_successes: u32,
    /// When set, connections must use H2 instead of H3 until this instant
    /// because H3 produced repeated APPLICATION_CLOSE or other transport
    /// errors. Cleared by a successful explicit H3 re-probe.
    pub(super) h3_downgrade_until: Option<Instant>,
    /// Timestamp of the most recent real data transfer on this transport.
    /// Used to skip probe cycles when the uplink is actively carrying traffic.
    pub(super) last_active: Option<Instant>,
    /// Timestamp of the most recent early probe wakeup caused by a runtime
    /// failure. Rate-limits wakeups to one per `PROBE_WAKEUP_MIN_INTERVAL`.
    pub(super) last_probe_wakeup: Option<Instant>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct UplinkStatus {
    pub(super) tcp: PerTransportStatus,
    pub(super) udp: PerTransportStatus,
    pub(super) last_error: Option<String>,
    pub(super) last_checked: Option<Instant>,
}

impl UplinkStatus {
    /// Borrow the per-transport status for the given transport kind.
    pub(super) fn of(&self, kind: TransportKind) -> &PerTransportStatus {
        match kind {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }

}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PenaltyState {
    pub(super) value_secs: f64,
    pub(super) updated_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct StickyRoute {
    pub(super) uplink_index: usize,
    pub(super) expires_at: Instant,
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
pub(super) enum RoutingKey {
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

#[derive(Debug, Clone, Serialize)]
pub struct UplinkManagerSnapshot {
    /// Group this snapshot was generated for. Surfaced as the `group`
    /// Prometheus label on snapshot-rendered metrics.
    pub group: String,
    pub generated_at_unix_ms: u128,
    pub load_balancing_mode: String,
    pub routing_scope: String,
    pub global_active_uplink: Option<String>,
    /// Active uplink for TCP in per_uplink routing scope.
    pub tcp_active_uplink: Option<String>,
    /// Active uplink for UDP in per_uplink routing scope.
    pub udp_active_uplink: Option<String>,
    pub uplinks: Vec<UplinkSnapshot>,
    pub sticky_routes: Vec<StickyRouteSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkSnapshot {
    pub index: usize,
    pub name: String,
    /// Name of the uplink group this entry belongs to. Emitted as the
    /// `group` Prometheus label alongside `uplink`.
    pub group: String,
    pub weight: f64,
    pub tcp_healthy: Option<bool>,
    pub udp_healthy: Option<bool>,
    pub tcp_latency_ms: Option<u128>,
    pub udp_latency_ms: Option<u128>,
    pub tcp_rtt_ewma_ms: Option<u128>,
    pub udp_rtt_ewma_ms: Option<u128>,
    pub tcp_penalty_ms: Option<u128>,
    pub udp_penalty_ms: Option<u128>,
    pub tcp_effective_latency_ms: Option<u128>,
    pub udp_effective_latency_ms: Option<u128>,
    pub tcp_score_ms: Option<u128>,
    pub udp_score_ms: Option<u128>,
    pub cooldown_tcp_ms: Option<u128>,
    pub cooldown_udp_ms: Option<u128>,
    pub last_checked_ago_ms: Option<u128>,
    pub last_error: Option<String>,
    pub standby_tcp_ready: usize,
    pub standby_udp_ready: usize,
    pub tcp_consecutive_failures: u32,
    pub udp_consecutive_failures: u32,
    pub h3_tcp_downgrade_until_ms: Option<u128>,
    pub h3_udp_downgrade_until_ms: Option<u128>,
    pub last_active_tcp_ago_ms: Option<u128>,
    pub last_active_udp_ago_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StickyRouteSnapshot {
    pub key: String,
    pub uplink_index: usize,
    pub uplink_name: String,
    pub expires_in_ms: u128,
}


pub(super) struct StandbyPool {
    pub(super) tcp: Mutex<VecDeque<AnyWsStream>>,
    pub(super) udp: Mutex<VecDeque<AnyWsStream>>,
    pub(super) tcp_refill: Mutex<()>,
    pub(super) udp_refill: Mutex<()>,
}

impl StandbyPool {
    pub(super) fn new() -> Self {
        Self {
            tcp: Mutex::new(VecDeque::new()),
            udp: Mutex::new(VecDeque::new()),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProbeOutcome {
    pub(super) tcp_ok: bool,
    /// false when the uplink has no `udp_ws_url` — means "UDP not applicable",
    /// not "UDP probe failed".  Health and standby tracking are skipped in
    /// this case so that Grafana shows empty (unknown) rather than red (0).
    pub(super) udp_ok: bool,
    pub(super) udp_applicable: bool,
    pub(super) tcp_latency: Option<Duration>,
    pub(super) udp_latency: Option<Duration>,
}

#[derive(Clone)]
pub(super) struct CandidateState {
    pub(super) index: usize,
    pub(super) uplink: Arc<UplinkConfig>,
    pub(super) healthy: bool,
    pub(super) score: Option<Duration>,
}
