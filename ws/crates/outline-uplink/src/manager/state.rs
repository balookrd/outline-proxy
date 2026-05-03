//! [`UplinkManager`] runtime container: per-uplink statuses, active-uplink
//! selection, sticky routes, standby pools, probe-wakeup signal, and the
//! shutdown channel that feeds every background loop owned by this manager.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex as SyncMutex;
use tokio::sync::{Notify, RwLock, Semaphore, watch};

use crate::config::{LoadBalancingConfig, ProbeConfig};
use crate::routing_key::RoutingKey;
use crate::state::StateStore;
use crate::types::Uplink;

use super::standby_pool::StandbyPool;
use super::status::UplinkStatus;
use super::sticky::StickyRoute;

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
