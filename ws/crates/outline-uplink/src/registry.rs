//! `UplinkRegistry` — a collection of per-group [`UplinkManager`]s.
//!
//! Each group has its own probe loop, standby pools, sticky routes,
//! active-uplink trackers, and load-balancing config; nothing is shared
//! between groups except through this registry.
//!
//! ## Hot-swap
//!
//! The internal list of groups lives behind an [`ArcSwap`] so that a call
//! to [`UplinkRegistry::apply_new_groups`] replaces the managers without
//! invalidating clones held elsewhere (proxy accept loop, TUN routing,
//! metrics/control servers). Old background loops are stopped via the
//! per-manager shutdown watch; in-flight traffic using an old manager
//! clone finishes naturally because the manager is kept alive by the
//! caller's `Arc` until the last reference drops.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use tracing::info;

use crate::config::UplinkGroupConfig;

use super::state::StateStore;
use super::types::{TransportKind, UplinkManager, UplinkManagerSnapshot};

/// A named [`UplinkManager`].
#[derive(Clone, Debug)]
pub struct UplinkGroupHandle {
    pub name: String,
    pub manager: UplinkManager,
}

/// Immutable snapshot of the registry's group list. Swapped atomically by
/// [`UplinkRegistry::apply_new_groups`].
struct RegistryState {
    groups: Vec<UplinkGroupHandle>,
    by_name: HashMap<String, usize>,
}

/// Cheaply-clonable handle to the current group list. All clones share the
/// same [`ArcSwap`], so a hot-swap is visible to every holder.
#[derive(Clone)]
pub struct UplinkRegistry {
    state: Arc<ArcSwap<RegistryState>>,
}

impl std::fmt::Debug for UplinkRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.load();
        f.debug_struct("UplinkRegistry")
            .field("groups", &state.groups.len())
            .finish()
    }
}

impl UplinkRegistry {
    pub fn new(
        groups: Vec<UplinkGroupConfig>,
        dns_cache: Arc<outline_transport::DnsCache>,
    ) -> Result<Self> {
        let state = build_state(groups, None, dns_cache, None)?;
        Ok(Self { state: Arc::new(ArcSwap::from_pointee(state)) })
    }

    /// Like [`Self::new`] but restores active-uplink selection from `state_store`
    /// (loaded by the caller) and wires it for future persistence.
    pub async fn new_with_state(
        groups: Vec<UplinkGroupConfig>,
        state_store: Option<Arc<StateStore>>,
        dns_cache: Arc<outline_transport::DnsCache>,
    ) -> Result<Self> {
        // Resolve persisted names up-front so the build step does not have
        // to be async.
        let mut restored: Vec<(Option<String>, Option<String>, Option<String>)> =
            Vec::with_capacity(groups.len());
        if let Some(store) = &state_store {
            for group in &groups {
                let gs = store.group_state(&group.name).await;
                restored.push((gs.global_active, gs.tcp_active, gs.udp_active));
            }
        } else {
            restored.resize(groups.len(), (None, None, None));
        }
        let state = build_state(groups, Some(restored), dns_cache, state_store)?;
        Ok(Self { state: Arc::new(ArcSwap::from_pointee(state)) })
    }

    /// The first-declared group. Callers that have not yet been taught to
    /// dispatch through the routing table (proxy, TUN, metrics) rely on
    /// this as the default.
    pub fn default_group(&self) -> UplinkManager {
        self.state.load().groups[0].manager.clone()
    }

    pub fn default_group_name(&self) -> String {
        self.state.load().groups[0].name.clone()
    }

    pub fn group_by_name(&self, name: &str) -> Option<UplinkManager> {
        let state = self.state.load();
        state.by_name.get(name).map(|&i| state.groups[i].manager.clone())
    }

    /// Clone the current group list. The returned `Vec` is a snapshot —
    /// subsequent swaps are not reflected in it.
    pub fn groups(&self) -> Vec<UplinkGroupHandle> {
        self.state.load().groups.clone()
    }

    pub fn group_count(&self) -> usize {
        self.state.load().groups.len()
    }

    pub fn total_uplinks(&self) -> usize {
        self.state.load().groups.iter().map(|g| g.manager.uplinks().len()).sum()
    }

    /// Prime strict active-uplink selection for every group (noop for
    /// per-flow / non-strict modes, handled inside each manager).
    pub async fn initialize_strict_active_selection(&self) {
        let groups = self.state.load().groups.clone();
        for group in &groups {
            group.manager.initialize_strict_active_selection().await;
        }
    }

    /// Spawn one probe loop task per group. Each loop honours its own
    /// probe interval, semaphore sizes, and wakeup notifier.
    pub fn spawn_probe_loops(&self) {
        for group in self.state.load().groups.iter() {
            group.manager.spawn_probe_loop();
        }
    }

    pub fn spawn_warm_standby_loops(&self) {
        for group in self.state.load().groups.iter() {
            group.manager.spawn_warm_standby_loop();
        }
    }

    pub fn spawn_standby_keepalive_loops(&self) {
        for group in self.state.load().groups.iter() {
            group.manager.spawn_standby_keepalive_loop();
        }
    }

    pub fn spawn_sticky_prune_loops(&self) {
        for group in self.state.load().groups.iter() {
            group.manager.spawn_sticky_prune_loop();
        }
    }

    /// Spawn a single process-wide sweeper for the H2/H3 shared-connection
    /// caches. Independent of warm-standby so that groups with
    /// `warm_standby_tcp = warm_standby_udp = 0` still get stale entries
    /// evicted (otherwise soft-closed/DNS-rotated connections hold FDs open).
    pub fn spawn_shared_connection_gc_loop(&self) {
        let mut shutdown = self.state.load().groups[0].manager.shutdown_rx();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
                }
                outline_transport::gc_shared_connections().await;
            }
        });
    }

    /// Cancel all background loops (probe, warm-standby, keepalive) for every
    /// group. Call this before dropping a registry on full process shutdown
    /// so old tasks do not outlive the registry they were spawned from.
    pub fn shutdown(&self) {
        for group in self.state.load().groups.iter() {
            group.manager.shutdown();
        }
    }

    /// Manually switch the active uplink identified by `uplink_name`. When
    /// `group` is `Some`, only that group is considered; otherwise all groups
    /// are searched (uplink names are globally unique across groups).
    pub async fn set_active_uplink_by_name(
        &self,
        group: Option<&str>,
        uplink_name: &str,
        transport: Option<TransportKind>,
    ) -> Result<(String, usize)> {
        let state = self.state.load();
        let manager: UplinkManager = if let Some(g) = group {
            state
                .by_name
                .get(g)
                .map(|&i| state.groups[i].manager.clone())
                .ok_or_else(|| anyhow::anyhow!("uplink group \"{}\" not found", g))?
        } else {
            state
                .groups
                .iter()
                .find(|h| h.manager.uplinks().iter().any(|u| u.name == uplink_name))
                .map(|h| h.manager.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("uplink \"{}\" not found in any group", uplink_name)
                })?
        };
        let index = manager.set_active_uplink_by_name(uplink_name, transport).await?;
        Ok((manager.group_name().to_string(), index))
    }

    /// Snapshot each group for Prometheus rendering. The returned vector
    /// preserves declaration order, matching the `groups` view.
    pub async fn snapshots(&self) -> Vec<UplinkManagerSnapshot> {
        let groups = self.state.load().groups.clone();
        let mut out = Vec::with_capacity(groups.len());
        for group in &groups {
            out.push(group.manager.snapshot().await);
        }
        out
    }

    /// Replace the group list with freshly-built managers. Spawns the
    /// standard background loops for the new managers *before* the swap
    /// so that every group remains observable throughout, and sends the
    /// shutdown signal to the displaced managers afterwards.
    ///
    /// Existing callers that hold [`UplinkManager`] clones (in-flight
    /// traffic) continue to use the old manager until they drop their
    /// clones; no connection is torn down by this call.
    ///
    /// `dns_cache` and `state_store` must match the values the registry
    /// was originally built with, so that persistence and DNS caching
    /// stay consistent across swaps.
    pub async fn apply_new_groups(
        &self,
        groups: Vec<UplinkGroupConfig>,
        dns_cache: Arc<outline_transport::DnsCache>,
        state_store: Option<Arc<StateStore>>,
    ) -> Result<()> {
        // Resolve persisted active-uplink names for the new groups.
        let mut restored: Vec<(Option<String>, Option<String>, Option<String>)> =
            Vec::with_capacity(groups.len());
        if let Some(store) = &state_store {
            for group in &groups {
                let gs = store.group_state(&group.name).await;
                restored.push((gs.global_active, gs.tcp_active, gs.udp_active));
            }
        } else {
            restored.resize(groups.len(), (None, None, None));
        }

        let new_state = build_state(groups, Some(restored), dns_cache, state_store)?;

        // Spawn background loops for the new managers first. If this were
        // reordered after the swap, a small window would exist where no
        // probes run for anyone — readers loading during that window would
        // see the new managers but with empty health state.
        for group in &new_state.groups {
            group.manager.spawn_probe_loop();
            group.manager.spawn_warm_standby_loop();
            group.manager.spawn_standby_keepalive_loop();
            group.manager.spawn_sticky_prune_loop();
        }
        // Prime strict active-uplink selection on the new managers.
        for group in &new_state.groups {
            group.manager.initialize_strict_active_selection().await;
        }

        // Atomic swap. Any holder of an `UplinkRegistry` clone sees the new
        // state on its next `.state.load()`.
        let old = self.state.swap(Arc::new(new_state));

        // Tell the displaced managers to stop their loops. In-flight traffic
        // using an already-borrowed `UplinkManager` clone will finish
        // naturally; only background loops are interrupted.
        for group in old.groups.iter() {
            group.manager.shutdown();
        }
        Ok(())
    }
}

fn build_state(
    groups: Vec<UplinkGroupConfig>,
    // Per-group (global, tcp, udp) persisted active-uplink names. `None`
    // means "no state_store attached"; element-wise `None`s mean "no
    // persisted value for this group" and are equivalent to fresh start.
    restored: Option<Vec<(Option<String>, Option<String>, Option<String>)>>,
    dns_cache: Arc<outline_transport::DnsCache>,
    state_store: Option<Arc<StateStore>>,
) -> Result<RegistryState> {
    if groups.is_empty() {
        bail!("no uplink groups configured");
    }
    validate_uplink_names(&groups)?;

    let mut by_name = HashMap::with_capacity(groups.len());
    let mut managed = Vec::with_capacity(groups.len());
    for (index, group) in groups.into_iter().enumerate() {
        if by_name.insert(group.name.clone(), index).is_some() {
            bail!("duplicate uplink group name \"{}\"", group.name);
        }
        let (init_global, init_tcp, init_udp) = match &restored {
            Some(v) => v.get(index).cloned().unwrap_or((None, None, None)),
            None => (None, None, None),
        };
        let manager = UplinkManager::new_with_state(
            group.name.clone(),
            group.uplinks,
            group.probe,
            group.load_balancing,
            Arc::clone(&dns_cache),
            state_store.clone(),
            init_global,
            init_tcp,
            init_udp,
        )?;
        managed.push(UplinkGroupHandle { name: group.name, manager });
    }
    Ok(RegistryState { groups: managed, by_name })
}

impl UplinkRegistry {
    /// Test-only ctor that supplies a fresh throwaway DnsCache.
    pub fn new_for_test(groups: Vec<UplinkGroupConfig>) -> Result<Self> {
        Self::new(groups, Arc::new(outline_transport::DnsCache::default()))
    }

    /// Test-only helper: build a registry wrapping a single pre-constructed
    /// [`UplinkManager`] under its own group name. Lets TUN / proxy tests
    /// that already hand-build an `UplinkManager` stand up a minimal
    /// [`UplinkRegistry`] for `outline_tun::TunRouting` without going
    /// through `UplinkGroupConfig`.
    pub fn from_single_manager(manager: UplinkManager) -> Self {
        let name = manager.group_name().to_string();
        let mut by_name = std::collections::HashMap::new();
        by_name.insert(name.clone(), 0);
        let state = RegistryState {
            groups: vec![UplinkGroupHandle { name, manager }],
            by_name,
        };
        Self { state: Arc::new(ArcSwap::from_pointee(state)) }
    }
}

/// Reject duplicate uplink names across all groups.
///
/// Uplink names must be globally unique so that Prometheus `uplink="…"` labels
/// remain unambiguous. Called by both [`UplinkRegistry::new`] and
/// [`UplinkRegistry::new_with_state`] to keep the check in one place.
fn validate_uplink_names(groups: &[UplinkGroupConfig]) -> Result<()> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for group in groups {
        for uplink in &group.uplinks {
            if let Some(other_group) = seen.insert(uplink.name.clone(), group.name.clone()) {
                bail!(
                    "uplink name \"{}\" is used in both groups \"{}\" and \"{}\"; \
                     uplink names must be globally unique",
                    uplink.name,
                    other_group,
                    group.name
                );
            }
        }
    }
    Ok(())
}

pub fn log_registry_summary(registry: &UplinkRegistry) {
    let groups = registry.groups();
    info!(
        groups = groups.len(),
        total_uplinks = registry.total_uplinks(),
        default_group = %registry.default_group_name(),
        "uplink registry initialized"
    );
    for group in &groups {
        super::manager::log_uplink_summary_named(&group.manager, &group.name);
    }
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
