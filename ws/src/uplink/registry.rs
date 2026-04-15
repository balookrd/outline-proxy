//! `UplinkRegistry` — a collection of per-group [`UplinkManager`]s.
//!
//! Each group has its own probe loop, standby pools, sticky routes,
//! active-uplink trackers, and load-balancing config; nothing is shared
//! between groups except through this registry.
//!
//! Until the routing integration lands (etap 5), proxy/TUN call sites still
//! operate on a single [`UplinkManager`] handle — [`UplinkRegistry::default_group`]
//! returns the first configured group and is what lib.rs hands out.

use std::collections::HashMap;

use anyhow::{Result, bail};
use tracing::info;

use crate::config::UplinkGroupConfig;

use super::types::{UplinkManager, UplinkManagerSnapshot};

/// A named [`UplinkManager`].
#[derive(Clone)]
pub struct UplinkGroup {
    pub name: String,
    pub manager: UplinkManager,
}

#[derive(Clone)]
pub struct UplinkRegistry {
    groups: Vec<UplinkGroup>,
    by_name: HashMap<String, usize>,
}

impl UplinkRegistry {
    pub fn new(groups: Vec<UplinkGroupConfig>) -> Result<Self> {
        if groups.is_empty() {
            bail!("no uplink groups configured");
        }
        // Reject collisions on uplink names across groups so that Prometheus
        // labels (`uplink="…"`) remain unambiguous until etap 6 adds a `group`
        // label.
        let mut seen_uplink_names: HashMap<String, String> = HashMap::new();
        for group in &groups {
            for uplink in &group.uplinks {
                if let Some(other_group) =
                    seen_uplink_names.insert(uplink.name.clone(), group.name.clone())
                {
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

        let mut by_name = HashMap::with_capacity(groups.len());
        let mut managed = Vec::with_capacity(groups.len());
        for (index, group) in groups.into_iter().enumerate() {
            if by_name.insert(group.name.clone(), index).is_some() {
                bail!("duplicate uplink group name \"{}\"", group.name);
            }
            let manager = UplinkManager::new(
                group.name.clone(),
                group.uplinks,
                group.probe,
                group.load_balancing,
            )?;
            managed.push(UplinkGroup { name: group.name, manager });
        }
        Ok(Self { groups: managed, by_name })
    }

    /// The first-declared group, used by callers that have not yet been taught
    /// to dispatch through the routing table (proxy, TUN, metrics).
    pub fn default_group(&self) -> &UplinkManager {
        &self.groups[0].manager
    }

    pub fn default_group_name(&self) -> &str {
        &self.groups[0].name
    }

    pub fn group_by_name(&self, name: &str) -> Option<&UplinkManager> {
        self.by_name.get(name).map(|&i| &self.groups[i].manager)
    }

    pub fn groups(&self) -> &[UplinkGroup] {
        &self.groups
    }

    pub fn total_uplinks(&self) -> usize {
        self.groups.iter().map(|g| g.manager.uplinks().len()).sum()
    }

    /// Prime strict active-uplink selection for every group (noop for
    /// per-flow / non-strict modes, handled inside each manager).
    pub async fn initialize_strict_active_selection(&self) {
        for group in &self.groups {
            group.manager.initialize_strict_active_selection().await;
        }
    }

    /// Spawn one probe loop task per group. Each loop honours its own
    /// probe interval, semaphore sizes, and wakeup notifier.
    pub fn spawn_probe_loops(&self) {
        for group in &self.groups {
            group.manager.spawn_probe_loop();
        }
    }

    pub fn spawn_warm_standby_loops(&self) {
        for group in &self.groups {
            group.manager.spawn_warm_standby_loop();
        }
    }

    pub fn spawn_standby_keepalive_loops(&self) {
        for group in &self.groups {
            group.manager.spawn_standby_keepalive_loop();
        }
    }

    /// Snapshot each group for Prometheus rendering. The returned vector
    /// preserves declaration order, matching the `groups` view.
    pub async fn snapshots(&self) -> Vec<UplinkManagerSnapshot> {
        let mut out = Vec::with_capacity(self.groups.len());
        for group in &self.groups {
            out.push(group.manager.snapshot().await);
        }
        out
    }
}

pub fn log_registry_summary(registry: &UplinkRegistry) {
    info!(
        groups = registry.groups().len(),
        total_uplinks = registry.total_uplinks(),
        default_group = registry.default_group_name(),
        "uplink registry initialized"
    );
    for group in registry.groups() {
        super::manager::log_uplink_summary_named(&group.manager, &group.name);
    }
}
