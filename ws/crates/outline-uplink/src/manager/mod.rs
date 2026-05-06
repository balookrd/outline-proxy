pub(crate) mod active_wire;
pub(crate) mod candidates;
mod failures;
mod mode_downgrade;
pub(crate) mod probe;
mod reporting;
mod snapshot;
pub(crate) mod standby;
pub(crate) mod standby_pool;
pub(crate) mod state;
pub(crate) mod status;
pub(crate) mod sticky;
#[cfg(any(test, feature = "test-helpers"))]
#[path = "tests/test_helpers.rs"]
mod test_helpers;

pub(crate) use reporting::log_uplink_summary_named;
pub use reporting::deduplicate_attempted_uplink_names;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::sync::{watch, Notify, RwLock, Semaphore};

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};

use super::state::StateStore;
use super::types::{TransportKind, Uplink, UplinkManager};
use self::standby_pool::StandbyPool;
use self::state::{ActiveUplinks, UplinkManagerInner};
use self::status::UplinkStatus;

impl UplinkManager {
    pub async fn initialize_strict_active_selection(&self) {
        if !self.strict_global_active_uplink() && !self.strict_per_uplink_active_uplink() {
            return;
        }

        // Prime initial health before any client traffic arrives so the first
        // strict active-uplink choice is deterministic and probe-driven rather
        // than depending on which session wins the startup race.
        //
        // Skip the blocking probe when a persisted active-uplink selection was
        // restored from the state store — the selection is already deterministic
        // and the background probe loop (spawn_probe_loops) will validate it
        // shortly after startup.  Blocking here in that case only delays the
        // point at which the listener starts accepting traffic.
        if self.inner.probe.enabled() {
            let already_selected = if self.strict_global_active_uplink() {
                self.global_active_uplink_index().await.is_some()
            } else {
                self.active_uplink_index_for_transport(TransportKind::Tcp)
                    .await
                    .is_some()
                    || self
                        .active_uplink_index_for_transport(TransportKind::Udp)
                        .await
                        .is_some()
            };
            if !already_selected {
                self.probe_all().await;
            }
        }

        if self.strict_global_active_uplink() {
            if self.global_active_uplink_index().await.is_none() {
                let _ = self
                    .strict_transport_candidates(TransportKind::Tcp, None, None, true)
                    .await;
            }
            return;
        }

        if self
            .active_uplink_index_for_transport(TransportKind::Tcp)
            .await
            .is_none()
        {
            let _ = self
                .strict_transport_candidates(TransportKind::Tcp, None, None, true)
                .await;
        }
        if self
            .active_uplink_index_for_transport(TransportKind::Udp)
            .await
            .is_none()
        {
            let _ = self
                .strict_transport_candidates(TransportKind::Udp, None, None, true)
                .await;
        }
    }

    pub fn new(
        group_name: impl Into<String>,
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
        dns_cache: Arc<outline_transport::DnsCache>,
    ) -> Result<Self> {
        Self::new_with_state(
            group_name,
            uplinks,
            probe,
            load_balancing,
            dns_cache,
            None,
            None,
            None,
            None,
        )
    }

    /// Like [`Self::new`] but also accepts a [`StateStore`] for persistence and
    /// optional initial active-uplink names to restore from a previous run.
    /// Names that no longer match any configured uplink are silently ignored.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_state(
        group_name: impl Into<String>,
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
        dns_cache: Arc<outline_transport::DnsCache>,
        state_store: Option<Arc<StateStore>>,
        initial_global_active: Option<String>,
        initial_tcp_active: Option<String>,
        initial_udp_active: Option<String>,
    ) -> Result<Self> {
        if uplinks.is_empty() {
            bail!("at least one uplink must be configured");
        }

        let count = uplinks.len();
        let probe_max_concurrent = probe.max_concurrent;
        let probe_max_dials = probe.max_dials;
        let uplinks: Vec<Uplink> = uplinks.into_iter().map(Uplink::new).collect();
        let (shutdown_tx, _) = watch::channel(false);

        // Resolve persisted names to indices.  Unknown names are ignored so
        // that removing an uplink from config doesn't block startup.
        let find = |name: Option<String>| -> Option<usize> {
            name.and_then(|n| uplinks.iter().position(|u| u.name == n))
        };
        let initial_global = find(initial_global_active);
        let initial_tcp = find(initial_tcp_active);
        let initial_udp = find(initial_udp_active);
        let active_uplinks = RwLock::new(ActiveUplinks {
            global: initial_global,
            global_reason: initial_global.map(|_| "restored from state".to_string()),
            tcp: initial_tcp,
            tcp_reason: initial_tcp.map(|_| "restored from state".to_string()),
            udp: initial_udp,
            udp_reason: initial_udp.map(|_| "restored from state".to_string()),
        });
        Ok(Self {
            inner: Arc::new(UplinkManagerInner {
                group_name: group_name.into(),
                uplinks,
                probe,
                load_balancing,
                statuses: (0..count)
                    .map(|_| parking_lot::Mutex::new(UplinkStatus::default()))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                probe_warm_udp: (0..count)
                    .map(|_| self::probe::warm_udp::new_slot())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                probe_warm_tcp: (0..count)
                    .map(|_| self::probe::warm_tcp::new_slot())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                active_uplinks,
                sticky_routes: RwLock::new(HashMap::new()),
                standby_pools: (0..count).map(|_| StandbyPool::new()).collect(),
                probe_execution_limit: Arc::new(Semaphore::new(probe_max_concurrent)),
                probe_dial_limit: Arc::new(Semaphore::new(probe_max_dials)),
                probe_wakeup: Arc::new(Notify::new()),
                state_store,
                dns_cache,
                shutdown_tx,
            }),
        })
    }

    /// Name of the group this manager represents. Used as the `group`
    /// Prometheus label at metric emission sites.
    pub fn group_name(&self) -> &str {
        &self.inner.group_name
    }

    /// Signal all background loops spawned by this manager to stop.
    /// Called by the owner (registry or application) on config reload or shutdown.
    pub fn shutdown(&self) {
        let _ = self.inner.shutdown_tx.send(true);
    }

    pub(crate) fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.inner.shutdown_tx.subscribe()
    }

    /// Shared DNS cache used by every transport resolve path belonging to
    /// this manager (probe, standby refills, on-demand TCP/UDP connects).
    pub fn dns_cache(&self) -> &outline_transport::DnsCache {
        &self.inner.dns_cache
    }

    pub fn uplinks(&self) -> &[Uplink] {
        &self.inner.uplinks
    }

    /// Expose this group's load-balancing config so the dispatch layer can
    /// honour per-group timeouts / keepalives without reaching into private
    /// internals.
    pub fn load_balancing(&self) -> &LoadBalancingConfig {
        &self.inner.load_balancing
    }

    /// Expose this group's probe config (used by startup warnings that need
    /// to inspect configured probe targets).
    pub fn probe_config(&self) -> &ProbeConfig {
        &self.inner.probe
    }
}
