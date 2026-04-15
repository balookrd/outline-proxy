mod candidates;
mod probe_loop;
mod reporting;
mod standby;
mod sticky;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::sync::{Notify, RwLock, Semaphore};
use tokio::time::{Instant, sleep};
use tracing::info;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};

use super::selection::{effective_latency, selection_score};
use super::types::{
    StandbyPool, StickyRouteSnapshot, TransportKind, UplinkManager, UplinkManagerInner,
    UplinkManagerSnapshot, UplinkSnapshot, UplinkStatus,
};
use super::utils::{
    current_penalty, duration_to_millis_option, load_balancing_mode_name, routing_scope_name,
};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

impl UplinkManager {
    pub async fn initialize_strict_active_selection(&self) {
        if !self.strict_global_active_uplink() && !self.strict_per_uplink_active_uplink() {
            return;
        }

        // Prime initial health before any client traffic arrives so the first
        // strict active-uplink choice is deterministic and probe-driven rather
        // than depending on which session wins the startup race.
        if self.inner.probe.enabled() {
            self.probe_all().await;
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
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
    ) -> Result<Self> {
        if uplinks.is_empty() {
            bail!("at least one uplink must be configured");
        }

        let count = uplinks.len();
        let probe_max_concurrent = probe.max_concurrent;
        let probe_max_dials = probe.max_dials;
        Ok(Self {
            inner: Arc::new(UplinkManagerInner {
                uplinks: uplinks.into_iter().map(Arc::new).collect(),
                probe,
                load_balancing,
                statuses: RwLock::new(vec![UplinkStatus::default(); count]),
                global_active_uplink: RwLock::new(None),
                tcp_active_uplink: RwLock::new(None),
                udp_active_uplink: RwLock::new(None),
                sticky_routes: RwLock::new(HashMap::new()),
                standby_pools: (0..count).map(|_| StandbyPool::new()).collect(),
                probe_execution_limit: Arc::new(Semaphore::new(probe_max_concurrent)),
                probe_dial_limit: Arc::new(Semaphore::new(probe_max_dials)),
                probe_wakeup: Arc::new(Notify::new()),
            }),
        })
    }

    pub fn spawn_warm_standby_loop(&self) {
        if self.inner.load_balancing.warm_standby_tcp == 0
            && self.inner.load_balancing.warm_standby_udp == 0
        {
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_all_standby().await;
            loop {
                sleep(WARM_STANDBY_MAINTENANCE_INTERVAL).await;
                manager.refill_all_standby().await;
            }
        });
    }

    /// Spawns a background loop that pings warm-standby **TCP** pool connections
    /// at `tcp_ws_standby_keepalive_interval` to keep them alive through NAT/
    /// firewall idle-timeout windows.  This is separate from the 15-second
    /// validation loop: the validation loop also runs for UDP and handles
    /// refill; this loop is TCP-only and intentionally runs more frequently.
    pub fn spawn_standby_keepalive_loop(&self) {
        let interval = match self.inner.load_balancing.tcp_ws_standby_keepalive_interval {
            Some(d) if self.inner.load_balancing.warm_standby_tcp > 0 => d,
            _ => return,
        };

        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(interval).await;
                for index in 0..manager.inner.uplinks.len() {
                    manager.keepalive_tcp_pool(index).await;
                }
            }
        });
    }

    pub async fn run_standby_maintenance(&self) {
        self.refill_all_standby().await;
    }

    #[cfg(test)]
    pub(super) async fn run_tcp_standby_keepalive(&self, index: usize) {
        self.keepalive_tcp_pool(index).await;
    }

    pub fn uplinks(&self) -> &[Arc<UplinkConfig>] {
        &self.inner.uplinks
    }

    pub async fn snapshot(&self) -> UplinkManagerSnapshot {
        let now = Instant::now();
        let statuses = self.inner.statuses.read().await.clone();
        let global_active_index = *self.inner.global_active_uplink.read().await;
        let tcp_active_index = *self.inner.tcp_active_uplink.read().await;
        let udp_active_index = *self.inner.udp_active_uplink.read().await;

        let mut uplinks = Vec::with_capacity(self.inner.uplinks.len());
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            let status = &statuses[index];
            let standby_tcp_ready = self.inner.standby_pools[index].tcp.lock().await.len();
            let standby_udp_ready = self.inner.standby_pools[index].udp.lock().await.len();
            let tcp_penalty = current_penalty(&status.tcp_penalty, now, &self.inner.load_balancing);
            let udp_penalty = current_penalty(&status.udp_penalty, now, &self.inner.load_balancing);
            let tcp_effective_latency =
                effective_latency(status, TransportKind::Tcp, now, &self.inner.load_balancing);
            let udp_effective_latency =
                effective_latency(status, TransportKind::Udp, now, &self.inner.load_balancing);
            let tcp_score = selection_score(
                status,
                uplink.weight,
                TransportKind::Tcp,
                now,
                &self.inner.load_balancing,
                self.inner.load_balancing.routing_scope,
            );
            let udp_score = selection_score(
                status,
                uplink.weight,
                TransportKind::Udp,
                now,
                &self.inner.load_balancing,
                self.inner.load_balancing.routing_scope,
            );
            uplinks.push(UplinkSnapshot {
                index,
                name: uplink.name.clone(),
                weight: uplink.weight,
                tcp_healthy: status.tcp_healthy,
                udp_healthy: status.udp_healthy,
                tcp_latency_ms: status.tcp_latency.map(|v| v.as_millis()),
                udp_latency_ms: status.udp_latency.map(|v| v.as_millis()),
                tcp_rtt_ewma_ms: status.tcp_rtt_ewma.map(|v| v.as_millis()),
                udp_rtt_ewma_ms: status.udp_rtt_ewma.map(|v| v.as_millis()),
                tcp_penalty_ms: duration_to_millis_option(tcp_penalty),
                udp_penalty_ms: duration_to_millis_option(udp_penalty),
                tcp_effective_latency_ms: duration_to_millis_option(tcp_effective_latency),
                udp_effective_latency_ms: duration_to_millis_option(udp_effective_latency),
                tcp_score_ms: duration_to_millis_option(tcp_score),
                udp_score_ms: duration_to_millis_option(udp_score),
                cooldown_tcp_ms: status
                    .cooldown_until_tcp
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                cooldown_udp_ms: status
                    .cooldown_until_udp
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                last_checked_ago_ms: status
                    .last_checked
                    .map(|checked| now.duration_since(checked).as_millis()),
                last_error: status.last_error.clone(),
                standby_tcp_ready,
                standby_udp_ready,
                tcp_consecutive_failures: status.tcp_consecutive_failures,
                udp_consecutive_failures: status.udp_consecutive_failures,
                h3_tcp_downgrade_until_ms: status
                    .h3_tcp_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                h3_udp_downgrade_until_ms: status
                    .h3_udp_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                last_active_tcp_ago_ms: status
                    .last_active_tcp
                    .map(|t| now.duration_since(t).as_millis()),
                last_active_udp_ago_ms: status
                    .last_active_udp
                    .map(|t| now.duration_since(t).as_millis()),
            });
        }

        let global_active_uplink = global_active_index
            .and_then(|index| self.inner.uplinks.get(index))
            .map(|uplink| uplink.name.clone());
        let per_uplink = self.strict_per_uplink_active_uplink();
        let tcp_active_uplink = per_uplink
            .then(|| {
                tcp_active_index
                    .and_then(|i| self.inner.uplinks.get(i))
                    .map(|u| u.name.clone())
            })
            .flatten();
        let udp_active_uplink = per_uplink
            .then(|| {
                udp_active_index
                    .and_then(|i| self.inner.uplinks.get(i))
                    .map(|u| u.name.clone())
            })
            .flatten();

        let sticky_routes = {
            let sticky = self.inner.sticky_routes.read().await;
            sticky
                .iter()
                .filter_map(|(key, route)| {
                    route.expires_at.checked_duration_since(now).map(|remaining| {
                        StickyRouteSnapshot {
                            key: key.to_string(),
                            uplink_index: route.uplink_index,
                            uplink_name: self.inner.uplinks[route.uplink_index].name.clone(),
                            expires_in_ms: remaining.as_millis(),
                        }
                    })
                })
                .collect()
        };

        UplinkManagerSnapshot {
            generated_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            load_balancing_mode: load_balancing_mode_name(self.inner.load_balancing.mode)
                .to_string(),
            routing_scope: routing_scope_name(self.inner.load_balancing.routing_scope).to_string(),
            global_active_uplink,
            tcp_active_uplink,
            udp_active_uplink,
            uplinks,
            sticky_routes,
        }
    }
}

pub fn log_uplink_summary(manager: &UplinkManager) {
    log_uplink_summary_named(manager, "default");
}

pub fn log_uplink_summary_named(manager: &UplinkManager, group: &str) {
    info!(
        group,
        uplinks = manager.uplinks().len(),
        mode = ?manager.inner.load_balancing.mode,
        routing_scope = ?manager.inner.load_balancing.routing_scope,
        sticky_ttl_secs = manager.inner.load_balancing.sticky_ttl.as_secs(),
        hysteresis_ms = manager.inner.load_balancing.hysteresis.as_millis() as u64,
        failure_cooldown_secs = manager.inner.load_balancing.failure_cooldown.as_secs(),
        tcp_chunk0_failover_timeout_secs =
            manager.inner.load_balancing.tcp_chunk0_failover_timeout.as_secs(),
        warm_standby_tcp = manager.inner.load_balancing.warm_standby_tcp,
        warm_standby_udp = manager.inner.load_balancing.warm_standby_udp,
        rtt_ewma_alpha = manager.inner.load_balancing.rtt_ewma_alpha,
        failure_penalty_ms = manager.inner.load_balancing.failure_penalty.as_millis() as u64,
        failure_penalty_max_ms =
            manager.inner.load_balancing.failure_penalty_max.as_millis() as u64,
        failure_penalty_halflife_secs = manager
            .inner
            .load_balancing
            .failure_penalty_halflife
            .as_secs(),
        "uplink group initialized"
    );
}
