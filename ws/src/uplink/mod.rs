use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

use crate::config::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
};
use crate::metrics;
use crate::types::{TargetAddr, UplinkTransport};

mod probe;
mod probe_impl;
mod scoring;
mod standby;
mod sticky;
#[cfg(test)]
mod tests;
mod types;

pub use types::{
    StickyRouteSnapshot, TransportKind, UplinkCandidate, UplinkManagerSnapshot, UplinkSnapshot,
};

use self::scoring::{
    add_penalty, classify_runtime_failure_cause, classify_runtime_failure_signature,
    cooldown_active, cooldown_remaining, current_penalty, duration_to_millis_option,
    effective_latency, load_balancing_mode_name, mark_probe_wakeup,
    normalize_other_runtime_failure_detail, rightless_bool, routing_key, routing_scope_name,
    score_latency, selection_health, selection_score, strict_gate_transport, strict_route_key,
    supports_transport_for_scope, update_rtt_ewma,
};
use self::types::{CandidateState, StandbyPool, UplinkManagerInner, UplinkStatus};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);
const PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct UplinkManager {
    pub(super) inner: Arc<UplinkManagerInner>,
}

impl UplinkManager {
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
                statuses: tokio::sync::RwLock::new(vec![UplinkStatus::default(); count]),
                global_active_uplink: tokio::sync::RwLock::new(None),
                tcp_active_uplink: tokio::sync::RwLock::new(None),
                udp_active_uplink: tokio::sync::RwLock::new(None),
                sticky_routes: tokio::sync::RwLock::new(std::collections::HashMap::new()),
                standby_pools: (0..count).map(|_| StandbyPool::new()).collect(),
                probe_execution_limit: Arc::new(tokio::sync::Semaphore::new(probe_max_concurrent)),
                probe_dial_limit: Arc::new(tokio::sync::Semaphore::new(probe_max_dials)),
                probe_wakeup: Arc::new(tokio::sync::Notify::new()),
            }),
        })
    }

    pub fn spawn_probe_loop(&self) {
        if !self.inner.probe.enabled() {
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            manager.probe_all().await;
            loop {
                // Wake up either when the scheduled interval elapses or when a
                // runtime failure triggers an early wakeup (probe_wakeup).
                tokio::select! {
                    _ = sleep(manager.inner.probe.interval) => {}
                    _ = manager.inner.probe_wakeup.notified() => {}
                }
                manager.probe_all().await;
            }
        });
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
                    manager.maintain_pool(index, TransportKind::Tcp).await;
                }
            }
        });
    }

    pub async fn run_standby_maintenance(&self) {
        self.refill_all_standby().await;
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
                    route
                        .expires_at
                        .checked_duration_since(now)
                        .map(|remaining| StickyRouteSnapshot {
                            key: key.to_string(),
                            uplink_index: route.uplink_index,
                            uplink_name: self.inner.uplinks[route.uplink_index].name.clone(),
                            expires_in_ms: remaining.as_millis(),
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

    pub async fn tcp_candidates(&self, target: &TargetAddr) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Tcp) {
            return self
                .strict_transport_candidates(TransportKind::Tcp, Some(target))
                .await;
        }
        self.ordered_candidates(TransportKind::Tcp, Some(target))
            .await
    }

    pub async fn udp_candidates(&self, target: Option<&TargetAddr>) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Udp) {
            return self
                .strict_transport_candidates(TransportKind::Udp, target)
                .await;
        }
        self.ordered_candidates(TransportKind::Udp, target).await
    }

    pub fn strict_global_active_uplink(&self) -> bool {
        self.inner.load_balancing.mode == LoadBalancingMode::ActivePassive
            && self.inner.load_balancing.routing_scope == RoutingScope::Global
    }

    pub fn strict_per_uplink_active_uplink(&self) -> bool {
        self.inner.load_balancing.mode == LoadBalancingMode::ActivePassive
            && self.inner.load_balancing.routing_scope == RoutingScope::PerUplink
    }

    pub fn strict_active_uplink_for(&self, _transport: TransportKind) -> bool {
        self.strict_global_active_uplink() || self.strict_per_uplink_active_uplink()
    }

    pub async fn confirm_selected_uplink(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
        uplink_index: usize,
    ) {
        let rk = routing_key(transport, target, self.inner.load_balancing.routing_scope);
        self.set_active_uplink_index_for_transport(transport, uplink_index)
            .await;
        self.store_sticky_route(&rk, uplink_index).await;
    }

    pub async fn global_active_uplink_index(&self) -> Option<usize> {
        if !self.strict_global_active_uplink() {
            return None;
        }
        *self.inner.global_active_uplink.read().await
    }

    pub async fn active_uplink_index_for_transport(
        &self,
        transport: TransportKind,
    ) -> Option<usize> {
        if self.strict_global_active_uplink() {
            return *self.inner.global_active_uplink.read().await;
        }
        if self.strict_per_uplink_active_uplink() {
            return match transport {
                TransportKind::Tcp => *self.inner.tcp_active_uplink.read().await,
                TransportKind::Udp => *self.inner.udp_active_uplink.read().await,
            };
        }
        None
    }

    pub async fn runtime_failure_debug_state(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> (Option<u128>, Option<u128>) {
        let now = Instant::now();
        let statuses = self.inner.statuses.read().await;
        let Some(status) = statuses.get(index) else {
            return (None, None);
        };

        match transport {
            TransportKind::Tcp => (
                status
                    .cooldown_until_tcp
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis()),
                current_penalty(&status.tcp_penalty, now, &self.inner.load_balancing)
                    .map(|value| value.as_millis()),
            ),
            TransportKind::Udp => (
                status
                    .cooldown_until_udp
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis()),
                current_penalty(&status.udp_penalty, now, &self.inner.load_balancing)
                    .map(|value| value.as_millis()),
            ),
        }
    }

    pub async fn tcp_cooldown_debug_summary(&self) -> Vec<String> {
        let now = Instant::now();
        let statuses = self.inner.statuses.read().await;
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .map(|(index, uplink)| {
                let status = &statuses[index];
                let cooldown_ms = status
                    .cooldown_until_tcp
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(0);
                let penalty_ms =
                    current_penalty(&status.tcp_penalty, now, &self.inner.load_balancing)
                        .map(|value| value.as_millis())
                        .unwrap_or(0);
                format!(
                    "{}#{}(healthy={:?},cooldown_ms={},penalty_ms={},last_error={})",
                    uplink.name,
                    index,
                    status.tcp_healthy,
                    cooldown_ms,
                    penalty_ms,
                    status.last_error.as_deref().unwrap_or("-")
                )
            })
            .collect()
    }

    pub async fn report_runtime_failure(
        &self,
        index: usize,
        transport: TransportKind,
        error: &anyhow::Error,
    ) {
        let error_text = format!("{error:#}");
        let failure_cause = classify_runtime_failure_cause(&error_text);
        let failure_signature = classify_runtime_failure_signature(&error_text);
        let failure_other_detail = (failure_signature == "other")
            .then(|| normalize_other_runtime_failure_detail(&error_text));
        let (uplink_name, cooldown_until, penalty_ms, already_in_cooldown, should_wake_probe) = {
            let now = Instant::now();
            let mut statuses = self.inner.statuses.write().await;
            let status = &mut statuses[index];
            status.last_error = Some(error_text.clone());
            let uplink_name = self.inner.uplinks[index].name.clone();
            match transport {
                TransportKind::Tcp => {
                    let already_in_cooldown = status
                        .cooldown_until_tcp
                        .is_some_and(|deadline| deadline > now);
                    if !already_in_cooldown {
                        // When probe is enabled it is the authoritative source of health.
                        // Do not add a penalty on every transient runtime failure: under
                        // load, H3 streams drop frequently even on a healthy server, so
                        // accumulating penalty here would inflate the uplink's effective
                        // score and cause it to lose EWMA-based elections even while the
                        // probe continues to report it as healthy.  Penalty is instead
                        // added by the probe path once it confirms a real failure
                        // (consecutive_failures >= min_failures).
                        // When probe is disabled there is no other confirmation signal,
                        // so we still penalise immediately to influence cooldown-based
                        // candidate selection.
                        if !self.inner.probe.enabled() {
                            add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                        }
                        status.cooldown_until_tcp =
                            Some(now + self.inner.load_balancing.failure_cooldown);
                        metrics::record_runtime_failure("tcp", &uplink_name);
                        metrics::record_runtime_failure_cause("tcp", &uplink_name, failure_cause);
                        metrics::record_runtime_failure_signature(
                            "tcp",
                            &uplink_name,
                            failure_signature,
                        );
                        if let Some(detail) = &failure_other_detail {
                            metrics::record_runtime_failure_other_detail(
                                "tcp",
                                &uplink_name,
                                detail,
                            );
                        }
                    } else {
                        metrics::record_runtime_failure_suppressed("tcp", &uplink_name);
                    }
                    // When probe is enabled it is the authoritative source of
                    // tcp_healthy.  A single runtime connection failure is not
                    // sufficient evidence that the server is down — only the probe
                    // can confirm that.  Setting tcp_healthy here would cause a
                    // global-scope failover on every transient error, which is exactly
                    // what we want to avoid.  When probe is disabled there is no other
                    // health signal, so fall back to marking the uplink unhealthy
                    // immediately so that cooldown-based gating can still trigger a switch.
                    if !self.inner.probe.enabled() {
                        status.tcp_healthy = Some(false);
                    }
                    let should_wake_probe = self.inner.probe.enabled()
                        && !already_in_cooldown
                        && mark_probe_wakeup(
                            &mut status.last_probe_wakeup_tcp,
                            now,
                            PROBE_WAKEUP_MIN_INTERVAL,
                        );
                    (
                        uplink_name,
                        status.cooldown_until_tcp,
                        current_penalty(&status.tcp_penalty, now, &self.inner.load_balancing)
                            .map(|value| value.as_millis()),
                        already_in_cooldown,
                        should_wake_probe,
                    )
                }
                TransportKind::Udp => {
                    let already_in_cooldown = status
                        .cooldown_until_udp
                        .is_some_and(|deadline| deadline > now);
                    if !already_in_cooldown {
                        // Same rationale as TCP above: when probe is enabled, defer
                        // penalty to the probe confirmation path to avoid inflating
                        // the score of a healthy-but-loaded uplink.
                        if !self.inner.probe.enabled() {
                            add_penalty(&mut status.udp_penalty, now, &self.inner.load_balancing);
                        }
                        status.cooldown_until_udp =
                            Some(now + self.inner.load_balancing.failure_cooldown);
                        metrics::record_runtime_failure("udp", &uplink_name);
                        metrics::record_runtime_failure_cause("udp", &uplink_name, failure_cause);
                        metrics::record_runtime_failure_signature(
                            "udp",
                            &uplink_name,
                            failure_signature,
                        );
                        if let Some(detail) = &failure_other_detail {
                            metrics::record_runtime_failure_other_detail(
                                "udp",
                                &uplink_name,
                                detail,
                            );
                        }
                    } else {
                        metrics::record_runtime_failure_suppressed("udp", &uplink_name);
                    }
                    if !self.inner.probe.enabled() {
                        status.udp_healthy = Some(false);
                    }
                    let should_wake_probe = self.inner.probe.enabled()
                        && !already_in_cooldown
                        && mark_probe_wakeup(
                            &mut status.last_probe_wakeup_udp,
                            now,
                            PROBE_WAKEUP_MIN_INTERVAL,
                        );
                    (
                        uplink_name,
                        status.cooldown_until_udp,
                        current_penalty(&status.udp_penalty, now, &self.inner.load_balancing)
                            .map(|value| value.as_millis()),
                        already_in_cooldown,
                        should_wake_probe,
                    )
                }
            }
        };

        let cooldown_ms = cooldown_until.map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
        });
        if already_in_cooldown {
            debug!(
                uplink = %uplink_name,
                uplink_index = index,
                transport = ?transport,
                cooldown_ms,
                penalty_ms,
                error = %format!("{error:#}"),
                "runtime uplink failure observed while uplink is already in cooldown"
            );
        } else {
            warn!(
                uplink = %uplink_name,
                uplink_index = index,
                transport = ?transport,
                cooldown_ms,
                penalty_ms,
                error = %format!("{error:#}"),
                "runtime uplink failure recorded"
            );
            // Wake the probe loop immediately so it can confirm the failure
            // without waiting for the next scheduled interval.
            if should_wake_probe {
                metrics::record_probe_wakeup(
                    &uplink_name,
                    match transport {
                        TransportKind::Tcp => "tcp",
                        TransportKind::Udp => "udp",
                    },
                    "runtime_failure",
                    "sent",
                );
                self.inner.probe_wakeup.notify_one();
            } else if self.inner.probe.enabled() {
                metrics::record_probe_wakeup(
                    &uplink_name,
                    match transport {
                        TransportKind::Tcp => "tcp",
                        TransportKind::Udp => "udp",
                    },
                    "runtime_failure",
                    "suppressed",
                );
                debug!(
                    uplink = %uplink_name,
                    uplink_index = index,
                    transport = ?transport,
                    min_interval_secs = PROBE_WAKEUP_MIN_INTERVAL.as_secs(),
                    "probe wakeup suppressed by runtime-failure rate limit"
                );
            }
        }
        // If the uplink is configured for H3 and a TCP connection failed at
        // runtime for any reason, mark H3 as temporarily broken so subsequent
        // connections use H2 instead.
        //
        // Previously this was gated on specific APPLICATION_CLOSE error codes
        // (H3_INTERNAL_ERROR, etc.), but H3/QUIC connections can fail with
        // many other errors (connection lost, transport error, stream reset,
        // QUIC timeout, …) that would leave the downgrade timer unset and
        // cause repeated cooldown-driven flapping:
        //   cooldown expires → try H3 → non-APPLICATION_CLOSE error → cooldown →
        //   switch to backup → cooldown expires → try H3 again → repeat.
        // Triggering the downgrade on any TCP failure is safe: if the server
        // is genuinely down both H3 and H2 will fail and we failover to another
        // uplink regardless.  Recovery is natural: once h3_downgrade_duration
        // elapses the next real connection re-tests H3.
        if matches!(transport, TransportKind::Tcp) {
            let uplink = &self.inner.uplinks[index];
            if uplink.transport == UplinkTransport::Websocket
                && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
            {
                let now = tokio::time::Instant::now();
                let mut statuses = self.inner.statuses.write().await;
                let status = &mut statuses[index];
                let downgrade_until = now + self.inner.load_balancing.h3_downgrade_duration;
                let prev = status.h3_tcp_downgrade_until;
                if prev.map_or(true, |t| t < now) {
                    warn!(
                        uplink = %uplink.name,
                        error = %format!("{error:#}"),
                        downgrade_secs = self.inner.load_balancing.h3_downgrade_duration.as_secs(),
                        "H3 TCP runtime error detected, downgrading TCP transport to H2"
                    );
                }
                status.h3_tcp_downgrade_until = Some(downgrade_until);
            }
        }
        self.clear_standby(index, transport).await;
    }

    pub async fn runtime_failure_probe_wakeup_debug_state(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> Option<u128> {
        let now = Instant::now();
        let statuses = self.inner.statuses.read().await;
        let status = statuses.get(index)?;
        match transport {
            TransportKind::Tcp => status
                .last_probe_wakeup_tcp
                .map(|t| now.saturating_duration_since(t).as_millis()),
            TransportKind::Udp => status
                .last_probe_wakeup_udp
                .map(|t| now.saturating_duration_since(t).as_millis()),
        }
    }

    /// Called when real traffic successfully flows through an uplink.
    ///
    /// Updates the activity timestamp (rate-limited to once per 5 s to keep
    /// write-lock contention low for high-frequency UDP callers).  When
    /// `clears_cooldown` is true it also marks the transport as healthy,
    /// resets consecutive-failure counters, and clears any active failure
    /// cooldown — use this only when data has been *received back* from the
    /// upstream, confirming the full data path works.  Pass `false` when
    /// recording outbound traffic (client → upstream) before the upstream has
    /// responded; doing so at that point would incorrectly clear a cooldown
    /// that was set because the upstream failed to respond.
    pub async fn report_active_traffic(
        &self,
        index: usize,
        transport: TransportKind,
        clears_cooldown: bool,
    ) {
        let now = Instant::now();
        // Fast path: skip the write lock when we recently reported for this transport.
        {
            let statuses = self.inner.statuses.read().await;
            let last = match transport {
                TransportKind::Tcp => statuses[index].last_active_tcp,
                TransportKind::Udp => statuses[index].last_active_udp,
            };
            if last.map_or(false, |t| now.duration_since(t) < Duration::from_secs(5)) {
                return;
            }
        }
        let uplink_name = self.inner.uplinks[index].name.clone();
        let mut statuses = self.inner.statuses.write().await;
        let status = &mut statuses[index];
        // Double-check after acquiring write lock.
        let last = match transport {
            TransportKind::Tcp => &mut status.last_active_tcp,
            TransportKind::Udp => &mut status.last_active_udp,
        };
        if last.map_or(false, |t| now.duration_since(t) < Duration::from_secs(5)) {
            return;
        }
        *last = Some(now);
        debug!(
            uplink = %uplink_name,
            transport = ?transport,
            "real traffic activity recorded"
        );
        // When probe is enabled it is the authoritative source of tcp_healthy /
        // udp_healthy.  Overriding it here would let an in-flight session on a
        // probe-marked-unhealthy uplink keep resetting the health flag to
        // Some(true), preventing the failover from taking effect in
        // active-passive / global scope.  When probe is disabled there is no
        // other health signal, so we update the health state from traffic.
        // Only update health state and clear cooldown when the caller confirms
        // that the upstream has actually responded (clears_cooldown=true).
        // Outbound-only traffic (client → upstream, clears_cooldown=false) must
        // not clear the cooldown because the upstream may still fail to respond.
        if clears_cooldown {
            let probe_enabled = self.inner.probe.enabled();
            match transport {
                TransportKind::Tcp => {
                    if !probe_enabled {
                        status.tcp_healthy = Some(true);
                        status.tcp_consecutive_failures = 0;
                    }
                    status.cooldown_until_tcp = None;
                }
                TransportKind::Udp => {
                    if !probe_enabled {
                        status.udp_healthy = Some(true);
                        status.udp_consecutive_failures = 0;
                    }
                    status.cooldown_until_udp = None;
                }
            }
        }
    }

    /// Called when the upstream WebSocket closes unexpectedly mid-session
    /// (server-initiated close, not a client disconnect).  Does not set a
    /// full runtime-failure cooldown — that would penalise the uplink for
    /// normal per-connection lifetime limits — but clears the activity
    /// timestamp so that the next probe cycle is not skipped.  This ensures
    /// the probe detects a downed server promptly instead of waiting for
    /// `probe.interval` of silence.
    ///
    /// Exception: when traffic was active very recently (within
    /// `failure_cooldown`), the timestamp is preserved.  Under load servers
    /// close connections frequently due to per-connection lifetime limits;
    /// clearing the timestamp each time would force probe cycles during the
    /// busiest moments, which risks false-negative health readings and
    /// spurious failovers.  The scheduled probe interval provides a more
    /// reliable signal once the burst subsides.
    pub async fn report_upstream_close(&self, index: usize, transport: TransportKind) {
        let now = Instant::now();
        let threshold = self.inner.load_balancing.failure_cooldown;
        let mut statuses = self.inner.statuses.write().await;
        let status = &mut statuses[index];
        match transport {
            TransportKind::Tcp => {
                let recently_active = status
                    .last_active_tcp
                    .is_some_and(|t| now.duration_since(t) < threshold);
                if !recently_active {
                    status.last_active_tcp = None;
                }
            }
            TransportKind::Udp => {
                let recently_active = status
                    .last_active_udp
                    .is_some_and(|t| now.duration_since(t) < threshold);
                if !recently_active {
                    status.last_active_udp = None;
                }
            }
        }
    }

    /// Feed a connection-establishment latency sample into the RTT EWMA for
    /// the given uplink and transport.  Called when a fresh (non-standby)
    /// WebSocket connection is established so that real path quality is
    /// reflected in routing scores alongside probe-derived measurements.
    pub async fn report_connection_latency(
        &self,
        index: usize,
        transport: TransportKind,
        latency: Duration,
    ) {
        let mut statuses = self.inner.statuses.write().await;
        let status = &mut statuses[index];
        let alpha = self.inner.load_balancing.rtt_ewma_alpha;
        match transport {
            TransportKind::Tcp => {
                update_rtt_ewma(&mut status.tcp_rtt_ewma, Some(latency), alpha);
            }
            TransportKind::Udp => {
                update_rtt_ewma(&mut status.udp_rtt_ewma, Some(latency), alpha);
            }
        }
    }

    /// Returns the effective TCP WebSocket mode for `index`, falling back to
    /// H2 when H3 has been marked broken by repeated runtime errors.
    pub(super) async fn effective_tcp_ws_mode(
        &self,
        index: usize,
    ) -> crate::types::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport == UplinkTransport::Websocket
            && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
        {
            let statuses = self.inner.statuses.read().await;
            let status = &statuses[index];
            if status
                .h3_tcp_downgrade_until
                .is_some_and(|t| t > tokio::time::Instant::now())
            {
                return crate::types::WsTransportMode::H2;
            }
        }
        uplink.tcp_ws_mode
    }

    pub(super) async fn ordered_candidates(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        self.prune_sticky_routes().await;
        let rk = routing_key(transport, target, self.inner.load_balancing.routing_scope);
        let statuses = self.inner.statuses.read().await;
        let now = Instant::now();

        let mut candidates = self
            .inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, uplink)| {
                supports_transport_for_scope(
                    uplink,
                    transport,
                    self.inner.load_balancing.routing_scope,
                )
            })
            .map(|(index, uplink)| CandidateState {
                index,
                uplink: Arc::clone(uplink),
                healthy: selection_health(
                    &statuses[index],
                    transport,
                    now,
                    self.inner.load_balancing.routing_scope,
                ),
                score: selection_score(
                    &statuses[index],
                    uplink.weight,
                    transport,
                    now,
                    &self.inner.load_balancing,
                    self.inner.load_balancing.routing_scope,
                ),
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Vec::new();
        }

        candidates.sort_by(|left, right| {
            rightless_bool(left.healthy)
                .cmp(&rightless_bool(right.healthy))
                .reverse()
                .then_with(|| {
                    left.score
                        .unwrap_or(Duration::MAX)
                        .cmp(&right.score.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let preferred_index = self
            .preferred_sticky_index(&rk, transport, &candidates, &statuses)
            .await;
        if let Some(index) = preferred_index {
            if let Some(pos) = candidates
                .iter()
                .position(|candidate| candidate.index == index)
            {
                let sticky = candidates.remove(pos);
                candidates.insert(0, sticky);
            }
        } else if let Some(first) = candidates.first() {
            self.store_sticky_route(&rk, first.index).await;
        }

        candidates
            .into_iter()
            .map(|candidate| UplinkCandidate {
                index: candidate.index,
                uplink: candidate.uplink,
            })
            .collect()
    }

    pub(super) async fn strict_transport_candidates(
        &self,
        transport: TransportKind,
        _target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        self.prune_sticky_routes().await;
        let statuses = self.inner.statuses.read().await;
        let now = Instant::now();
        let mut candidates = self
            .inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, uplink)| {
                supports_transport_for_scope(
                    uplink,
                    transport,
                    self.inner.load_balancing.routing_scope,
                )
            })
            .map(|(index, uplink)| CandidateState {
                index,
                uplink: Arc::clone(uplink),
                healthy: selection_health(
                    &statuses[index],
                    transport,
                    now,
                    self.inner.load_balancing.routing_scope,
                ),
                score: selection_score(
                    &statuses[index],
                    uplink.weight,
                    transport,
                    now,
                    &self.inner.load_balancing,
                    self.inner.load_balancing.routing_scope,
                ),
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Vec::new();
        }

        candidates.sort_by(|left, right| {
            rightless_bool(left.healthy)
                .cmp(&rightless_bool(right.healthy))
                .reverse()
                .then_with(|| {
                    left.score
                        .unwrap_or(Duration::MAX)
                        .cmp(&right.score.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let gate_transport =
            strict_gate_transport(self.inner.load_balancing.routing_scope, transport);
        let mut switching_from_cooldown = false;
        if let Some(active_index) = self.active_uplink_index_for_transport(transport).await {
            if let Some(candidate) = candidates
                .iter()
                .find(|candidate| candidate.index == active_index)
            {
                // When probe is enabled it is the authoritative source of health.  Runtime
                // failures only set a cooldown; they do NOT update tcp_healthy/udp_healthy
                // when probe is enabled (see report_runtime_failure), so a single transient
                // connection error cannot trigger a permanent failover here.
                // Once the probe has confirmed the uplink is down (tcp/udp_healthy ==
                // Some(false)), we must switch even after the cooldown expires — otherwise
                // the dead uplink would be retried every failure_cooldown seconds.
                // When probe is disabled, runtime failures do set tcp_healthy = Some(false),
                // but that field is not used for the switch decision — instead we fall back
                // to cooldown-based gating so that failures can still cause a switch.
                let probe_healthy = if self.inner.probe.enabled() {
                    match gate_transport {
                        TransportKind::Tcp => statuses[active_index].tcp_healthy != Some(false),
                        TransportKind::Udp => statuses[active_index].udp_healthy != Some(false),
                    }
                } else {
                    true
                };
                // An active cooldown means recent connections to this uplink timed out
                // or errored.  Probe tests only SS-server reachability, not the full
                // data path (SS server → target).  A healthy probe therefore does NOT
                // mean that user traffic will succeed; the cooldown from runtime
                // failures is the only signal that the data path is broken.
                // We require both: probe-confirmed health AND no active runtime-failure
                // cooldown.  This lets the probe remain the sole source for permanent
                // failover (probe failure → tcp_healthy=Some(false) → stays switched
                // even after cooldown expires), while runtime failures cause a
                // temporary switch that lasts at most failure_cooldown_secs.
                let active_cooldown = cooldown_active(&statuses[active_index], gate_transport, now);
                let should_keep = probe_healthy && !active_cooldown;
                debug!(
                    uplink = %self.inner.uplinks[active_index].name,
                    probe_healthy,
                    active_cooldown,
                    should_keep,
                    "strict_transport_candidates: keep decision"
                );
                if should_keep {
                    // When auto_failback is disabled (default), never switch away
                    // from a healthy active uplink — only failure triggers a switch.
                    if !self.inner.load_balancing.auto_failback {
                        let key =
                            strict_route_key(transport, self.inner.load_balancing.routing_scope);
                        self.store_sticky_route(&key, active_index).await;
                        return vec![UplinkCandidate {
                            index: candidate.index,
                            uplink: Arc::clone(&candidate.uplink),
                        }];
                    }
                    // auto_failback = true: if a higher-priority healthy candidate
                    // exists, switch to it — but only once it has been consistently
                    // healthy for at least min_failures consecutive probe cycles.
                    // A single successful probe is not enough: the primary may be
                    // transiently up (e.g. service restarting) and returning traffic
                    // to it prematurely would break connections.
                    //
                    // IMPORTANT: auto_failback only ever switches to a
                    // *higher-priority* uplink.  Switching to a lower-priority
                    // uplink is a failover, not a failback; failovers must be
                    // driven by probe-confirmed failure, not by EWMA comparison.
                    //
                    // Priority is defined by `weight` (higher weight = more
                    // preferred, because score = EWMA / weight).  Index is used
                    // as a stable tiebreaker when weights are equal.
                    //
                    // The distinction matters under load: the active uplink's EWMA
                    // inflates (slower H3 connections feed higher latency samples)
                    // while the idle backup retains a low probe-derived EWMA.  If
                    // auto_failback used raw EWMA to pick "best", the backup would
                    // appear superior and trigger a spurious switch even though the
                    // active is probe-healthy and carrying real traffic.
                    //
                    // Weight is a stable, load-independent priority signal: we only
                    // failback to a candidate that has strictly higher weight than
                    // the active (or equal weight but lower config index).  If the
                    // active is already the highest-priority probe-healthy uplink,
                    // best is None and we keep the active without any switch.
                    let active_weight = self.inner.uplinks[active_index].weight;
                    let best = candidates
                        .iter()
                        .filter(|b| {
                            let b_weight = self.inner.uplinks[b.index].weight;
                            let higher_priority = b_weight > active_weight
                                || (b_weight == active_weight && b.index < active_index);
                            higher_priority
                                && match gate_transport {
                                    TransportKind::Tcp => {
                                        statuses[b.index].tcp_healthy == Some(true)
                                    }
                                    TransportKind::Udp => {
                                        statuses[b.index].udp_healthy == Some(true)
                                    }
                                }
                        })
                        .max_by(|a, b| {
                            let wa = self.inner.uplinks[a.index].weight;
                            let wb = self.inner.uplinks[b.index].weight;
                            wa.partial_cmp(&wb)
                                .unwrap_or(std::cmp::Ordering::Equal)
                                .then_with(|| b.index.cmp(&a.index)) // lower index wins
                        });
                    let is_best = best.is_none();
                    let best_is_stable = best.map_or(true, |b| {
                        let min = self.inner.probe.min_failures as u32;
                        let consecutive = match gate_transport {
                            TransportKind::Tcp => statuses[b.index].tcp_consecutive_successes,
                            TransportKind::Udp => statuses[b.index].udp_consecutive_successes,
                        };
                        consecutive >= min
                    });
                    if is_best || !best_is_stable {
                        let key =
                            strict_route_key(transport, self.inner.load_balancing.routing_scope);
                        self.store_sticky_route(&key, active_index).await;
                        return vec![UplinkCandidate {
                            index: candidate.index,
                            uplink: Arc::clone(&candidate.uplink),
                        }];
                    }
                    // Current active is healthy but the best candidate is stable
                    // enough to switch to.  Fall through; switching_from_cooldown
                    // stays false so we use base (penalty-free) scoring.
                } else {
                    // Active uplink is unhealthy or on cooldown — switch with
                    // penalty-aware re-sort to avoid oscillating back immediately.
                    switching_from_cooldown = true;
                }
            } else {
                // Active uplink no longer in the candidate set — re-select.
                switching_from_cooldown = true;
            }
        }

        // When we are switching away from a failed active uplink (cooldown is
        // active), re-sort candidates using three-level ordering:
        //
        // 1. Healthy candidates come first (probe-confirmed, no active cooldown).
        //
        // 2. Among unhealthy candidates (all in cooldown), prefer the one whose
        //    cooldown expires soonest — i.e. the one that failed longest ago.
        //    When both uplinks are simultaneously in cooldown (e.g. primary
        //    fails, fallback is selected, fallback also fails), score/EWMA alone
        //    would pick the historically-fastest uplink regardless of how recently
        //    it failed.  Remaining-cooldown is a more direct signal: a smaller
        //    remaining window means the failure is older and recovery is more
        //    likely.
        //
        // 3. Penalty-aware score as a secondary key — prevents oscillation under
        //    load (primary fails → switch to backup → backup fails → would switch
        //    back to primary whose cooldown cleared but penalty remains).
        //
        // For the initial selection (no previous active) this re-sort is skipped
        // so that strict-mode selection remains EWMA-driven.
        if switching_from_cooldown {
            candidates.sort_by(|left, right| {
                let left_remaining = cooldown_remaining(&statuses[left.index], gate_transport, now);
                let right_remaining =
                    cooldown_remaining(&statuses[right.index], gate_transport, now);
                let left_score = score_latency(
                    &statuses[left.index],
                    self.inner.uplinks[left.index].weight,
                    gate_transport,
                    now,
                    &self.inner.load_balancing,
                );
                let right_score = score_latency(
                    &statuses[right.index],
                    self.inner.uplinks[right.index].weight,
                    gate_transport,
                    now,
                    &self.inner.load_balancing,
                );
                rightless_bool(left.healthy)
                    .cmp(&rightless_bool(right.healthy))
                    .reverse()
                    // Among unhealthy: prefer the one whose cooldown expires
                    // soonest (failed longest ago → most likely recovered).
                    .then_with(|| left_remaining.cmp(&right_remaining))
                    // Secondary: penalty-aware score (prevents oscillation).
                    .then_with(|| {
                        left_score
                            .unwrap_or(Duration::MAX)
                            .cmp(&right_score.unwrap_or(Duration::MAX))
                    })
                    .then_with(|| left.index.cmp(&right.index))
            });
        }

        let selected = candidates[0].index;
        self.set_active_uplink_index_for_transport(transport, selected)
            .await;
        let key = strict_route_key(transport, self.inner.load_balancing.routing_scope);
        self.store_sticky_route(&key, selected).await;
        vec![UplinkCandidate {
            index: selected,
            uplink: Arc::clone(&candidates[0].uplink),
        }]
    }

    pub(super) async fn set_active_uplink_index_for_transport(
        &self,
        transport: TransportKind,
        uplink_index: usize,
    ) {
        if self.strict_global_active_uplink() {
            *self.inner.global_active_uplink.write().await = Some(uplink_index);
        } else if self.strict_per_uplink_active_uplink() {
            match transport {
                TransportKind::Tcp => {
                    *self.inner.tcp_active_uplink.write().await = Some(uplink_index);
                }
                TransportKind::Udp => {
                    *self.inner.udp_active_uplink.write().await = Some(uplink_index);
                }
            }
        }
    }
}

pub fn log_uplink_summary(manager: &UplinkManager) {
    info!(
        uplinks = manager.uplinks().len(),
        mode = ?manager.inner.load_balancing.mode,
        routing_scope = ?manager.inner.load_balancing.routing_scope,
        sticky_ttl_secs = manager.inner.load_balancing.sticky_ttl.as_secs(),
        hysteresis_ms = manager.inner.load_balancing.hysteresis.as_millis() as u64,
        failure_cooldown_secs = manager.inner.load_balancing.failure_cooldown.as_secs(),
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
        "uplink manager initialized"
    );
}
