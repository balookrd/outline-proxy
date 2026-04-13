use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::{Notify, RwLock, Semaphore};
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
};
use crate::memory::{maybe_shrink_hash_map, maybe_shrink_vecdeque};
use crate::metrics;
use crate::transport::{
    AnyWsStream, UdpWsTransport, connect_shadowsocks_udp_with_source, connect_websocket_with_source,
};
use crate::types::{TargetAddr, UplinkTransport};

use super::probe::probe_uplink;
use super::selection::{
    cooldown_active, cooldown_remaining, effective_latency, score_latency, selection_health,
    selection_score, strict_gate_transport, supports_transport_for_scope,
};
use super::types::{
    CandidateState, RoutingKey, StandbyPool, StickyRoute, StickyRouteSnapshot, TransportKind,
    UplinkCandidate, UplinkManager, UplinkManagerInner, UplinkManagerSnapshot, UplinkSnapshot,
    UplinkStatus,
};
use super::utils::{
    add_penalty, classify_runtime_failure_cause, classify_runtime_failure_signature,
    current_penalty, duration_to_millis_option, load_balancing_mode_name, mark_probe_wakeup,
    normalize_other_runtime_failure_detail, rightless_bool, routing_key, routing_scope_name,
    strict_route_key, update_rtt_ewma,
};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);
const PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);

async fn run_probe_attempt_with_timeout(
    uplink: Arc<UplinkConfig>,
    probe: ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::types::WsTransportMode,
    timeout_duration: Duration,
) -> Result<super::types::ProbeOutcome> {
    let mut probe_task =
        tokio::spawn(
            async move { probe_uplink(&uplink, &probe, dial_limit, effective_tcp_mode).await },
        );
    let timeout_sleep = sleep(timeout_duration);
    tokio::pin!(timeout_sleep);

    tokio::select! {
        joined = &mut probe_task => match joined {
            Ok(result) => result,
            Err(error) => Err(anyhow!("probe task failed: {error}")),
        },
        _ = &mut timeout_sleep => {
            probe_task.abort();
            let _ = probe_task.await;
            Err(anyhow!("probe timed out after {:?}", timeout_duration))
        }
    }
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
                tcp_active_index.and_then(|i| self.inner.uplinks.get(i)).map(|u| u.name.clone())
            })
            .flatten();
        let udp_active_uplink = per_uplink
            .then(|| {
                udp_active_index.and_then(|i| self.inner.uplinks.get(i)).map(|u| u.name.clone())
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

    pub async fn tcp_candidates(&self, target: &TargetAddr) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Tcp) {
            return self.strict_transport_candidates(TransportKind::Tcp, Some(target)).await;
        }
        self.ordered_candidates(TransportKind::Tcp, Some(target)).await
    }

    pub async fn udp_candidates(&self, target: Option<&TargetAddr>) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Udp) {
            return self.strict_transport_candidates(TransportKind::Udp, target).await;
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
        let routing_key = routing_key(transport, target, self.inner.load_balancing.routing_scope);
        self.set_active_uplink_index_for_transport(transport, uplink_index).await;
        self.store_sticky_route(&routing_key, uplink_index).await;
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
                    let already_in_cooldown =
                        status.cooldown_until_tcp.is_some_and(|deadline| deadline > now);
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
                    let already_in_cooldown =
                        status.cooldown_until_udp.is_some_and(|deadline| deadline > now);
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

        let cooldown_ms = cooldown_until
            .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_millis());
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
    /// write-lock contention low for high-frequency UDP callers), marks the
    /// transport as healthy, resets consecutive-failure counters, and clears
    /// any active failure cooldown.  A successful data transfer is stronger
    /// evidence of liveness than a probe ping/pong, so we treat it
    /// accordingly.
    pub async fn report_active_traffic(&self, index: usize, transport: TransportKind) {
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
                let recently_active =
                    status.last_active_tcp.is_some_and(|t| now.duration_since(t) < threshold);
                if !recently_active {
                    status.last_active_tcp = None;
                }
            }
            TransportKind::Udp => {
                let recently_active =
                    status.last_active_udp.is_some_and(|t| now.duration_since(t) < threshold);
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
    async fn effective_tcp_ws_mode(&self, index: usize) -> crate::types::WsTransportMode {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport == UplinkTransport::Websocket
            && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
        {
            let statuses = self.inner.statuses.read().await;
            let status = &statuses[index];
            if status.h3_tcp_downgrade_until.is_some_and(|t| t > tokio::time::Instant::now()) {
                return crate::types::WsTransportMode::H2;
            }
        }
        uplink.tcp_ws_mode
    }

    /// Pops one connection from the TCP standby pool without falling back to a
    /// fresh dial.  Returns `None` if the pool is empty.  Callers can use this
    /// to implement a silent retry: attempt the pool entry first; if it turns
    /// out to be stale, fall back to `connect_tcp_ws_fresh` without recording
    /// a runtime failure.
    pub async fn try_take_tcp_standby(&self, candidate: &UplinkCandidate) -> Option<AnyWsStream> {
        if candidate.uplink.transport != UplinkTransport::Websocket {
            return None;
        }
        let ws = self.inner.standby_pools[candidate.index].tcp.lock().await.pop_front()?;
        self.spawn_refill(candidate.index, TransportKind::Tcp);
        metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "hit");
        debug!(uplink = %candidate.uplink.name, "using warm-standby TCP websocket");
        Some(ws)
    }

    /// Dials a fresh TCP WebSocket connection, bypassing the standby pool.
    pub async fn connect_tcp_ws_fresh(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<AnyWsStream> {
        if candidate.uplink.transport != UplinkTransport::Websocket {
            bail!("uplink {} does not use websocket transport", candidate.uplink.name);
        }
        metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "miss");
        let mode = self.effective_tcp_ws_mode(candidate.index).await;
        debug!(
            uplink = %candidate.uplink.name,
            mode = %mode,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let started = Instant::now();
        let ws =
            connect_websocket_with_source(
                candidate.uplink.tcp_ws_url.as_ref().ok_or_else(|| {
                    anyhow!("uplink {} missing tcp_ws_url", candidate.uplink.name)
                })?,
                mode,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to connect to {}",
                    candidate.uplink.tcp_ws_url.as_ref().expect("validated tcp_ws_url")
                )
            })?;
        // Feed the on-demand dial latency into the RTT EWMA so real connection
        // quality is reflected in routing scores, not just probe ping/pong times.
        self.report_connection_latency(candidate.index, TransportKind::Tcp, started.elapsed())
            .await;
        Ok(ws)
    }

    pub async fn acquire_tcp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<AnyWsStream> {
        if let Some(ws) = self.try_take_tcp_standby(candidate).await {
            return Ok(ws);
        }
        self.connect_tcp_ws_fresh(candidate, source).await
    }

    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<UdpWsTransport> {
        if candidate.uplink.transport == UplinkTransport::Shadowsocks {
            metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "miss");
            let udp_addr = candidate.uplink.udp_addr.as_ref().ok_or_else(|| {
                anyhow!("udp_addr is not configured for uplink {}", candidate.uplink.name)
            })?;
            let started = Instant::now();
            let socket = connect_shadowsocks_udp_with_source(
                udp_addr,
                candidate.uplink.fwmark,
                candidate.uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| format!("failed to connect to {}", udp_addr))?;
            self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
                .await;
            return Ok(UdpWsTransport::from_socket(
                socket,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
            )?);
        }

        let pool = &self.inner.standby_pools[candidate.index];
        if let Some(ws) = pool.udp.lock().await.pop_front() {
            self.spawn_refill(candidate.index, TransportKind::Udp);
            metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "hit");
            debug!(uplink = %candidate.uplink.name, "using warm-standby UDP websocket");
            return Ok(UdpWsTransport::from_websocket(
                ws,
                candidate.uplink.cipher,
                &candidate.uplink.password,
                source,
                self.inner.load_balancing.udp_ws_keepalive_interval,
            )?);
        }

        metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "miss");
        debug!(uplink = %candidate.uplink.name, "no warm-standby UDP websocket available, dialing on-demand");
        let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
            anyhow!("udp_ws_url is not configured for uplink {}", candidate.uplink.name)
        })?;
        let started = Instant::now();
        let transport = UdpWsTransport::connect(
            udp_ws_url,
            candidate.uplink.udp_ws_mode,
            candidate.uplink.cipher,
            &candidate.uplink.password,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            source,
            self.inner.load_balancing.udp_ws_keepalive_interval,
        )
        .await
        .with_context(|| format!("failed to connect to {}", udp_ws_url))?;
        self.report_connection_latency(candidate.index, TransportKind::Udp, started.elapsed())
            .await;
        Ok(transport)
    }

    async fn ordered_candidates(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        self.prune_sticky_routes().await;
        let routing_key = routing_key(transport, target, self.inner.load_balancing.routing_scope);
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
                    left.score.unwrap_or(Duration::MAX).cmp(&right.score.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let preferred_index = self
            .preferred_sticky_index(&routing_key, transport, &candidates, &statuses)
            .await;
        if let Some(index) = preferred_index {
            if let Some(pos) = candidates.iter().position(|candidate| candidate.index == index) {
                let sticky = candidates.remove(pos);
                candidates.insert(0, sticky);
            }
        } else if let Some(first) = candidates.first() {
            self.store_sticky_route(&routing_key, first.index).await;
        }

        candidates
            .into_iter()
            .map(|candidate| UplinkCandidate { index: candidate.index, uplink: candidate.uplink })
            .collect()
    }

    async fn strict_transport_candidates(
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
                    left.score.unwrap_or(Duration::MAX).cmp(&right.score.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let gate_transport =
            strict_gate_transport(self.inner.load_balancing.routing_scope, transport);
        let mut switching_from_cooldown = false;
        if let Some(active_index) = self.active_uplink_index_for_transport(transport).await {
            if let Some(candidate) =
                candidates.iter().find(|candidate| candidate.index == active_index)
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
                // Global + probe enabled: probe is the sole gate — do not also require
                // !cooldown, because cooldown is not set by probe failures and we want
                // probe-confirmed health to immediately re-allow the primary.
                // All other cases (PerUplink / probe disabled): combine probe health with
                // cooldown so that transient runtime failures still trigger a temporary
                // switch while persistent probe failures cause a permanent switch.
                let should_keep = if self.inner.load_balancing.routing_scope == RoutingScope::Global
                    && self.inner.probe.enabled()
                {
                    probe_healthy
                } else {
                    probe_healthy && !cooldown_active(&statuses[active_index], gate_transport, now)
                };
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
        // active), re-sort candidates so that unhealthy uplinks whose cooldown
        // expires sooner are tried first, with penalty-aware score as a
        // secondary key. For the initial selection (no previous active)
        // penalties are ignored to preserve the intent that strict-mode
        // selection is EWMA-driven.
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
                    .then_with(|| left_remaining.cmp(&right_remaining))
                    .then_with(|| {
                        left_score
                            .unwrap_or(Duration::MAX)
                            .cmp(&right_score.unwrap_or(Duration::MAX))
                    })
                    .then_with(|| left.index.cmp(&right.index))
            });
        }

        let selected = candidates[0].index;
        self.set_active_uplink_index_for_transport(transport, selected).await;
        let key = strict_route_key(transport, self.inner.load_balancing.routing_scope);
        self.store_sticky_route(&key, selected).await;
        vec![UplinkCandidate { index: selected, uplink: Arc::clone(&candidates[0].uplink) }]
    }

    async fn set_active_uplink_index_for_transport(
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

    async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
            self.maintain_pool(index, TransportKind::Tcp).await;
            self.maintain_pool(index, TransportKind::Udp).await;
        }
    }

    fn spawn_refill(&self, index: usize, transport: TransportKind) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_pool(index, transport).await;
        });
    }

    async fn maintain_pool(&self, index: usize, transport: TransportKind) {
        self.validate_pool(index, transport).await;
        self.refill_pool(index, transport).await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = Arc::clone(&self.inner.uplinks[index]);
        if uplink.transport != UplinkTransport::Websocket {
            return;
        }
        let pool = &self.inner.standby_pools[index];
        let refill_guard = match transport {
            TransportKind::Tcp => pool.tcp_refill.lock().await,
            TransportKind::Udp => pool.udp_refill.lock().await,
        };

        let transport_label = match transport {
            TransportKind::Tcp => "tcp",
            TransportKind::Udp => "udp",
        };
        let pool_vec = match transport {
            TransportKind::Tcp => &pool.tcp,
            TransportKind::Udp => &pool.udp,
        };

        // Read current length once; track additions with a counter to avoid
        // re-locking on every iteration just to check the pool size.
        let mut current_len = pool_vec.lock().await.len();

        loop {
            if current_len >= desired {
                break;
            }

            let ws = match transport {
                TransportKind::Tcp => {
                    let mode = self.effective_tcp_ws_mode(index).await;
                    let Some(tcp_ws_url) = uplink.tcp_ws_url.as_ref() else {
                        break;
                    };
                    connect_websocket_with_source(
                        tcp_ws_url,
                        mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_tcp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", tcp_ws_url))
                }
                TransportKind::Udp => {
                    if uplink.transport != UplinkTransport::Websocket {
                        break;
                    }
                    let Some(url) = uplink.udp_ws_url.as_ref() else {
                        break;
                    };
                    connect_websocket_with_source(
                        url,
                        uplink.udp_ws_mode,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        "standby_udp",
                    )
                    .await
                    .with_context(|| format!("failed to preconnect to {}", url))
                }
            };

            match ws {
                Ok(ws) => {
                    pool_vec.lock().await.push_back(ws);
                    current_len += 1;
                    metrics::record_warm_standby_refill(transport_label, &uplink.name, true);
                    debug!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        desired,
                        "warm-standby websocket replenished"
                    );
                }
                Err(error) => {
                    metrics::record_warm_standby_refill(transport_label, &uplink.name, false);
                    warn!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        error = %format!("{error:#}"),
                        "failed to replenish warm-standby websocket"
                    );
                    break;
                }
            }
        }

        drop(refill_guard);
    }

    async fn validate_pool(&self, index: usize, transport: TransportKind) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::protocol::Message;

        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = Arc::clone(&self.inner.uplinks[index]);
        let pool = &self.inner.standby_pools[index];
        let mut drained = std::collections::VecDeque::new();
        {
            let mut guard = match transport {
                TransportKind::Tcp => pool.tcp.lock().await,
                TransportKind::Udp => pool.udp.lock().await,
            };
            drained.extend(guard.drain(..));
        }

        if drained.is_empty() {
            return;
        }

        let mut alive = std::collections::VecDeque::with_capacity(drained.len());
        while let Some(mut ws) = drained.pop_front() {
            let started = Instant::now();
            // Check liveness with a non-blocking read (1 ms timeout).
            // Many servers do not respond to WebSocket ping frames, so we use
            // a quick peek instead: if the server has closed the connection we
            // will see a Close frame or an error immediately; otherwise the
            // read times out and we treat the connection as still alive.
            let alive_result: Result<()> = match timeout(Duration::from_millis(1), ws.next()).await
            {
                Err(_elapsed) => Ok(()), // still open — nothing to read
                Ok(None) => Err(anyhow!("standby websocket stream ended")),
                Ok(Some(Err(e))) => Err(anyhow!("standby websocket error: {e}")),
                Ok(Some(Ok(Message::Close(frame)))) => {
                    Err(anyhow!("standby websocket closed by server: {:?}", frame))
                }
                Ok(Some(Ok(_))) => Ok(()), // unexpected data frame — still alive
            };
            metrics::record_probe(
                &uplink.name,
                match transport {
                    TransportKind::Tcp => "tcp",
                    TransportKind::Udp => "udp",
                },
                "standby_ws",
                alive_result.is_ok(),
                started.elapsed(),
            );
            match alive_result {
                Ok(()) => alive.push_back(ws),
                Err(error) => {
                    use super::probe::is_expected_standby_probe_failure;
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    } else {
                        warn!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    }
                }
            }
        }

        let mut guard = match transport {
            TransportKind::Tcp => pool.tcp.lock().await,
            TransportKind::Udp => pool.udp.lock().await,
        };
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }

    async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        match transport {
            TransportKind::Tcp => {
                let mut guard = pool.tcp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
            TransportKind::Udp => {
                let mut guard = pool.udp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
        }
    }

    async fn preferred_sticky_index(
        &self,
        routing_key: &RoutingKey,
        transport: TransportKind,
        candidates: &[CandidateState],
        statuses: &[UplinkStatus],
    ) -> Option<usize> {
        let sticky_index = {
            let sticky = self.inner.sticky_routes.read().await;
            sticky.get(routing_key).map(|route| route.uplink_index)
        }?;

        let sticky = candidates.iter().find(|candidate| candidate.index == sticky_index)?;
        if !sticky.healthy {
            self.store_sticky_route(routing_key, candidates[0].index).await;
            return Some(candidates[0].index);
        }

        if self.inner.load_balancing.mode == LoadBalancingMode::ActivePassive {
            self.store_sticky_route(routing_key, sticky.index).await;
            return Some(sticky.index);
        }

        let fastest = candidates.iter().find(|candidate| candidate.healthy).unwrap_or(sticky);
        let now = Instant::now();
        // Always use penalty-aware scoring for the hysteresis check, regardless of routing
        // scope. This prevents a recently-failed uplink from immediately winning back the
        // sticky route when only its cooldown has expired but the failure penalty is still
        // elevated. Without this, Global scope (which ignores penalty in selection_score)
        // would cause oscillation: primary fails → switch to backup → cooldown expires →
        // primary wins back on base latency alone before the penalty has decayed.
        let sticky_score = score_latency(
            &statuses[sticky.index],
            self.inner.uplinks[sticky.index].weight,
            transport,
            now,
            &self.inner.load_balancing,
        );
        let fastest_score = score_latency(
            &statuses[fastest.index],
            self.inner.uplinks[fastest.index].weight,
            transport,
            now,
            &self.inner.load_balancing,
        );

        let should_switch = match (sticky_score, fastest_score) {
            (Some(sticky_score), Some(fastest_score)) => {
                sticky.index != fastest.index
                    && sticky_score > fastest_score + self.inner.load_balancing.hysteresis
            }
            _ => false,
        };

        if should_switch {
            self.store_sticky_route(routing_key, fastest.index).await;
            Some(fastest.index)
        } else {
            self.store_sticky_route(routing_key, sticky.index).await;
            Some(sticky.index)
        }
    }

    async fn store_sticky_route(&self, routing_key: &RoutingKey, uplink_index: usize) {
        let mut sticky = self.inner.sticky_routes.write().await;
        sticky.insert(
            routing_key.clone(),
            StickyRoute {
                uplink_index,
                expires_at: if self.strict_pinned_route_key(routing_key) {
                    Instant::now() + Duration::from_secs(365 * 24 * 60 * 60)
                } else {
                    Instant::now() + self.inner.load_balancing.sticky_ttl
                },
            },
        );
    }

    async fn prune_sticky_routes(&self) {
        let now = Instant::now();
        let mut sticky = self.inner.sticky_routes.write().await;
        sticky.retain(|key, route| {
            if self.strict_pinned_route_key(key) {
                return true;
            }
            route.expires_at > now
        });
        maybe_shrink_hash_map(&mut sticky);
    }

    fn strict_pinned_route_key(&self, key: &RoutingKey) -> bool {
        match self.inner.load_balancing.routing_scope {
            RoutingScope::Global => {
                self.strict_global_active_uplink() && *key == RoutingKey::Global
            }
            RoutingScope::PerUplink => {
                self.strict_per_uplink_active_uplink()
                    && matches!(key, RoutingKey::TransportGlobal(_))
            }
            RoutingScope::PerFlow => false,
        }
    }

    async fn probe_all(&self) {
        let mut tasks = tokio::task::JoinSet::new();
        let now = Instant::now();
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            // Skip the probe if recent traffic demonstrates the uplink is alive
            // AND it is already marked healthy.  We must NOT skip when the uplink
            // is unhealthy (tcp_healthy == Some(false) or None): in that case the
            // probe is the only mechanism that can confirm recovery and restore
            // the uplink to healthy status.  Skipping when unhealthy would leave
            // the health state stuck — a lingering session on the failed uplink
            // would prevent the probe from ever running and the uplink would
            // never come back online.
            {
                let statuses = self.inner.statuses.read().await;
                let s = &statuses[index];
                let threshold = self.inner.probe.interval;
                let tcp_active =
                    s.last_active_tcp.map_or(false, |t| now.duration_since(t) < threshold);
                let tcp_currently_healthy = s.tcp_healthy == Some(true);
                // Do NOT skip if there is an active cooldown: a runtime
                // connection failure was reported, meaning the uplink may be
                // down even though tcp_healthy is still Some(true) (the probe
                // is the authoritative health source when enabled, so
                // report_runtime_failure does not flip tcp_healthy directly).
                // We must run the probe so it can detect the failure and
                // trigger failover.
                let tcp_no_cooldown = !cooldown_active(s, TransportKind::Tcp, now);
                // In global scope with probe enabled the probe is the sole
                // health gate — the cooldown from a runtime failure does NOT
                // affect the switch decision (see strict_transport_candidates).
                // Running a probe immediately after a runtime failure under
                // load is counterproductive: the server is busy, the new QUIC
                // handshake competes with existing traffic, and the probe is
                // likely to fail → false negative → spurious failover.
                // Active traffic is already stronger evidence of liveness than
                // a probe ping, so we skip the probe cycle whenever traffic is
                // flowing and the uplink is probe-confirmed healthy, regardless
                // of any active runtime-failure cooldown.
                // For non-global scopes the cooldown gate is used for candidate
                // selection, so we must still probe to confirm recovery before
                // the cooldown expires and re-admits the uplink.
                let global_probe = self.inner.load_balancing.routing_scope == RoutingScope::Global
                    && self.inner.probe.enabled();
                let skip_allowed = tcp_no_cooldown || global_probe;
                if tcp_active && tcp_currently_healthy && skip_allowed {
                    let udp_active =
                        s.last_active_udp.map_or(false, |t| now.duration_since(t) < threshold);
                    debug!(
                        uplink = %uplink.name,
                        last_active_tcp_ms = s.last_active_tcp.map(|t| now.duration_since(t).as_millis()),
                        last_active_udp_ms = s.last_active_udp.map(|t| now.duration_since(t).as_millis()),
                        udp_also_active = udp_active,
                        had_cooldown = !tcp_no_cooldown,
                        "skipping probe cycle: real traffic observed and uplink is healthy"
                    );
                    continue;
                }
            }

            let uplink = Arc::clone(uplink);
            let probe = self.inner.probe.clone();
            let timeout_duration = self.inner.probe.timeout;
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            let probe_attempts = probe.attempts.max(1);
            // Use the effective TCP WS mode so that when H3 is in the
            // downgrade window the probe tests H2 connectivity instead.
            // This prevents the probe from clearing h3_tcp_downgrade_until
            // prematurely via a successful H3 ping/pong that does not
            // represent real data-path behaviour (the server may reject
            // actual streams with APPLICATION_CLOSE while still answering
            // ping/pong at the connection level).
            let effective_tcp_mode = self.effective_tcp_ws_mode(index).await;
            tasks.spawn(async move {
                let _permit = execution_limit
                    .acquire_owned()
                    .await
                    .expect("probe execution semaphore closed");
                // Retry the probe up to `attempts` times within one cycle.
                // As soon as any attempt returns Ok we accept that result and
                // stop; only if every attempt fails do we propagate the error.
                // This makes each probe cycle resilient to transient network
                // blips that would otherwise needlessly increment the
                // consecutive-failure counter.
                let mut outcome = Err(anyhow!("no probe attempts"));
                for attempt in 0..probe_attempts {
                    outcome = run_probe_attempt_with_timeout(
                        Arc::clone(&uplink),
                        probe.clone(),
                        Arc::clone(&dial_limit),
                        effective_tcp_mode,
                        timeout_duration,
                    )
                    .await;
                    if outcome.is_ok() {
                        break;
                    }
                    if attempt + 1 < probe_attempts {
                        sleep(Duration::from_millis(500)).await;
                    }
                }
                (index, uplink, outcome)
            });
        }

        while let Some(joined) = tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "probe task failed");
                    continue;
                }
            };
            let mut refill_tcp = false;
            let mut refill_udp = false;
            match outcome {
                Ok(result) => {
                    let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
                        let now = Instant::now();
                        let min_failures = self.inner.probe.min_failures;
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_latency = result.tcp_latency;
                        status.udp_latency = result.udp_latency;
                        update_rtt_ewma(
                            &mut status.tcp_rtt_ewma,
                            result.tcp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        update_rtt_ewma(
                            &mut status.udp_rtt_ewma,
                            result.udp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        if !result.tcp_ok {
                            status.tcp_consecutive_successes = 0;
                            status.tcp_consecutive_failures =
                                status.tcp_consecutive_failures.saturating_add(1);
                            if status.tcp_consecutive_failures >= min_failures as u32 {
                                status.tcp_healthy = Some(false);
                                add_penalty(
                                    &mut status.tcp_penalty,
                                    now,
                                    &self.inner.load_balancing,
                                );
                            }
                            // If this uplink is configured for H3 and the TCP
                            // probe failed, downgrade to H2 for the next probe
                            // cycle.  Without this, intermittent H3 probe
                            // failures cause probe-driven flapping in
                            // active-passive / global scope: the probe
                            // alternates pass (H3) / fail (H3) → switch to
                            // backup / switch back to primary on every cycle.
                            // With H2 downgrade, recovery probing uses H2
                            // which is stable, and H3 is only retried after the
                            // downgrade timer expires.
                            if uplink.transport == UplinkTransport::Websocket
                                && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
                            {
                                let downgrade_until =
                                    now + self.inner.load_balancing.h3_downgrade_duration;
                                if status.h3_tcp_downgrade_until.map_or(true, |t| t < now) {
                                    warn!(
                                        uplink = %uplink.name,
                                        downgrade_secs = self.inner.load_balancing.h3_downgrade_duration.as_secs(),
                                        "H3 TCP probe failed, downgrading to H2 for next probe cycle"
                                    );
                                }
                                status.h3_tcp_downgrade_until = Some(downgrade_until);
                            }
                        } else {
                            status.tcp_consecutive_failures = 0;
                            status.tcp_consecutive_successes =
                                status.tcp_consecutive_successes.saturating_add(1);
                            status.tcp_healthy = Some(true);
                            // Only clear runtime-failure cooldown when the probe confirms TCP is
                            // healthy. Clearing unconditionally would make a recently-failed
                            // uplink immediately eligible again, causing oscillation under load.
                            status.cooldown_until_tcp = None;
                            // Do NOT clear h3_tcp_downgrade_until here.  The probe uses the
                            // effective (possibly downgraded) WS mode, so a successful probe
                            // only confirms H2 connectivity during a downgrade window — it does
                            // not prove that H3 is healthy again.  H3 recovery is tested
                            // naturally: once the downgrade timer expires, the next real
                            // connection attempt uses H3 and resets the timer only if it fails.
                        }
                        if result.udp_applicable {
                            if !result.udp_ok {
                                status.udp_consecutive_failures =
                                    status.udp_consecutive_failures.saturating_add(1);
                                if status.udp_consecutive_failures >= min_failures as u32 {
                                    status.udp_healthy = Some(false);
                                    add_penalty(
                                        &mut status.udp_penalty,
                                        now,
                                        &self.inner.load_balancing,
                                    );
                                }
                            } else {
                                status.udp_consecutive_failures = 0;
                                status.udp_consecutive_successes =
                                    status.udp_consecutive_successes.saturating_add(1);
                                status.udp_healthy = Some(true);
                                status.cooldown_until_udp = None;
                            }
                        }
                        if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                            status.last_error = None;
                        }
                        (
                            status.tcp_rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
                            status.udp_rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
                        )
                    };
                    debug!(
                        uplink = %uplink.name,
                        tcp_healthy = result.tcp_ok,
                        udp_healthy = result.udp_ok,
                        tcp_latency_ms = result.tcp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
                        udp_latency_ms = result.udp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
                        tcp_rtt_ewma_ms,
                        udp_rtt_ewma_ms,
                        "uplink probe succeeded"
                    );
                    refill_tcp = result.tcp_ok;
                    // When UDP is not configured for this uplink, leave the
                    // standby pool alone (don't clear it, don't refill it).
                    refill_udp = result.udp_applicable && result.udp_ok;
                }
                Err(error) => {
                    {
                        let now = Instant::now();
                        let min_failures = self.inner.probe.min_failures;
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_consecutive_successes = 0;
                        status.tcp_consecutive_failures =
                            status.tcp_consecutive_failures.saturating_add(1);
                        if status.tcp_consecutive_failures >= min_failures as u32 {
                            status.tcp_healthy = Some(false);
                            add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                        }
                        // Only penalise UDP when it is actually configured.
                        // The probe Err path is usually a TCP connect failure;
                        // penalising UDP here when there is no udp_ws_url would
                        // permanently mark UDP unhealthy for TCP-only uplinks.
                        if uplink.supports_udp() {
                            status.udp_consecutive_failures =
                                status.udp_consecutive_failures.saturating_add(1);
                            if status.udp_consecutive_failures >= min_failures as u32 {
                                status.udp_healthy = Some(false);
                                add_penalty(
                                    &mut status.udp_penalty,
                                    now,
                                    &self.inner.load_balancing,
                                );
                            }
                        }
                        // Probe connection itself failed (ws connect / timeout).
                        // Same H3 downgrade logic as the tcp_ok=false case above.
                        if uplink.transport == UplinkTransport::Websocket
                            && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
                        {
                            let downgrade_until =
                                now + self.inner.load_balancing.h3_downgrade_duration;
                            if status.h3_tcp_downgrade_until.map_or(true, |t| t < now) {
                                warn!(
                                    uplink = %uplink.name,
                                    error = %format!("{error:#}"),
                                    downgrade_secs = self.inner.load_balancing.h3_downgrade_duration.as_secs(),
                                    "H3 probe connection failed, downgrading TCP to H2"
                                );
                            }
                            status.h3_tcp_downgrade_until = Some(downgrade_until);
                        }
                        status.last_error = Some(format!("{error:#}"));
                    }
                    warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
                }
            }

            if refill_tcp {
                self.spawn_refill(index, TransportKind::Tcp);
            } else {
                self.clear_standby(index, TransportKind::Tcp).await;
            }
            if refill_udp {
                self.spawn_refill(index, TransportKind::Udp);
            } else if uplink.supports_udp() {
                // Only clear UDP standby when UDP is actually configured.
                // Without this guard a TCP-only uplink would keep clearing an
                // already-empty UDP pool on every probe cycle.
                self.clear_standby(index, TransportKind::Udp).await;
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
