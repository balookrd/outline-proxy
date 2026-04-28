use std::cmp::Ordering;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::time::Instant;

use crate::config::{LoadBalancingMode, RoutingScope};
use socks5_proto::TargetAddr;

use super::super::routing_key::{routing_key, strict_route_key};
use super::super::selection::{
    cooldown_active, cooldown_remaining, score_latency, selection_health, selection_score,
    strict_gate_transport, supports_transport_for_scope,
};
use super::super::types::{CandidateState, TransportKind, UplinkCandidate, UplinkManager};

fn higher_weight_first(left_weight: f64, right_weight: f64) -> Ordering {
    right_weight.partial_cmp(&left_weight).unwrap_or(Ordering::Equal)
}

fn healthy_first(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

fn transport_reason_label(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "TCP",
        TransportKind::Udp => "UDP",
    }
}

fn transport_failover_detail(
    status: &super::super::types::UplinkStatus,
    transport: TransportKind,
    now: Instant,
    include_probe_health: bool,
) -> Option<String> {
    let label = transport_reason_label(transport);
    if include_probe_health && status.of(transport).healthy == Some(false) {
        Some(format!("{label} probe marked active unhealthy"))
    } else if cooldown_active(status, transport, now) {
        Some(format!("{label} runtime cooldown active"))
    } else {
        None
    }
}

impl UplinkManager {
    pub async fn tcp_candidates(&self, target: &TargetAddr) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Tcp) {
            return self
                .strict_transport_candidates(TransportKind::Tcp, Some(target), None, true)
                .await;
        }
        self.ordered_candidates(TransportKind::Tcp, Some(target)).await
    }

    pub async fn udp_candidates(&self, target: Option<&TargetAddr>) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Udp) {
            return self
                .strict_transport_candidates(TransportKind::Udp, target, None, true)
                .await;
        }
        self.ordered_candidates(TransportKind::Udp, target).await
    }

    pub async fn tcp_failover_candidates(
        &self,
        target: &TargetAddr,
        failed_active_index: usize,
    ) -> Vec<UplinkCandidate> {
        if self.strict_active_uplink_for(TransportKind::Tcp) {
            return self
                .strict_transport_candidates(
                    TransportKind::Tcp,
                    Some(target),
                    Some(failed_active_index),
                    false,
                )
                .await;
        }
        self.ordered_candidates(TransportKind::Tcp, Some(target)).await
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
        // In strict global mode with probe enabled, the global active uplink is
        // owned by (a) the operator via manual switch and (b) the probe loop —
        // not by per-session connect outcomes. Letting every successful connect
        // write `active_uplinks` here lets in-flight sessions that started
        // before a manual switch silently revert it: the session selected the
        // old active, succeeds (handshake passes even when the data path is
        // broken), and overwrites the operator's choice. Same rationale as
        // [`confirm_runtime_failover_uplink`] — only update sticky routes.
        let owns_active = !(self.strict_global_active_uplink() && self.inner.probe.enabled());
        if owns_active {
            self.set_active_uplink_index_for_transport(
                transport,
                uplink_index,
                "successful selection",
            )
            .await;
        }
        self.store_sticky_route(&routing_key, uplink_index).await;
        // Successful end-to-end connect on this uplink is strong evidence the
        // data path is alive — clear the runtime-failure streak so a transient
        // burst of failures does not push it to unhealthy.
        self.inner.with_status_mut(uplink_index, |status| match transport {
            TransportKind::Tcp => status.tcp.consecutive_runtime_failures = 0,
            TransportKind::Udp => status.udp.consecutive_runtime_failures = 0,
        });
    }

    pub async fn confirm_runtime_failover_uplink(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
        uplink_index: usize,
    ) {
        // In strict global mode with probes enabled, the probe is the
        // authoritative source of process-wide active-uplink health. A single
        // successful runtime failover should rescue only the current session,
        // not immediately repoint the global active uplink for all new
        // sessions. Otherwise transient chunk-0 stalls or mid-session transport
        // resets under load still cause visible global flapping even though the
        // probe continues to report the original uplink as healthy.
        if self.strict_global_active_uplink() && self.inner.probe.enabled() {
            return;
        }

        self.confirm_selected_uplink(transport, target, uplink_index).await;
    }

    pub async fn global_active_uplink_index(&self) -> Option<usize> {
        if !self.strict_global_active_uplink() {
            return None;
        }
        self.inner.active_uplinks.read().await.global
    }

    /// Non-side-effecting health check used by the dispatch layer to decide
    /// whether to route a connection here or to fall back to another target.
    ///
    /// Returns true when at least one transport-capable uplink in this group
    /// is currently healthy (probe-confirmed or, when probes are disabled,
    /// not in cooldown). Unlike [`Self::tcp_candidates`] / [`Self::udp_candidates`], this
    /// method does not touch sticky routes or active-uplink state.
    pub async fn has_any_healthy(&self, transport: TransportKind) -> bool {
        let now = Instant::now();
        let scope = self.inner.load_balancing.routing_scope;
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, u)| supports_transport_for_scope(u, transport, scope))
            .any(|(index, _)| {
                let status = self.inner.read_status(index);
                selection_health(&status, &self.inner.uplinks[index], transport, now, scope)
            })
    }

    pub async fn active_uplink_index_for_transport(
        &self,
        transport: TransportKind,
    ) -> Option<usize> {
        if self.strict_global_active_uplink() {
            return self.inner.active_uplinks.read().await.global;
        }
        if self.strict_per_uplink_active_uplink() {
            let active = self.inner.active_uplinks.read().await;
            return match transport {
                TransportKind::Tcp => active.tcp,
                TransportKind::Udp => active.udp,
            };
        }
        None
    }

    fn primary_order(&self, left: &CandidateState, right: &CandidateState) -> Ordering {
        healthy_first(left.healthy)
            .cmp(&healthy_first(right.healthy))
            .reverse()
            .then_with(|| {
                higher_weight_first(
                    self.inner.uplinks[left.index].weight,
                    self.inner.uplinks[right.index].weight,
                )
            })
            .then_with(|| {
                left.score
                    .unwrap_or(Duration::MAX)
                    .cmp(&right.score.unwrap_or(Duration::MAX))
            })
            .then_with(|| left.index.cmp(&right.index))
    }

    // Initial strict-mode selection (no previous active): weight before score
    // so that the configured priority signal dominates before any EWMA data.
    // Same shape as `primary_order` — kept as a separate function for clarity
    // at call sites that explicitly mark the cold-start case.
    fn initial_strict_order(&self, left: &CandidateState, right: &CandidateState) -> Ordering {
        healthy_first(left.healthy)
            .cmp(&healthy_first(right.healthy))
            .reverse()
            .then_with(|| {
                higher_weight_first(
                    self.inner.uplinks[left.index].weight,
                    self.inner.uplinks[right.index].weight,
                )
            })
            .then_with(|| {
                left.score
                    .unwrap_or(Duration::MAX)
                    .cmp(&right.score.unwrap_or(Duration::MAX))
            })
            .then_with(|| left.index.cmp(&right.index))
    }

    // Re-sort after a failed active uplink: prefer candidates whose cooldown
    // expires soonest, then honour configured priority (`weight`), then break
    // remaining ties with penalty-aware latency score.
    //
    // `weight` is treated as a hard priority — a deliberately downranked
    // backup must not win failover by virtue of a faster probe RTT alone.
    // Without this, `score = (EWMA + penalty) / weight` could let a
    // low-weight, low-EWMA uplink outrank a higher-weight one with similar
    // health, defeating the operator's intent.
    fn failover_order(
        &self,
        left: &CandidateState,
        right: &CandidateState,
        gate_transport: TransportKind,
        now: Instant,
    ) -> Ordering {
        let left_remaining = cooldown_remaining(&left.status, gate_transport, now);
        let right_remaining = cooldown_remaining(&right.status, gate_transport, now);
        let left_score = score_latency(
            &left.status,
            self.inner.uplinks[left.index].weight,
            gate_transport,
            now,
            &self.inner.load_balancing,
        );
        let right_score = score_latency(
            &right.status,
            self.inner.uplinks[right.index].weight,
            gate_transport,
            now,
            &self.inner.load_balancing,
        );
        healthy_first(left.healthy)
            .cmp(&healthy_first(right.healthy))
            .reverse()
            .then_with(|| left_remaining.cmp(&right_remaining))
            .then_with(|| {
                higher_weight_first(
                    self.inner.uplinks[left.index].weight,
                    self.inner.uplinks[right.index].weight,
                )
            })
            .then_with(|| {
                left_score
                    .unwrap_or(Duration::MAX)
                    .cmp(&right_score.unwrap_or(Duration::MAX))
            })
            .then_with(|| left.index.cmp(&right.index))
    }

    fn build_candidate_states(
        &self,
        transport: TransportKind,
        now: Instant,
    ) -> Vec<CandidateState> {
        let scope = self.inner.load_balancing.routing_scope;
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, uplink)| supports_transport_for_scope(uplink, transport, scope))
            .map(|(index, uplink)| {
                let status = self.inner.read_status(index);
                CandidateState {
                    index,
                    uplink: uplink.clone(),
                    healthy: selection_health(&status, uplink, transport, now, scope),
                    score: selection_score(
                        &status,
                        uplink.weight,
                        transport,
                        now,
                        &self.inner.load_balancing,
                        scope,
                    ),
                    status,
                }
            })
            .collect()
    }

    fn strict_active_failure_details(
        &self,
        candidate: &CandidateState,
        gate_transport: TransportKind,
        now: Instant,
    ) -> Vec<String> {
        let include_probe_health = self.inner.probe.enabled();
        let mut transports = vec![gate_transport];
        if self.inner.load_balancing.routing_scope == RoutingScope::Global
            && candidate.uplink.supports_udp()
            && gate_transport != TransportKind::Udp
        {
            transports.push(TransportKind::Udp);
        }
        transports
            .into_iter()
            .filter_map(|transport| {
                transport_failover_detail(&candidate.status, transport, now, include_probe_health)
            })
            .collect()
    }

    async fn ordered_candidates(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        let routing_key = routing_key(transport, target, self.inner.load_balancing.routing_scope);
        let now = Instant::now();

        let mut candidates = self.build_candidate_states(transport, now);

        if candidates.is_empty() {
            return Vec::new();
        }

        candidates.sort_by(|left, right| self.primary_order(left, right));

        let preferred_index = self
            .preferred_sticky_index(&routing_key, transport, &candidates)
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
            .map(|candidate| UplinkCandidate {
                index: candidate.index,
                uplink: candidate.uplink,
            })
            .collect()
    }

    pub(crate) async fn strict_transport_candidates(
        &self,
        transport: TransportKind,
        _target: Option<&TargetAddr>,
        failed_active_index: Option<usize>,
        commit_selection: bool,
    ) -> Vec<UplinkCandidate> {
        let now = Instant::now();
        let current_active = self.active_uplink_index_for_transport(transport).await;
        let mut candidates = self.build_candidate_states(transport, now);

        if candidates.is_empty() {
            return Vec::new();
        }

        if current_active.is_none() {
            candidates.sort_by(|left, right| self.initial_strict_order(left, right));
        } else {
            candidates.sort_by(|left, right| self.primary_order(left, right));
        }

        let gate_transport =
            strict_gate_transport(self.inner.load_balancing.routing_scope, transport);
        let mut switching_from_cooldown = false;
        let mut failover_reason: Option<String> = None;
        if let Some(active_index) = current_active {
            let active_failed = failed_active_index.is_some_and(|index| index == active_index);
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
                let active_failure_details =
                    self.strict_active_failure_details(candidate, gate_transport, now);
                let probe_healthy = if self.inner.probe.enabled() {
                    !active_failure_details
                        .iter()
                        .any(|detail| detail.contains("probe marked active unhealthy"))
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
                    probe_healthy && active_failure_details.is_empty()
                };
                if should_keep && !active_failed {
                    // When auto_failback is disabled (default), never switch away
                    // from a healthy active uplink — only failure triggers a switch.
                    if !self.inner.load_balancing.auto_failback {
                        if commit_selection {
                            let key = strict_route_key(
                                transport,
                                self.inner.load_balancing.routing_scope,
                            );
                            self.store_sticky_route(&key, active_index).await;
                        }
                        return vec![UplinkCandidate {
                            index: candidate.index,
                            uplink: candidate.uplink.clone(),
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
                                    TransportKind::Tcp => b.status.tcp.healthy == Some(true),
                                    TransportKind::Udp => b.status.udp.healthy == Some(true),
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
                    let best_is_stable = best.is_none_or(|b| {
                        let min = self.inner.probe.min_failures as u32;
                        let consecutive = match gate_transport {
                            TransportKind::Tcp => b.status.tcp.consecutive_successes,
                            TransportKind::Udp => b.status.udp.consecutive_successes,
                        };
                        consecutive >= min
                    });
                    if is_best || !best_is_stable {
                        if commit_selection {
                            let key = strict_route_key(
                                transport,
                                self.inner.load_balancing.routing_scope,
                            );
                            self.store_sticky_route(&key, active_index).await;
                        }
                        return vec![UplinkCandidate {
                            index: candidate.index,
                            uplink: candidate.uplink.clone(),
                        }];
                    }
                    // Current active is healthy but the best candidate is stable
                    // enough to switch to.  Fall through; switching_from_cooldown
                    // stays false so we use base (penalty-free) scoring.
                } else {
                    // Active uplink is unhealthy or on cooldown — switch with
                    // penalty-aware re-sort to avoid oscillating back immediately.
                    switching_from_cooldown = true;
                    let gate_label = transport_reason_label(gate_transport);
                    let mut details = vec![if active_failed {
                        format!("failover: {gate_label} runtime failure on active uplink")
                    } else {
                        active_failure_details
                            .first()
                            .cloned()
                            .map(|detail| format!("failover: {detail}"))
                            .unwrap_or_else(|| {
                                format!(
                                    "failover: {gate_label} active gate rejected current uplink"
                                )
                            })
                    }];
                    for detail in active_failure_details.iter().skip(1) {
                        details.push(detail.clone());
                    }
                    failover_reason = Some(details.join("; "));
                }
            } else {
                // Active uplink no longer in the candidate set — re-select.
                switching_from_cooldown = true;
                failover_reason = Some(format!(
                    "failover: active uplink no longer supports {}",
                    transport_reason_label(gate_transport)
                ));
            }
        }

        // When we are switching away from a failed active uplink (cooldown is
        // active), re-sort candidates so that unhealthy uplinks whose cooldown
        // expires sooner are tried first, with penalty-aware score as a
        // secondary key. For the initial selection (no previous active)
        // penalties are ignored to preserve the intent that strict-mode
        // selection is EWMA-driven.
        if switching_from_cooldown {
            candidates.sort_by(|left, right| self.failover_order(left, right, gate_transport, now));
        }

        if commit_selection {
            let selected = candidates[0].index;
            let reason = match (current_active, switching_from_cooldown) {
                (None, _) => "initial selection",
                (Some(_), false) => "auto-failback to higher priority uplink",
                (Some(_), true) => failover_reason
                    .as_deref()
                    .unwrap_or("failover: active unhealthy or in cooldown"),
            };
            self.set_active_uplink_index_for_transport(transport, selected, reason)
                .await;
            let key = strict_route_key(transport, self.inner.load_balancing.routing_scope);
            self.store_sticky_route(&key, selected).await;
            return vec![UplinkCandidate {
                index: selected,
                uplink: candidates[0].uplink.clone(),
            }];
        }

        candidates
            .into_iter()
            .map(|candidate| UplinkCandidate {
                index: candidate.index,
                uplink: candidate.uplink,
            })
            .collect()
    }

    /// Manually switch the active uplink for this group to the one identified
    /// by `name`. When `transport` is `Some(_)` and the group runs in
    /// `per_uplink` routing scope, only that transport is switched; otherwise
    /// both transports are updated. The selection is persisted via the state
    /// store (if configured) so it survives restarts.
    ///
    /// Returns the chosen uplink index. Errors when the group is not in
    /// `active_passive` mode or when the name does not match any configured
    /// uplink in this group.
    pub async fn set_active_uplink_by_name(
        &self,
        name: &str,
        transport: Option<TransportKind>,
    ) -> Result<usize> {
        if self.inner.load_balancing.mode != LoadBalancingMode::ActivePassive {
            bail!(
                "manual switch is only supported in active_passive mode (group \"{}\" is {:?})",
                self.inner.group_name,
                self.inner.load_balancing.mode
            );
        }
        let index = self
            .inner
            .uplinks
            .iter()
            .position(|u| u.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "uplink \"{}\" not found in group \"{}\"",
                    name,
                    self.inner.group_name
                )
            })?;

        // Manual switch is a clean-slate signal from the operator: clear all
        // accumulated probe/runtime metrics so the auto-selection loop cannot
        // immediately revert to a different uplink based on stale health,
        // cooldowns, EWMA or penalties. Without this reset, a chosen uplink
        // whose `healthy == Some(false)` or whose cooldown is still active
        // would be overridden by `strict_transport_candidates` on the next
        // dispatch.
        self.reset_all_uplink_statuses();
        // Drop sticky routes too — they may pin traffic to the previous active
        // uplink for sessions that already cached a routing decision. We
        // re-seed the relevant keys below.
        self.inner.sticky_routes.write().await.clear();

        if self.strict_global_active_uplink() {
            self.set_active_uplink_index_for_transport(TransportKind::Tcp, index, "manual switch")
                .await;
        } else if self.strict_per_uplink_active_uplink() {
            match transport {
                Some(t) => {
                    self.set_active_uplink_index_for_transport(t, index, "manual switch")
                        .await;
                },
                None => {
                    self.set_active_uplink_index_for_transport(
                        TransportKind::Tcp,
                        index,
                        "manual switch",
                    )
                    .await;
                    self.set_active_uplink_index_for_transport(
                        TransportKind::Udp,
                        index,
                        "manual switch",
                    )
                    .await;
                },
            }
        }

        // Refresh sticky route(s) so the next dispatch immediately observes
        // the override instead of being routed by the old sticky entry.
        let scope = self.inner.load_balancing.routing_scope;
        if scope == RoutingScope::Global {
            let key = strict_route_key(TransportKind::Tcp, scope);
            self.store_sticky_route(&key, index).await;
        } else if scope == RoutingScope::PerUplink {
            for t in [TransportKind::Tcp, TransportKind::Udp] {
                if transport.is_none() || transport == Some(t) {
                    let key = strict_route_key(t, scope);
                    self.store_sticky_route(&key, index).await;
                }
            }
        }

        // Wake up the probe loop so a fresh health/latency reading is
        // collected immediately for the cleared statuses instead of waiting
        // for the next scheduled probe interval.
        self.inner.probe_wakeup.notify_waiters();

        Ok(index)
    }

    /// Clear every per-uplink status field used by the auto-selection logic:
    /// healthy flags, cooldowns, EWMA/latency, penalties, consecutive
    /// success/failure counters, h3 downgrade gate, and last error. Called on
    /// manual switch so accumulated state from a degraded period does not
    /// influence the new selection.
    fn reset_all_uplink_statuses(&self) {
        for slot in self.inner.statuses.iter() {
            *slot.lock() = Default::default();
        }
    }

    pub(crate) async fn set_active_uplink_index_for_transport(
        &self,
        transport: TransportKind,
        uplink_index: usize,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        if self.strict_global_active_uplink() {
            let mut active = self.inner.active_uplinks.write().await;
            let changed = active.global != Some(uplink_index);
            active.global = Some(uplink_index);
            if changed || active.global_reason.is_none() || reason == "manual switch" {
                active.global_reason = Some(reason.clone());
            }
        } else if self.strict_per_uplink_active_uplink() {
            match transport {
                TransportKind::Tcp => {
                    let mut active = self.inner.active_uplinks.write().await;
                    let changed = active.tcp != Some(uplink_index);
                    active.tcp = Some(uplink_index);
                    if changed || active.tcp_reason.is_none() || reason == "manual switch" {
                        active.tcp_reason = Some(reason.clone());
                    }
                },
                TransportKind::Udp => {
                    let mut active = self.inner.active_uplinks.write().await;
                    let changed = active.udp != Some(uplink_index);
                    active.udp = Some(uplink_index);
                    if changed || active.udp_reason.is_none() || reason == "manual switch" {
                        active.udp_reason = Some(reason.clone());
                    }
                },
            }
        }

        if let Some(store) = &self.inner.state_store {
            let uplink_name = self.inner.uplinks[uplink_index].name.clone();
            let group_name = &self.inner.group_name;
            if self.strict_global_active_uplink() {
                store
                    .update_active(group_name, Some(Some(uplink_name)), None, None)
                    .await;
            } else {
                match transport {
                    TransportKind::Tcp => {
                        store
                            .update_active(group_name, None, Some(Some(uplink_name)), None)
                            .await;
                    },
                    TransportKind::Udp => {
                        store
                            .update_active(group_name, None, None, Some(Some(uplink_name)))
                            .await;
                    },
                }
            }
        }
    }
}
