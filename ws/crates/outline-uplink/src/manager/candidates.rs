use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::time::Instant;

use crate::config::{LoadBalancingMode, RoutingScope};
use socks5_proto::TargetAddr;

use super::super::selection::{
    cooldown_active, cooldown_remaining, score_latency, selection_health, selection_score,
    strict_gate_transport, supports_transport_for_scope,
};
use super::super::types::{CandidateState, TransportKind, UplinkCandidate, UplinkManager};
use super::super::utils::{rightless_bool, routing_key, strict_route_key};

fn higher_weight_first(left_weight: f64, right_weight: f64) -> Ordering {
    right_weight.partial_cmp(&left_weight).unwrap_or(Ordering::Equal)
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
        self.set_active_uplink_index_for_transport(transport, uplink_index)
            .await;
        self.store_sticky_route(&routing_key, uplink_index).await;
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
    /// not in cooldown). Unlike [`tcp_candidates`] / [`udp_candidates`], this
    /// method does not touch sticky routes or active-uplink state.
    pub async fn has_any_healthy(&self, transport: TransportKind) -> bool {
        let statuses = self.inner.statuses.read().await.clone();
        let now = Instant::now();
        let scope = self.inner.load_balancing.routing_scope;
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, u)| supports_transport_for_scope(u, transport, scope))
            .any(|(index, _)| selection_health(&statuses[index], transport, now, scope))
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

    async fn ordered_candidates(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        self.prune_sticky_routes().await;
        let routing_key = routing_key(transport, target, self.inner.load_balancing.routing_scope);
        let statuses = self.inner.statuses.read().await.clone();
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
                .then_with(|| {
                    higher_weight_first(
                        self.inner.uplinks[left.index].weight,
                        self.inner.uplinks[right.index].weight,
                    )
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
        self.prune_sticky_routes().await;
        let statuses = self.inner.statuses.read().await.clone();
        let now = Instant::now();
        let current_active = self.active_uplink_index_for_transport(transport).await;
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

        if current_active.is_none() {
            candidates.sort_by(|left, right| {
                rightless_bool(left.healthy)
                    .cmp(&rightless_bool(right.healthy))
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
            });
        } else {
            candidates.sort_by(|left, right| {
                rightless_bool(left.healthy)
                    .cmp(&rightless_bool(right.healthy))
                    .reverse()
                    .then_with(|| {
                        left.score
                            .unwrap_or(Duration::MAX)
                            .cmp(&right.score.unwrap_or(Duration::MAX))
                    })
                    .then_with(|| {
                        higher_weight_first(
                            self.inner.uplinks[left.index].weight,
                            self.inner.uplinks[right.index].weight,
                        )
                    })
                    .then_with(|| left.index.cmp(&right.index))
            });
        }

        let gate_transport =
            strict_gate_transport(self.inner.load_balancing.routing_scope, transport);
        let mut switching_from_cooldown = false;
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
                let probe_healthy = if self.inner.probe.enabled() {
                    match gate_transport {
                        TransportKind::Tcp => {
                            statuses[active_index].tcp.healthy != Some(false)
                        },
                        TransportKind::Udp => {
                            statuses[active_index].udp.healthy != Some(false)
                        },
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
                                        statuses[b.index].tcp.healthy == Some(true)
                                    },
                                    TransportKind::Udp => {
                                        statuses[b.index].udp.healthy == Some(true)
                                    },
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
                            TransportKind::Tcp => {
                                statuses[b.index].tcp.consecutive_successes
                            },
                            TransportKind::Udp => {
                                statuses[b.index].udp.consecutive_successes
                            },
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
                    .then_with(|| {
                        higher_weight_first(
                            self.inner.uplinks[left.index].weight,
                            self.inner.uplinks[right.index].weight,
                        )
                    })
                    .then_with(|| left.index.cmp(&right.index))
            });
        }

        if commit_selection {
            let selected = candidates[0].index;
            self.set_active_uplink_index_for_transport(transport, selected).await;
            let key = strict_route_key(transport, self.inner.load_balancing.routing_scope);
            self.store_sticky_route(&key, selected).await;
            return vec![UplinkCandidate {
                index: selected,
                uplink: Arc::clone(&candidates[0].uplink),
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

        if self.strict_global_active_uplink() {
            self.set_active_uplink_index_for_transport(TransportKind::Tcp, index)
                .await;
        } else if self.strict_per_uplink_active_uplink() {
            match transport {
                Some(t) => {
                    self.set_active_uplink_index_for_transport(t, index).await;
                },
                None => {
                    self.set_active_uplink_index_for_transport(TransportKind::Tcp, index)
                        .await;
                    self.set_active_uplink_index_for_transport(TransportKind::Udp, index)
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

        Ok(index)
    }

    pub(crate) async fn set_active_uplink_index_for_transport(
        &self,
        transport: TransportKind,
        uplink_index: usize,
    ) {
        if self.strict_global_active_uplink() {
            self.inner.active_uplinks.write().await.global = Some(uplink_index);
        } else if self.strict_per_uplink_active_uplink() {
            match transport {
                TransportKind::Tcp => {
                    self.inner.active_uplinks.write().await.tcp = Some(uplink_index);
                },
                TransportKind::Udp => {
                    self.inner.active_uplinks.write().await.udp = Some(uplink_index);
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
