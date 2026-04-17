use std::time::Duration;

use tokio::time::Instant;

use crate::config::{LoadBalancingMode, RoutingScope};
use crate::memory::maybe_shrink_hash_map;

use super::super::selection::score_latency;
use super::super::types::{
    CandidateState, RoutingKey, StickyRoute, TransportKind, UplinkManager, UplinkStatus,
};

/// Hard cap on non-pinned per-flow sticky-route entries.
///
/// Pinned entries (the global active uplink and per-transport active uplinks in
/// strict ActivePassive mode) are always stored regardless of this limit because
/// there are at most `2 * num_uplinks` of them and they are critical for
/// correctness.  Per-flow entries, however, grow one-per-unique-target and can
/// reach millions under traffic from large NAT pools or many distinct clients.
///
/// When the cap is hit, new per-flow entries are silently dropped: the flow
/// falls through to a fresh latency-ordered selection instead of a sticky one.
/// This degrades stickiness for the marginal flows but preserves memory safety.
const MAX_STICKY_ROUTES: usize = 100_000;

impl UplinkManager {
    pub(super) async fn preferred_sticky_index(
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

        let fastest = candidates
            .iter()
            .find(|candidate| candidate.healthy)
            .unwrap_or(sticky);
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
            },
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

    pub(super) async fn store_sticky_route(&self, routing_key: &RoutingKey, uplink_index: usize) {
        let pinned = self.strict_pinned_route_key(routing_key);
        let mut sticky = self.inner.sticky_routes.write().await;
        // Enforce the per-flow cap: drop new non-pinned entries when full.
        // Already-present keys are always updated (they don't add to the count).
        if !pinned && sticky.len() >= MAX_STICKY_ROUTES && !sticky.contains_key(routing_key) {
            return;
        }
        sticky.insert(
            routing_key.clone(),
            StickyRoute {
                uplink_index,
                expires_at: if pinned {
                    Instant::now() + Duration::from_secs(365 * 24 * 60 * 60)
                } else {
                    Instant::now() + self.inner.load_balancing.sticky_ttl
                },
            },
        );
    }

    pub(super) async fn prune_sticky_routes(&self) {
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
            },
            RoutingScope::PerUplink => {
                self.strict_per_uplink_active_uplink()
                    && matches!(key, RoutingKey::TransportGlobal(_))
            },
            RoutingScope::PerFlow => false,
        }
    }
}
