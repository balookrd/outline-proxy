use std::time::Duration;

use tokio::time::Instant;

use crate::config::{LoadBalancingMode, RoutingScope};
use crate::memory::maybe_shrink_hash_map;

use super::super::selection::score_latency;
use super::super::types::{
    CandidateState, RoutingKey, StickyRoute, TransportKind, UplinkManager, UplinkStatus,
};

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

    pub(super) async fn store_sticky_route(&self, routing_key: &RoutingKey, uplink_index: usize) {
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
            }
            RoutingScope::PerUplink => {
                self.strict_per_uplink_active_uplink()
                    && matches!(key, RoutingKey::TransportGlobal(_))
            }
            RoutingScope::PerFlow => false,
        }
    }
}
