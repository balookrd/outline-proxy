//! Deterministic re-selection order shared by independent nodes.
//!
//! `reselect_at` rotation is normally an OS-seeded draw over locally-weighted
//! candidates, so two nodes running the same config land on different uplinks
//! and their users leave from different egress addresses. Under
//! [`LoadBalancingConfig::reselect_sync`](crate::config::LoadBalancingConfig::reselect_sync)
//! the draw is replaced by a function of data every node already agrees on —
//! group name, uplink names, the local calendar day and the slot index — so
//! agreement needs no communication.
//!
//! Health, cooldown and admin state stay strictly local: they filter the
//! shared order rather than shape it. That is deliberate — a node whose leg
//! dies must leave immediately, without waiting for anyone.

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::time::Instant;

use crate::config::RoutingScope;
use crate::penalty::weighted_permutation_with_rng;
use crate::selection::{cooldown_active, selection_health, supports_transport_for_scope};
use crate::types::{TransportKind, UplinkManager};

/// BLAKE3 derive-key context. Bump the version suffix only for a deliberate,
/// fleet-wide reshuffle: changing it makes every node compute a new order, and
/// nodes on mixed builds disagree until all of them are updated.
const SYNC_SEED_CONTEXT: &str = "outline-ws-rust reselect-sync seed v1";

/// One firing of the wall-clock schedule: the local calendar day it belongs
/// to plus the index of the slot within the group's sorted `reselect_at`.
/// Two nodes in the same timezone compute the same `SlotKey` for the same
/// instant, which is the whole basis of their agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotKey {
    pub(crate) day_key: i64,
    pub(crate) slot: usize,
}

/// The slot whose decision is currently in force: the last one at or before
/// `secs_of_day`, or — before the day's first slot — the previous day's last
/// slot. Returns `None` only when no slots are configured, which the config
/// loader already refuses in combination with `reselect_sync`.
///
/// `slots` must be sorted ascending; the loader sorts and dedups `reselect_at`.
pub(crate) fn current_slot_key(
    day_key: i64,
    secs_of_day: u32,
    slots: &[(u8, u8)],
) -> Option<SlotKey> {
    let last = slots.len().checked_sub(1)?;
    let passed = slots
        .iter()
        .rposition(|&(h, m)| u32::from(h) * 3600 + u32::from(m) * 60 <= secs_of_day);
    Some(match passed {
        Some(slot) => SlotKey { day_key, slot },
        None => SlotKey { day_key: day_key - 1, slot: last },
    })
}

/// The firing before `key`. Used for the rotation exclusion: the previous
/// slot's deterministic winner is what this slot's order must move away from,
/// and unlike "the current active uplink" it is identical on every node.
pub(crate) fn previous_slot_key(key: SlotKey, slots: &[(u8, u8)]) -> SlotKey {
    match key.slot.checked_sub(1) {
        Some(slot) => SlotKey { day_key: key.day_key, slot },
        None => SlotKey {
            day_key: key.day_key - 1,
            slot: slots.len().saturating_sub(1),
        },
    }
}

/// Seed shared by every node that agrees on `(group, uplink names, slot)`.
///
/// Names are NUL-separated so `["ab", "c"]` and `["a", "bc"]` cannot collide —
/// a collision would silently merge two configurations into one sync domain.
/// Nothing secret goes in: the order is derived from configuration, not from
/// credentials, and is reproducible by anyone who knows the uplink names.
pub(crate) fn sync_seed(group: &str, uplink_names: &[&str], key: SlotKey) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key(SYNC_SEED_CONTEXT);
    hasher.update(group.as_bytes());
    hasher.update(&[0]);
    for name in uplink_names {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
    }
    hasher.update(&key.day_key.to_le_bytes());
    // `usize` is widened explicitly: the seed must not depend on the pointer
    // width of the node computing it.
    hasher.update(&(key.slot as u64).to_le_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(head)
}

impl UplinkManager {
    /// Preference order for `key`: a permutation of every uplink index, most
    /// preferred first, weighted by the **configured** `weight` alone.
    ///
    /// Local penalty and health state is deliberately absent — it differs per
    /// node and would defeat the shared seed. Health filters this order later,
    /// in [`Self::sync_pick`].
    pub(crate) fn sync_order(&self, key: SlotKey) -> Vec<usize> {
        let names: Vec<&str> = self.inner.uplinks.iter().map(|u| u.name.as_str()).collect();
        let seed = sync_seed(self.group_name(), &names, key);
        let weights: Vec<f64> = self.inner.uplinks.iter().map(|u| u.weight.max(0.0)).collect();
        let mut rng = StdRng::seed_from_u64(seed);
        weighted_permutation_with_rng(&weights, &mut rng)
    }

    /// The uplink this slot selects on this node: the first entry of the
    /// shared order that is locally usable, skipping the previous slot's
    /// deterministic winner so a slot still rotates.
    ///
    /// The exclusion is advisory. Enforcing it when nothing else is healthy
    /// would leave this node either idle or on a stale leg while its twin sat
    /// on the one working uplink — exactly the divergence this feature exists
    /// to prevent — so it is dropped in that case.
    pub(crate) fn sync_pick(
        &self,
        key: SlotKey,
        gate: TransportKind,
        scope: RoutingScope,
        now: Instant,
    ) -> Option<usize> {
        let order = self.sync_order(key);
        let previous = previous_slot_key(key, &self.inner.load_balancing.reselect_at);
        let excluded = self.sync_order(previous).first().copied();
        self.first_eligible(&order, gate, scope, now, excluded)
            .or_else(|| self.first_eligible(&order, gate, scope, now, None))
    }

    /// First index of `order` this node may actually use right now:
    /// administratively enabled, able to carry `gate` under `scope`, health-
    /// eligible and not cooling down. Mirrors the filter in
    /// `reselect::draw_reselect_candidate`, minus the weighting.
    fn first_eligible(
        &self,
        order: &[usize],
        gate: TransportKind,
        scope: RoutingScope,
        now: Instant,
        exclude: Option<usize>,
    ) -> Option<usize> {
        order.iter().copied().find(|&index| {
            if exclude == Some(index) || !self.inner.admin_enabled(index) {
                return false;
            }
            let uplink = &self.inner.uplinks[index];
            if !supports_transport_for_scope(uplink, gate, scope) {
                return false;
            }
            self.inner.with_status(index, |status| {
                selection_health(status, uplink, gate, now, scope, &self.inner.load_balancing)
                    && !cooldown_active(status, gate, now)
            })
        })
    }
}

#[cfg(test)]
#[path = "tests/sync_order.rs"]
mod tests;
