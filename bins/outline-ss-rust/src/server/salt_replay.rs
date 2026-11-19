//! Anti-replay filter for Shadowsocks TCP handshakes.
//!
//! A Shadowsocks TCP handshake is `salt || AEAD(fixed_header) || …`. The
//! session key is derived deterministically from `salt` and the user PSK, so a
//! passive attacker who captures a full handshake can re-submit it verbatim:
//! the server re-derives the same key, the AEAD opens, and for SS-2022 the
//! `validate_timestamp` check still passes inside its ±30-second window (legacy
//! AEAD has no timestamp at all, so a captured handshake replays forever). The
//! request is then re-executed against the same target with the same payload.
//!
//! Keeping the recently-seen request salts and rejecting a repeat closes that
//! window. The salt is a fresh random value per handshake, so it is globally
//! unique and suffices as the key on its own — no per-user partitioning is
//! needed for correctness.
//!
//! Mirrors [`crate::server::replay::ReplayStore`] (the SS-2022 UDP filter):
//! a bounded `DashMap` with a TTL reaper and a `StoreFull` outcome that
//! distinguishes a capacity drop from an actual replay.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::clock;

/// Outcome of [`SaltReplayStore::check_and_mark`]. `StoreFull` distinguishes a
/// capacity-driven miss from a genuine replay: the call site treats the two
/// differently (fail-open on capacity, reject on replay).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SaltReplayCheck {
    Fresh,
    Replay,
    StoreFull,
}

/// Process-wide store of request salts seen on TCP handshakes. Entries idle for
/// longer than `idle_timeout` are reaped by [`Self::evict_idle`]. A non-zero
/// `max_salts` caps the number of retained salts so a flood of unique
/// handshakes cannot inflate memory between eviction sweeps.
pub(crate) struct SaltReplayStore {
    /// `salt -> (user_id, last_seen_secs)`. The salt is the whole random prefix,
    /// so it is its own key; the value retains identity and timestamp for
    /// quota accounting and the TTL reaper.
    entries: DashMap<Arc<[u8]>, (Arc<str>, u64)>,
    /// Per-user active salt counter for quota enforcement and isolation.
    user_counts: DashMap<Arc<str>, usize>,
    idle_timeout: Duration,
    max_salts: usize,
    max_salts_per_user: usize,
}

impl SaltReplayStore {
    /// `max_salts = 0` disables the cap.
    pub(crate) fn new(idle_timeout: Duration, max_salts: usize) -> Arc<Self> {
        let max_salts_per_user = if max_salts > 0 { (max_salts / 2).max(1) } else { 0 };
        Self::with_per_user_limit(idle_timeout, max_salts, max_salts_per_user)
    }

    /// Creates a store with an explicit per-user salt limit.
    pub(crate) fn with_per_user_limit(
        idle_timeout: Duration,
        max_salts: usize,
        max_salts_per_user: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            user_counts: DashMap::new(),
            idle_timeout,
            max_salts,
            max_salts_per_user,
        })
    }

    /// Records a request `salt` for `user_id` and reports whether it is `Fresh`,
    /// a `Replay`, or dropped because the store or per-user quota is at capacity.
    pub(crate) fn check_and_mark(&self, user_id: &Arc<str>, salt: Arc<[u8]>) -> SaltReplayCheck {
        self.check_and_mark_at(user_id, salt, clock::current_unix_secs())
    }

    pub(crate) fn check_and_mark_at(
        &self,
        user_id: &Arc<str>,
        salt: Arc<[u8]>,
        now: u64,
    ) -> SaltReplayCheck {
        // Fast path: a salt we already hold is always a replay — there is no
        // window to advance, so its `last_seen` is left untouched and the TTL
        // keeps counting from first sighting.
        if self.entries.contains_key(&salt) {
            return SaltReplayCheck::Replay;
        }

        // Per-user quota check: prevent a single noisy tenant from exhausting
        // the global store and degrading replay protection for other users.
        if self.max_salts_per_user > 0
            && let Some(count) = self.user_counts.get(user_id)
            && *count >= self.max_salts_per_user
        {
            return SaltReplayCheck::StoreFull;
        }

        // Check the cap before taking a shard write lock in `entry(...)`.
        // `len()` takes per-shard read locks; doing it while holding a shard
        // write lock could deadlock against a concurrent `len()`. If full,
        // attempt an inline eviction of expired entries first.
        if self.max_salts > 0 && self.entries.len() >= self.max_salts {
            self.evict_idle_at(now);
            if self.entries.len() >= self.max_salts {
                return SaltReplayCheck::StoreFull;
            }
        }

        match self.entries.entry(salt) {
            // Raced with another caller that inserted the same salt first.
            Entry::Occupied(_) => SaltReplayCheck::Replay,
            Entry::Vacant(v) => {
                v.insert((Arc::clone(user_id), now));
                if self.max_salts_per_user > 0 {
                    *self.user_counts.entry(Arc::clone(user_id)).or_default() += 1;
                }
                SaltReplayCheck::Fresh
            },
        }
    }

    /// Drop entries idle for longer than `idle_timeout`. Returns the count
    /// reaped.
    pub(crate) fn evict_idle(&self) -> usize {
        self.evict_idle_at(clock::current_unix_secs())
    }

    pub(crate) fn evict_idle_at(&self, now: u64) -> usize {
        let threshold = now.saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        let mut decrements: std::collections::HashMap<Arc<str>, usize> =
            std::collections::HashMap::new();

        self.entries.retain(|_, (user_id, last_seen)| {
            if *last_seen < threshold {
                evicted += 1;
                *decrements.entry(Arc::clone(user_id)).or_default() += 1;
                false
            } else {
                true
            }
        });

        if !decrements.is_empty() {
            for (user_id, count) in decrements {
                match self.user_counts.entry(user_id) {
                    Entry::Occupied(mut occ) => {
                        if *occ.get() <= count {
                            occ.remove();
                        } else {
                            *occ.get_mut() -= count;
                        }
                    },
                    Entry::Vacant(_) => {},
                }
            }
        }

        evicted
    }
}

#[cfg(test)]
#[path = "tests/salt_replay.rs"]
mod tests;
