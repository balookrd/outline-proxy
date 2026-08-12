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
    /// `salt -> last_seen_secs`. The salt is the whole random prefix, so it is
    /// its own key; the value is only used by the TTL reaper.
    entries: DashMap<Arc<[u8]>, u64>,
    idle_timeout: Duration,
    max_salts: usize,
}

impl SaltReplayStore {
    /// `max_salts = 0` disables the cap.
    pub(crate) fn new(idle_timeout: Duration, max_salts: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            idle_timeout,
            max_salts,
        })
    }

    /// Records a request `salt` and reports whether it is `Fresh`, a `Replay`,
    /// or dropped because the store is at capacity.
    pub(crate) fn check_and_mark(&self, salt: Arc<[u8]>) -> SaltReplayCheck {
        self.check_and_mark_at(salt, clock::current_unix_secs())
    }

    fn check_and_mark_at(&self, salt: Arc<[u8]>, now: u64) -> SaltReplayCheck {
        // Fast path: a salt we already hold is always a replay — there is no
        // window to advance, so its `last_seen` is left untouched and the TTL
        // keeps counting from first sighting.
        if self.entries.contains_key(&salt) {
            return SaltReplayCheck::Replay;
        }
        // Check the cap before taking a shard write lock in `entry(...)`.
        // `len()` takes per-shard read locks; doing it while holding a shard
        // write lock could deadlock against a concurrent `len()`. The race
        // between the check and the insert is benign: the cap is a soft bound,
        // and at worst one extra salt is registered per racing caller.
        if self.max_salts > 0 && self.entries.len() >= self.max_salts {
            return SaltReplayCheck::StoreFull;
        }
        match self.entries.entry(salt) {
            // Raced with another caller that inserted the same salt first.
            Entry::Occupied(_) => SaltReplayCheck::Replay,
            Entry::Vacant(v) => {
                v.insert(now);
                SaltReplayCheck::Fresh
            },
        }
    }

    /// Drop entries idle for longer than `idle_timeout`. Returns the count
    /// reaped.
    pub(crate) fn evict_idle(&self) -> usize {
        self.evict_idle_at(clock::current_unix_secs())
    }

    fn evict_idle_at(&self, now: u64) -> usize {
        let threshold = now.saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        self.entries.retain(|_, last_seen| {
            if *last_seen < threshold {
                evicted += 1;
                false
            } else {
                true
            }
        });
        evicted
    }
}

#[cfg(test)]
#[path = "tests/salt_replay.rs"]
mod tests;
