//! Anti-replay filter for SS-2022 and legacy Shadowsocks UDP.
//!
//! SS-2022 carries a per-session monotonic `packet_id` in the UDP header.
//! AEAD alone does not prevent a passive attacker from re-submitting a
//! captured ciphertext within the 30-second timestamp window — the decrypt
//! succeeds every time. Keeping a sliding bitmap of recently-seen packet IDs
//! per `client_session_id` rejects those replays while tolerating
//! reordering up to `WINDOW_BITS` slots.
//!
//! Keyed by `client_session_id` (not `NatKey`) because one session may
//! address many upstream targets, and a replay to a *new* target would
//! otherwise spawn a fresh NAT entry with an empty bitmap and bypass the
//! filter entirely.
//!
//! Legacy (pre-2022) UDP has no session id, packet counter or timestamp — a
//! captured datagram re-decrypts and re-forwards forever otherwise. The only
//! per-datagram anchor is its random request salt, so legacy datagrams are
//! de-duplicated by salt in a second bounded set that shares this store's cap
//! and idle-eviction. Without a timestamp the window is memory-bounded rather
//! than complete: once a salt is evicted the same datagram reads fresh again.
//! Remembering every salt forever would be the only complete defence, and that
//! is unbounded memory — so this trades completeness for a bounded footprint,
//! and SS-2022 remains the cipher suite with full replay protection.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use dashmap::{DashMap, mapref::entry::Entry};
use parking_lot::Mutex;

use crate::clock;
use crate::crypto::UdpCipherMode;

/// For SS-2022 sessions, extract the `(client_session_id, packet_id)` pair used
/// as the replay-filter key. Returns `None` for legacy sessions which have no
/// per-packet counter.
pub(crate) fn replay_key(
    session: &UdpCipherMode,
    packet_id: Option<u64>,
) -> Option<([u8; 8], u64)> {
    let csid = match session {
        UdpCipherMode::Legacy => return None,
        UdpCipherMode::Aes2022 { client_session_id }
        | UdpCipherMode::Chacha2022 { client_session_id } => *client_session_id,
    };
    packet_id.map(|pid| (csid, pid))
}

/// Window width in packet-id slots. 1024 bits = 128 bytes per session — large
/// enough to tolerate normal UDP reordering, small enough to keep per-session
/// footprint trivial.
const WINDOW_BITS: u64 = 1024;
const BITMAP_WORDS: usize = (WINDOW_BITS as usize) / 64;

/// Sliding-window replay filter for one client session.
///
/// The window tracks the most recently seen `packet_id` as `highest` and
/// marks observed IDs in a bitmap: bit `i` corresponds to `highest - i`.
#[derive(Debug)]
struct ReplayWindow {
    highest: u64,
    /// `bitmap[0]` low bit = `highest`, bit 1 = `highest - 1`, ... .
    bitmap: [u64; BITMAP_WORDS],
    /// Whether any packet has been accepted yet. Distinguishes "never seen
    /// anything" from "highest == 0 was legitimately accepted".
    initialised: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; BITMAP_WORDS],
            initialised: false,
        }
    }

    /// Try to accept `packet_id`. Returns `true` if fresh, `false` if a
    /// replay (already seen or too old to tell).
    fn check_and_mark(&mut self, packet_id: u64) -> bool {
        if !self.initialised {
            self.initialised = true;
            self.highest = packet_id;
            self.set_bit(0);
            return true;
        }

        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.shift_left(shift);
            self.highest = packet_id;
            self.set_bit(0);
            return true;
        }

        let offset = self.highest - packet_id;
        if offset >= WINDOW_BITS {
            return false;
        }
        let offset = offset as usize;
        if self.get_bit(offset) {
            return false;
        }
        self.set_bit(offset);
        true
    }

    fn set_bit(&mut self, offset: usize) {
        let (word, bit) = (offset / 64, offset % 64);
        self.bitmap[word] |= 1u64 << bit;
    }

    fn get_bit(&self, offset: usize) -> bool {
        let (word, bit) = (offset / 64, offset % 64);
        (self.bitmap[word] >> bit) & 1 == 1
    }

    /// Shift the bitmap by `n` positions so that each previously-marked
    /// packet id `p` (which was at bit offset `old_highest - p`) ends up at
    /// its new offset `old_highest - p + n`. Bits that would end up at an
    /// offset >= `WINDOW_BITS` fall off the end of the window and are lost.
    fn shift_left(&mut self, n: u64) {
        if n >= WINDOW_BITS {
            self.bitmap = [0; BITMAP_WORDS];
            return;
        }
        let word_shift = (n / 64) as usize;
        let bit_shift = (n % 64) as u32;
        let mut out = [0_u64; BITMAP_WORDS];
        // Iterate from highest word down so we can safely read the source
        // words before they are overwritten (we don't share buffers, but
        // keeping the loop order consistent with the conceptual shift
        // direction makes it easier to reason about).
        for i in (0..BITMAP_WORDS).rev() {
            if i < word_shift {
                break;
            }
            let src = i - word_shift;
            let mut v = self.bitmap[src] << bit_shift;
            if bit_shift != 0 && src >= 1 {
                v |= self.bitmap[src - 1] >> (64 - bit_shift);
            }
            out[i] = v;
        }
        self.bitmap = out;
    }
}

struct ReplayEntry {
    window: Mutex<ReplayWindow>,
    last_seen_secs: AtomicU64,
    /// The authenticated user that created this session window. Kept so idle
    /// eviction can return the user's per-user slot without a second lookup.
    owner: Arc<str>,
}

/// Which cap a [`ReplayCheck::StoreFull`] drop hit. Surfaced as a
/// low-cardinality metric label so operators can tell a global-capacity drop
/// (raise `udp_replay_max_sessions`) from a noisy single tenant hitting its
/// per-user share (the others are unaffected).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReplayFull {
    /// The process-wide `max_sessions` cap on this map was reached.
    Global,
    /// The caller's `max_sessions_per_user` share was reached; other users can
    /// still register.
    PerUser,
}

impl ReplayFull {
    /// Static, low-cardinality label distinguishing the two caps. Mirrors the
    /// XHTTP registry's `reason="max_sessions"` / `"max_sessions_per_ip"`.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Global => "max_sessions",
            Self::PerUser => "max_sessions_per_user",
        }
    }
}

/// Outcome of [`ReplayStore::check_and_mark`]. `StoreFull` distinguishes a
/// drop caused by a capacity cap from an actual replay — both drop the packet
/// but they mean different things operationally — and carries which cap fired.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReplayCheck {
    Fresh,
    Replay,
    StoreFull(ReplayFull),
}

/// The salt of a legacy datagram, zero-padded to the widest Shadowsocks salt
/// (32 bytes; aes-128-gcm uses 16). A user runs a single cipher, so padding a
/// short salt with zeros cannot alias another user's salt in practice.
pub(crate) type LegacySalt = [u8; 32];

/// Legacy salt-dedup entry: which authenticated user first presented the salt
/// (so idle eviction can return its per-user slot) and when it was first seen
/// (for idle eviction). The salt itself carries no session id, so ownership is
/// taken from the authenticated caller.
struct LegacySaltEntry {
    owner: Arc<str>,
    first_seen: u64,
}

/// Process-wide store of replay windows, keyed by `client_session_id`, plus a
/// salt-dedup set for legacy datagrams. Entries idle for longer than
/// `idle_timeout` are reaped by `evict_idle`. A non-zero `max_sessions` caps
/// each map independently; a non-zero `max_sessions_per_user` additionally caps
/// how many entries a single authenticated user may hold across *both* maps, so
/// one tenant spraying unique session ids or salts cannot fill the global cap
/// and starve the others (a cross-tenant availability DoS) — only its own new
/// sessions are dropped once it is at its share.
pub(crate) struct ReplayStore {
    entries: DashMap<[u8; 8], Arc<ReplayEntry>>,
    /// Legacy request salt -> who first presented it and when (for idle
    /// eviction and per-user accounting).
    legacy_salts: DashMap<LegacySalt, LegacySaltEntry>,
    idle_timeout: Duration,
    max_sessions: usize,
    /// Per-user ceiling on live entries across both maps, applied on top of
    /// `max_sessions`. `0` disables it (global cap only).
    max_sessions_per_user: usize,
    /// Live entry count per user (SS-2022 windows + legacy salts combined),
    /// maintained alongside the maps so the per-user cap costs a shard lookup
    /// instead of a full scan. A user's counter is removed once it drops to
    /// zero, keeping the map proportional to the users that currently hold
    /// entries.
    per_user: DashMap<Arc<str>, usize>,
}

impl ReplayStore {
    /// `max_sessions = 0` disables the global cap on both maps;
    /// `max_sessions_per_user = 0` disables the per-user share.
    pub(crate) fn new(
        idle_timeout: Duration,
        max_sessions: usize,
        max_sessions_per_user: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            legacy_salts: DashMap::new(),
            idle_timeout,
            max_sessions,
            max_sessions_per_user,
            per_user: DashMap::new(),
        })
    }

    /// Records a `(client_session_id, packet_id)` pair for `user_id` and reports
    /// whether it is `Fresh`, a `Replay`, or dropped because a cap is full
    /// (`StoreFull`, carrying which cap fired).
    pub(crate) fn check_and_mark(
        &self,
        user_id: &Arc<str>,
        client_session_id: [u8; 8],
        packet_id: u64,
    ) -> ReplayCheck {
        let entry = if let Some(e) = self.entries.get(&client_session_id) {
            Arc::clone(e.value())
        } else {
            // Check the global cap before taking a shard lock in `entry(...)`.
            // `len()` takes per-shard read locks; doing it while holding a
            // shard write lock could deadlock against a concurrent `len()`
            // call that already holds read locks elsewhere. The race between
            // the check and the insert is benign: the cap is a soft bound,
            // and we only allow one extra registration per racing caller.
            if self.max_sessions > 0 && self.entries.len() >= self.max_sessions {
                return ReplayCheck::StoreFull(ReplayFull::Global);
            }
            // Then the per-user share. The slot is reserved *before* the map
            // insert so two concurrent creations for the same user cannot both
            // pass the check, and handed back below if we lost the insert race.
            // `per_user` is a distinct map, so this never nests with an
            // `entries` shard lock.
            if !self.reserve_user_slot(user_id) {
                return ReplayCheck::StoreFull(ReplayFull::PerUser);
            }
            match self.entries.entry(client_session_id) {
                Entry::Occupied(occupied) => {
                    self.release_user_slot(user_id);
                    Arc::clone(occupied.get())
                },
                Entry::Vacant(vacant) => Arc::clone(
                    vacant
                        .insert(Arc::new(ReplayEntry {
                            window: Mutex::new(ReplayWindow::new()),
                            last_seen_secs: AtomicU64::new(clock::current_unix_secs()),
                            owner: Arc::clone(user_id),
                        }))
                        .value(),
                ),
            }
        };
        entry
            .last_seen_secs
            .store(clock::current_unix_secs(), Ordering::Relaxed);
        if entry.window.lock().check_and_mark(packet_id) {
            ReplayCheck::Fresh
        } else {
            ReplayCheck::Replay
        }
    }

    /// Records a legacy request salt for `user_id` and reports whether it is
    /// `Fresh`, a `Replay` (already seen within the idle window), or dropped
    /// because a cap is full (`StoreFull`, carrying which cap fired). The stored
    /// timestamp is *not* refreshed on a replay hit, so a replayed salt cannot
    /// pin its own entry alive.
    pub(crate) fn check_and_mark_legacy_salt(
        &self,
        user_id: &Arc<str>,
        salt: LegacySalt,
    ) -> ReplayCheck {
        if let Some(existing) = self.legacy_salts.get(&salt) {
            drop(existing);
            return ReplayCheck::Replay;
        }
        // Check the global cap before taking a shard lock via `entry(...)`. Same
        // benign race as `check_and_mark`: the bound is soft, so a handful of
        // racing callers may each add one salt over the cap.
        if self.max_sessions > 0 && self.legacy_salts.len() >= self.max_sessions {
            return ReplayCheck::StoreFull(ReplayFull::Global);
        }
        // Then the per-user share, reserved before the insert (see
        // `check_and_mark`), handed back if the salt raced in or we spilled.
        if !self.reserve_user_slot(user_id) {
            return ReplayCheck::StoreFull(ReplayFull::PerUser);
        }
        match self.legacy_salts.entry(salt) {
            Entry::Occupied(_) => {
                self.release_user_slot(user_id);
                ReplayCheck::Replay
            },
            Entry::Vacant(slot) => {
                slot.insert(LegacySaltEntry {
                    owner: Arc::clone(user_id),
                    first_seen: clock::current_unix_secs(),
                });
                ReplayCheck::Fresh
            },
        }
    }

    /// Claims one per-user entry slot, returning `false` when the user is
    /// already at `max_sessions_per_user`. A disabled cap always succeeds and
    /// skips the bookkeeping entirely.
    fn reserve_user_slot(&self, user: &Arc<str>) -> bool {
        let cap = self.max_sessions_per_user;
        if cap == 0 {
            return true;
        }
        let mut count = self.per_user.entry(Arc::clone(user)).or_insert(0);
        if *count >= cap {
            return false;
        }
        *count += 1;
        true
    }

    /// Returns a slot claimed by [`Self::reserve_user_slot`]. The counter is
    /// dropped at zero so the map stays proportional to the users that
    /// currently hold entries.
    fn release_user_slot(&self, user: &Arc<str>) {
        if self.max_sessions_per_user == 0 {
            return;
        }
        if let Entry::Occupied(mut occupied) = self.per_user.entry(Arc::clone(user)) {
            let count = occupied.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                occupied.remove();
            }
        }
    }

    /// Drop entries idle for longer than `idle_timeout`.
    pub(crate) fn evict_idle(&self) -> usize {
        self.sweep(clock::current_unix_secs())
    }

    /// [`evict_idle`](Self::evict_idle) with an explicit `now`, so eviction can
    /// be exercised deterministically without moving the shared process clock.
    fn sweep(&self, now: u64) -> usize {
        let threshold = now.saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        // Owners of evicted entries whose per-user slot must be handed back;
        // skipped entirely when the per-user cap is disabled. Collected during
        // the sweep and released after it, so we never take a `per_user` lock
        // while `retain` holds an `entries`/`legacy_salts` shard.
        let track_users = self.max_sessions_per_user > 0;
        let mut released: Vec<Arc<str>> = Vec::new();
        self.entries.retain(|_, entry| {
            if entry.last_seen_secs.load(Ordering::Relaxed) < threshold {
                evicted += 1;
                if track_users {
                    released.push(Arc::clone(&entry.owner));
                }
                false
            } else {
                true
            }
        });
        self.legacy_salts.retain(|_, entry| {
            if entry.first_seen < threshold {
                evicted += 1;
                if track_users {
                    released.push(Arc::clone(&entry.owner));
                }
                false
            } else {
                true
            }
        });
        for user in &released {
            self.release_user_slot(user);
        }
        evicted
    }
}

#[cfg(test)]
#[path = "tests/replay.rs"]
mod tests;
