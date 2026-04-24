//! Anti-replay filter for SS-2022 UDP.
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

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
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
}

/// Process-wide store of replay windows, keyed by `client_session_id`.
/// Entries idle for longer than `idle_timeout` are reaped by `evict_idle`.
pub(crate) struct ReplayStore {
    entries: DashMap<[u8; 8], Arc<ReplayEntry>>,
    idle_timeout: Duration,
}

impl ReplayStore {
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            idle_timeout,
        })
    }

    /// Returns `true` if the `(client_session_id, packet_id)` pair is fresh
    /// and has been recorded; `false` if it is a replay or falls outside the
    /// sliding window.
    pub(crate) fn check_and_mark(
        &self,
        client_session_id: [u8; 8],
        packet_id: u64,
    ) -> bool {
        let entry = if let Some(e) = self.entries.get(&client_session_id) {
            Arc::clone(e.value())
        } else {
            Arc::clone(
                self.entries
                    .entry(client_session_id)
                    .or_insert_with(|| {
                        Arc::new(ReplayEntry {
                            window: Mutex::new(ReplayWindow::new()),
                            last_seen_secs: AtomicU64::new(clock::current_unix_secs()),
                        })
                    })
                    .value(),
            )
        };
        entry
            .last_seen_secs
            .store(clock::current_unix_secs(), Ordering::Relaxed);
        entry.window.lock().check_and_mark(packet_id)
    }

    /// Drop entries idle for longer than `idle_timeout`.
    pub(crate) fn evict_idle(&self) -> usize {
        let threshold = clock::current_unix_secs().saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        self.entries.retain(|_, entry| {
            if entry.last_seen_secs.load(Ordering::Relaxed) < threshold {
                evicted += 1;
                false
            } else {
                true
            }
        });
        evicted
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_packet_ids_accepted_in_order() {
        let mut w = ReplayWindow::new();
        for id in 0..100 {
            assert!(w.check_and_mark(id), "id={id}");
        }
    }

    #[test]
    fn immediate_duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(42));
        assert!(!w.check_and_mark(42));
    }

    #[test]
    fn reordered_within_window_accepted_once() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(10));
        assert!(w.check_and_mark(20));
        assert!(w.check_and_mark(15)); // reordered
        assert!(!w.check_and_mark(15)); // replay
    }

    #[test]
    fn old_packet_outside_window_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(5));
        assert!(w.check_and_mark(5 + WINDOW_BITS + 10));
        assert!(!w.check_and_mark(5)); // shifted out
    }

    #[test]
    fn big_jump_does_not_preserve_old_bits() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(10));
        assert!(w.check_and_mark(10 + WINDOW_BITS + 100));
        // id 10 is now far outside the window
        assert!(!w.check_and_mark(10));
        // id equal to new highest is a replay
        assert!(!w.check_and_mark(10 + WINDOW_BITS + 100));
    }

    #[test]
    fn store_isolates_sessions() {
        let store = ReplayStore::new(Duration::from_secs(60));
        let a = [1_u8; 8];
        let b = [2_u8; 8];
        assert!(store.check_and_mark(a, 7));
        assert!(store.check_and_mark(b, 7)); // different session, same id ok
        assert!(!store.check_and_mark(a, 7)); // replay on session a
        assert!(!store.check_and_mark(b, 7)); // replay on session b
    }

    #[test]
    fn window_boundary_at_edge() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(2000));
        // id = highest - (WINDOW_BITS - 1): inside window
        assert!(w.check_and_mark(2000 - (WINDOW_BITS - 1)));
        // id = highest - WINDOW_BITS: outside
        assert!(!w.check_and_mark(2000 - WINDOW_BITS));
    }

    #[test]
    fn replay_across_word_boundary() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_mark(100));
        assert!(w.check_and_mark(100 + 65)); // spans across word boundary on shift
        assert!(!w.check_and_mark(100)); // must still be detected
    }
}
