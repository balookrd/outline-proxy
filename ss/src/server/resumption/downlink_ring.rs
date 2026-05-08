// Phase-2 scaffolding for v2 Symmetric Downlink Replay: the wire
// format module + ParkedTcp field land before any callers do.
// Phases 4-6 (per-carrier capture+emit) wire the relay sites that
// invoke `push` / `replay_from`, at which point this attribute is
// removed.
#![allow(dead_code)]

//! Bounded ring buffer of recently-sent downlink chunks, addressed by
//! absolute byte offsets. Backs the Ack-Prefix Protocol v2 (Symmetric
//! Downlink Replay) feature on the server side: when an in-flight WS
//! dies, the next resume hit may carry a client-reported
//! `X-Outline-Resume-Down-Acked` offset, and the server replays the
//! contiguous suffix `[offset, total_sent())` from this ring before
//! fresh upstream→client bytes flow.
//!
//! See `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2)
//! for the protocol-level description.
//!
//! Design choices (deliberately diverging from the client's
//! [`outline_ws_rust`'s `ClientUpstreamRingBuffer`] in one place):
//!
//! * **Push never fails.** The relay loop reads chunks from the
//!   upstream `TcpStream` whose sizing the server cannot control. A
//!   chunk larger than the configured ring capacity must not crash
//!   the relay — it is stored as the trailing suffix that fits, and
//!   `total_sent` advances by the full chunk length. The bytes that
//!   could not be retained become "logically evicted" the instant the
//!   chunk is recorded; on a subsequent resume hit a client offset
//!   that points into this gap surfaces as `replay_from` →
//!   [`ReplayOutcome::Truncated`], which the resume-emit path
//!   translates into the v2 frame's `REPLAY_TRUNCATED` flag.
//!
//! * **Single-direction.** This is the *downlink* (server→client) ring.
//!   The uplink direction is handled by the client's ring buffer in
//!   `outline-ws-rust`; the symmetric protocol does not require an
//!   uplink ring on the server.
//!
//! * **Byte-keyed, not chunk-keyed.** The wire-level offset is the
//!   `total_sent_downlink` plaintext byte counter. The ring stores
//!   complete chunks but indexes them by the absolute offset of the
//!   first byte they contain, so `replay_from(offset)` can hand back
//!   partial-suffix slices spanning multiple stored chunks.

use std::collections::VecDeque;

/// Outcome of [`DownlinkRing::replay_from`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayOutcome {
    /// The contiguous suffix `[offset, total_sent())`. May be empty
    /// when `offset == total_sent()` (the client claims to have
    /// observed everything the server emitted; nothing to replay).
    Available(Vec<u8>),
    /// The requested offset is older than [`DownlinkRing::oldest_offset`]
    /// — eviction has rolled past the requested point and the missing
    /// bytes cannot be reconstructed. The resume-emit path sets the
    /// v2 frame's `REPLAY_TRUNCATED` flag and emits zero replay bytes.
    Truncated,
    /// The requested offset is *past* `total_sent()` — the client
    /// claims to have observed bytes the server never emitted. This
    /// is a protocol-level inconsistency (a buggy or malicious peer);
    /// the resume-emit path treats it as truncation defensively rather
    /// than fail the whole resume.
    OffsetAhead,
}

/// A `(absolute_first_byte_offset, payload)` pair stored in the ring.
#[derive(Debug)]
struct Entry {
    /// Absolute offset of `payload[0]` in the lifetime byte stream.
    offset: u64,
    payload: Vec<u8>,
}

/// Bounded FIFO ring of downlink chunks indexed by absolute byte
/// offset. Constructed once per session at upstream-handshake time
/// (when v2 is enabled) and lives for the session's whole lifetime,
/// including across parks.
pub(crate) struct DownlinkRing {
    capacity_bytes: usize,
    /// Currently-buffered chunks, oldest first. Sum of their `payload`
    /// lengths equals `current_bytes`.
    entries: VecDeque<Entry>,
    /// Cached sum of `entries[i].payload.len()`. Kept current on every
    /// push / eviction so accessors stay O(1).
    current_bytes: usize,
    /// Total bytes ever emitted toward the client (including bytes
    /// already evicted, including the dropped prefix of an oversized
    /// chunk). Equals the absolute offset of the next byte to be
    /// recorded.
    total_sent: u64,
}

impl DownlinkRing {
    /// Constructs an empty ring with the given byte capacity.
    /// `capacity_bytes == 0` produces a ring that retains no bytes —
    /// every push immediately advances `total_sent` without storing
    /// anything, and `replay_from` always reports `Truncated` (or
    /// `Available(empty)` when offset matches `total_sent`).
    pub(crate) fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            entries: VecDeque::new(),
            current_bytes: 0,
            total_sent: 0,
        }
    }

    /// Configured byte capacity. Stable for the lifetime of the ring.
    #[allow(dead_code)]
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Total bytes ever pushed (including bytes already evicted, and
    /// the truncated prefix of any oversized chunk). Equals the
    /// absolute offset of the next byte to be recorded.
    pub(crate) fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Absolute offset of the oldest byte currently retained in the
    /// ring. Equals `total_sent()` when the ring is empty.
    pub(crate) fn oldest_offset(&self) -> u64 {
        match self.entries.front() {
            Some(entry) => entry.offset,
            None => self.total_sent,
        }
    }

    /// Number of bytes currently held in the ring.
    #[allow(dead_code)]
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Records that `chunk` bytes were just emitted toward the client.
    /// Always succeeds. On overflow, evicts oldest entries FIFO. If
    /// the chunk itself exceeds capacity, only its trailing
    /// `capacity_bytes` are retained — earlier bytes count toward
    /// `total_sent` but are unrecoverable on replay (they surface as
    /// `Truncated` when the client's offset points into them).
    ///
    /// Empty pushes are a no-op so the relay loop can wire this
    /// unconditionally without filtering zero-length writes.
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        if self.capacity_bytes == 0 {
            // Ring configured with no retention: advance the lifetime
            // byte counter but keep the entries deque empty.
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        if chunk.len() >= self.capacity_bytes {
            // Oversized chunk — drop everything currently buffered and
            // retain only the trailing window of the new chunk.
            self.entries.clear();
            self.current_bytes = 0;
            let drop_prefix = chunk.len() - self.capacity_bytes;
            // Bytes 0..drop_prefix of `chunk` are recorded as sent but
            // not retained. Their offsets become unrecoverable on
            // replay; that is exactly what `Truncated` is for.
            let kept_offset = self.total_sent.saturating_add(drop_prefix as u64);
            let kept_payload = chunk[drop_prefix..].to_vec();
            let kept_len = kept_payload.len();
            self.entries.push_back(Entry {
                offset: kept_offset,
                payload: kept_payload,
            });
            self.current_bytes = kept_len;
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        // Chunk fits whole; evict oldest entries until it does.
        while self.current_bytes + chunk.len() > self.capacity_bytes {
            let evicted = self
                .entries
                .pop_front()
                .expect("loop condition implies entries is non-empty");
            self.current_bytes = self.current_bytes.saturating_sub(evicted.payload.len());
        }
        let offset = self.total_sent;
        self.entries.push_back(Entry {
            offset,
            payload: chunk.to_vec(),
        });
        self.current_bytes += chunk.len();
        self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
    }

    /// Returns the contiguous suffix `[offset, total_sent())` if it is
    /// still wholly retained, [`ReplayOutcome::Truncated`] if eviction
    /// has rolled past the requested point, or
    /// [`ReplayOutcome::OffsetAhead`] if the client claims more than
    /// the server ever emitted.
    pub(crate) fn replay_from(&self, offset: u64) -> ReplayOutcome {
        if offset > self.total_sent {
            return ReplayOutcome::OffsetAhead;
        }
        if offset == self.total_sent {
            return ReplayOutcome::Available(Vec::new());
        }
        let oldest = self.oldest_offset();
        if offset < oldest {
            return ReplayOutcome::Truncated;
        }
        let bytes_to_replay = (self.total_sent - offset) as usize;
        let mut out = Vec::with_capacity(bytes_to_replay);
        for entry in &self.entries {
            let entry_end = entry.offset + entry.payload.len() as u64;
            if entry_end <= offset {
                continue;
            }
            if entry.offset >= offset {
                out.extend_from_slice(&entry.payload);
            } else {
                let split = (offset - entry.offset) as usize;
                out.extend_from_slice(&entry.payload[split..]);
            }
        }
        debug_assert_eq!(
            out.len(),
            bytes_to_replay,
            "replay_from byte count must match the requested suffix length",
        );
        ReplayOutcome::Available(out)
    }
}

#[cfg(test)]
#[path = "tests/downlink_ring.rs"]
mod tests;
