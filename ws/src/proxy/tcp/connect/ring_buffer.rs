//! Bounded ring buffer of recently-sent uplink chunks, addressed by
//! absolute byte offsets. Backs the Ack-Prefix Protocol mid-session
//! retry path: when an in-flight WebSocket dies, we re-dial with the
//! capability bit set, parse the server-reported `up_acked` counter
//! from the new stream's first SS-AEAD chunk, and replay our buffered
//! tail starting at that offset so the upstream server receives every
//! payload byte exactly once.
//!
//! Design choices:
//!
//! * **Byte-keyed, not chunk-keyed.** The server reports `up_acked` in
//!   plaintext bytes (post-AEAD-decrypt), and that is the granularity
//!   the spec speaks in. The ring stores complete chunks but indexes
//!   them by the absolute offset *of the first byte they contain*, so
//!   `replay_from(offset)` can hand back partial-suffix slices as well
//!   as whole chunks.
//!
//! * **FIFO eviction with hard byte cap.** We never expand past
//!   `capacity_bytes`. New pushes evict whole chunks from the front
//!   until the new push fits. A push larger than the cap is rejected
//!   with [`PushError::OversizedSingleChunk`] — we cannot replay it
//!   without holding it whole, so falsely succeeding here would let
//!   `replay_from` silently miss bytes later.
//!
//! * **`replay_from(offset)` semantics.** Returns the contiguous tail
//!   `[offset, total_sent())`. If `offset < oldest_offset()` the data
//!   has been evicted and the caller cannot recover — surfaces
//!   [`ReplayError::OffsetEvicted`]. If `offset > total_sent()` the
//!   server is claiming it acked bytes we never sent, which means
//!   either a desync or a malicious / buggy server — surfaces
//!   [`ReplayError::OffsetAhead`].
//!
//! * **Single-direction.** This is the *uplink* (client→server) ring
//!   only. Spec narrows v1's "Zero-loss replay" non-goal to "Symmetric
//!   (downstream) zero-loss replay" — the downlink direction is out of
//!   scope, so SSH-style sessions still observe downlink byte gaps on
//!   retry. HTTP request bodies and idempotent RPCs are the v1 sweet
//!   spot.

use std::collections::VecDeque;

/// Failure modes for [`ClientUpstreamRingBuffer::push`]. Successful
/// pushes return `Ok(())` and never silently drop or truncate user
/// bytes — overflow is reported so the caller can stop, log, and
/// surface a metric instead of producing a torn replay later.
#[derive(Debug, PartialEq, Eq)]
pub enum PushError {
    /// The chunk on its own is larger than the configured ring
    /// capacity. Storing it would require evicting it immediately on
    /// the next push, defeating the buffer's purpose. The mid-session
    /// retry budget for this session must be considered exhausted from
    /// this point — no replay can reconstruct the missing bytes.
    OversizedSingleChunk { chunk_len: usize, capacity_bytes: usize },
}

/// Failure modes for [`ClientUpstreamRingBuffer::replay_from`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The requested offset is older than `oldest_offset()` — the
    /// chunks containing those bytes have been evicted. The session
    /// cannot be safely resumed; the caller should drop and surface
    /// `failed_replay` on the mid-session retry metric.
    OffsetEvicted { requested: u64, oldest_available: u64 },
    /// The requested offset is *past* `total_sent()` — the server
    /// claims to have acked bytes we never produced. Indicates a
    /// desync or a misbehaving / malicious peer; the caller must drop
    /// the session.
    OffsetAhead { requested: u64, total_sent: u64 },
}

/// A `(absolute_first_byte_offset, payload)` pair stored in the ring.
/// Kept private so the public surface forces callers through the
/// `push` / `replay_from` discipline.
#[derive(Debug)]
struct Entry {
    /// Absolute offset of `payload[0]` in the lifetime byte stream. Two
    /// entries with offsets `a < b` always satisfy `a + len_a == b`
    /// because the buffer never drops bytes from the *middle* of a
    /// chunk; eviction is whole-chunk FIFO.
    offset: u64,
    payload: Vec<u8>,
}

/// Bounded FIFO ring of uplink chunks indexed by absolute byte offset.
/// See module-level docs for the design rationale.
pub struct ClientUpstreamRingBuffer {
    capacity_bytes: usize,
    /// Currently-buffered chunks, oldest first. Sum of their `payload`
    /// lengths is `current_bytes`.
    entries: VecDeque<Entry>,
    /// Cached sum of `entries[i].payload.len()` so push/eviction stay
    /// O(1) instead of re-summing the deque.
    current_bytes: usize,
    /// Total bytes ever pushed (including evicted ones). Equals
    /// `oldest_offset() + current_bytes` whenever `entries` is
    /// non-empty.
    total_sent: u64,
}

impl ClientUpstreamRingBuffer {
    /// Constructs an empty ring with the given byte capacity.
    /// `capacity_bytes == 0` produces a ring that rejects every push
    /// — useful for representing "mid-session retry disabled" via a
    /// uniform handle without a separate `Option<RingBuffer>`.
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            entries: VecDeque::new(),
            current_bytes: 0,
            total_sent: 0,
        }
    }

    /// Configured byte capacity. Stable for the lifetime of the ring.
    /// Currently exercised only by tests; kept on the public surface
    /// for future diagnostics callers (metrics export, debug dumps).
    #[allow(dead_code)]
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Total bytes pushed since construction (including bytes already
    /// evicted). Equals the absolute offset of the *next* byte to be
    /// pushed. Currently exercised only by tests; kept on the public
    /// surface for future diagnostics.
    #[allow(dead_code)]
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Absolute offset of the oldest byte currently buffered. Equals
    /// `total_sent()` when the ring is empty (i.e. there is nothing to
    /// replay; any `replay_from(total_sent())` is a valid empty
    /// replay).
    pub fn oldest_offset(&self) -> u64 {
        match self.entries.front() {
            Some(entry) => entry.offset,
            None => self.total_sent,
        }
    }

    /// Number of bytes currently held in the ring (sum of all entries'
    /// payload lengths). Always `<= capacity_bytes`. Currently
    /// exercised only by tests; kept on the public surface for
    /// future diagnostics.
    #[allow(dead_code)]
    pub fn buffered_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Records that `chunk` was sent upstream. Evicts older entries
    /// FIFO to make room when the new push would exceed the cap.
    /// Empty pushes are a no-op so the caller can wire this
    /// unconditionally without filtering zero-length writes.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if chunk.len() > self.capacity_bytes {
            return Err(PushError::OversizedSingleChunk {
                chunk_len: chunk.len(),
                capacity_bytes: self.capacity_bytes,
            });
        }
        // Evict oldest entries until the new chunk fits. The
        // saturating subtraction is defensive — `current_bytes` is
        // always `<= capacity_bytes` so the headroom calculation never
        // underflows in practice, but a future change to the
        // bookkeeping should not be able to corrupt the invariant.
        while self.current_bytes + chunk.len() > self.capacity_bytes {
            let evicted = self
                .entries
                .pop_front()
                .expect("loop condition implies entries is non-empty");
            self.current_bytes = self.current_bytes.saturating_sub(evicted.payload.len());
        }
        let offset = self.total_sent;
        self.entries.push_back(Entry { offset, payload: chunk.to_vec() });
        self.current_bytes += chunk.len();
        self.total_sent += chunk.len() as u64;
        Ok(())
    }

    /// Returns the contiguous suffix `[offset, total_sent())` as a
    /// fresh `Vec<u8>`. Per spec, returning a single owned `Vec` makes
    /// the caller's resend path trivial: hand it to
    /// `writer.send_chunk(&replay)` (one or more chunks at the SS
    /// layer; the writer fragments to AEAD limits internally).
    ///
    /// `offset == total_sent()` is a valid request — it means "the
    /// server already has everything I sent" — and returns an empty
    /// Vec.
    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError> {
        if offset > self.total_sent {
            return Err(ReplayError::OffsetAhead {
                requested: offset,
                total_sent: self.total_sent,
            });
        }
        if offset == self.total_sent {
            return Ok(Vec::new());
        }
        let oldest = self.oldest_offset();
        if offset < oldest {
            return Err(ReplayError::OffsetEvicted {
                requested: offset,
                oldest_available: oldest,
            });
        }
        // Pre-size the output to the exact byte count we're about to
        // copy so the resend path doesn't grow the Vec mid-loop.
        let bytes_to_replay = (self.total_sent - offset) as usize;
        let mut out = Vec::with_capacity(bytes_to_replay);
        for entry in &self.entries {
            let entry_end = entry.offset + entry.payload.len() as u64;
            if entry_end <= offset {
                // Whole chunk is below the cursor — already acked.
                continue;
            }
            if entry.offset >= offset {
                // Whole chunk is above the cursor — copy verbatim.
                out.extend_from_slice(&entry.payload);
            } else {
                // Cursor splits this chunk; copy only the tail.
                let split = (offset - entry.offset) as usize;
                out.extend_from_slice(&entry.payload[split..]);
            }
        }
        debug_assert_eq!(
            out.len(),
            bytes_to_replay,
            "replay_from byte count must match the requested suffix length",
        );
        Ok(out)
    }
}

#[cfg(test)]
#[path = "tests/ring_buffer.rs"]
mod tests;
