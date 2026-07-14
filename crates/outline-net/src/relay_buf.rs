//! Receive-buffer policy for relay read loops.
//!
//! Every relay loop parks on socket readability and then reads whatever became
//! available. Sizing that read at the protocol maximum (64 KiB) on every
//! iteration makes a typical small read pay for the worst case, and lets the
//! transient RSS scale with the number of concurrent in-flight reads.
//!
//! [`RelayReadBuf`] keeps ONE allocation per read loop and reuses it across
//! iterations, while preserving the property the per-iteration allocation was
//! there for: an idle session must not pin a receive buffer. Once a park
//! outlives [`RelayReadBuf::idle_grace`] the buffer is handed back to the
//! allocator and the loop keeps waiting empty-handed, so a quiet session costs
//! nothing but the (already parked) task.
//!
//! Two shapes, because the two transports fail differently on a short buffer:
//!
//! - [`RelayReadBuf::fixed`] — datagram sockets. A datagram read into a buffer
//!   shorter than the datagram is silently TRUNCATED by the kernel, so the read
//!   window must always cover the largest datagram the socket can deliver. The
//!   win here is reuse, not sizing.
//! - [`RelayReadBuf::adaptive`] — byte streams. A short buffer only costs one
//!   extra loop iteration, never data, so the window starts small and doubles
//!   whenever a read saturates it. Small reads stay small; a bulk transfer
//!   reaches the ceiling within a few iterations.

use std::future::Future;
use std::time::Duration;

/// Idle window after which a parked read loop releases its buffer.
///
/// Short enough that a session going quiet stops pinning memory promptly, long
/// enough that chatty flows (interactive TCP, DNS/game UDP) keep reusing the
/// same allocation instead of reallocating between packets.
pub const RELAY_BUF_IDLE_GRACE: Duration = Duration::from_secs(5);

/// Starting read window for stream relay loops (see
/// [`RelayReadBuf::adaptive`]).
pub const STREAM_INITIAL_READ_CAPACITY: usize = 16 * 1024;

/// A reused read buffer that is released while the flow is idle.
pub struct RelayReadBuf {
    buf: Vec<u8>,
    /// Spare capacity handed to the next read.
    capacity: usize,
    /// Window the buffer falls back to after a release (and starts at).
    initial_capacity: usize,
    /// Ceiling for the adaptive growth; equals `initial_capacity` for a fixed
    /// buffer.
    max_capacity: usize,
    idle_grace: Duration,
}

impl RelayReadBuf {
    /// Fixed-window buffer for datagram sockets: every read gets room for
    /// `capacity` bytes, so a maximum-size datagram is never truncated.
    pub fn fixed(capacity: usize) -> Self {
        Self {
            buf: Vec::new(),
            capacity,
            initial_capacity: capacity,
            max_capacity: capacity,
            idle_grace: RELAY_BUF_IDLE_GRACE,
        }
    }

    /// Growing window for byte streams: starts at `initial` and doubles (up to
    /// `max`) each time a read fills the whole window.
    pub fn adaptive(initial: usize, max: usize) -> Self {
        let initial = initial.min(max);
        Self {
            buf: Vec::new(),
            capacity: initial,
            initial_capacity: initial,
            max_capacity: max,
            idle_grace: RELAY_BUF_IDLE_GRACE,
        }
    }

    /// Overrides the idle window before which the buffer is kept across parks.
    pub fn with_idle_grace(mut self, idle_grace: Duration) -> Self {
        self.idle_grace = idle_grace;
        self
    }

    /// Awaits `ready` (the loop's readiness future — socket readability, or any
    /// composition of it), releasing the buffer if the wait outlives the idle
    /// grace.
    ///
    /// `ready` is polled to completion either way: the grace deadline only
    /// drops the allocation, never the future, so no readiness event and no
    /// error is lost.
    pub async fn park<T, E, F>(&mut self, ready: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        if self.buf.capacity() == 0 {
            return ready.await;
        }
        let mut ready = std::pin::pin!(ready);
        match tokio::time::timeout(self.idle_grace, &mut ready).await {
            Ok(result) => result,
            Err(_elapsed) => {
                self.release();
                ready.await
            },
        }
    }

    /// Returns an empty buffer with room for the next read.
    ///
    /// Call once per iteration, after [`Self::park`] and immediately before the
    /// `try_read_buf` / `try_recv_buf` that fills it.
    pub fn ready(&mut self) -> &mut Vec<u8> {
        self.grow_after_saturated_read();
        self.buf.clear();
        // `reserve_exact` counts from `len`, which `clear` just zeroed, so the
        // request is the whole window — not the shortfall against `capacity()`.
        if self.buf.capacity() < self.capacity {
            self.buf.reserve_exact(self.capacity);
        }
        &mut self.buf
    }

    /// Bytes filled by the last read.
    pub fn filled(&self) -> &[u8] {
        &self.buf
    }

    /// Spare capacity the next [`Self::ready`] will hand out.
    pub fn read_capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes currently held by the allocation; `0` while released.
    pub fn allocated(&self) -> usize {
        self.buf.capacity()
    }

    fn release(&mut self) {
        self.buf = Vec::new();
        // A flow that just went quiet re-learns its read size from scratch, so
        // a past burst does not pin a wide window onto the next trickle.
        self.capacity = self.initial_capacity;
    }

    /// `try_read_buf` / `try_recv_buf` leave the read length in `buf.len()`. A
    /// read that consumed the whole window means the peer likely had more to
    /// give, so widen it for the next one. No-op for a fixed buffer, where
    /// `capacity == max_capacity`.
    fn grow_after_saturated_read(&mut self) {
        if self.capacity < self.max_capacity && self.buf.len() >= self.capacity {
            self.capacity = self.capacity.saturating_mul(2).min(self.max_capacity);
        }
    }
}

#[cfg(test)]
#[path = "tests/relay_buf.rs"]
mod tests;
