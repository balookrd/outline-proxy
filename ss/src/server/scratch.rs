//! Thread-local pool of plaintext scratch buffers for the shadowsocks relays.
//!
//! Each TCP relay/handshake path used to allocate a fresh
//! `Vec::with_capacity(MAX_CHUNK_SIZE)` (≈64 KiB) per connection. Under
//! connection churn this added measurable allocator pressure. [`ScratchBuf`]
//! is an RAII guard: [`take`](ScratchBuf::take) pulls a reused `Vec` from a
//! thread-local stash (or freshly allocates if empty); on drop the buffer is
//! cleared and pushed back, capped to a small number of cached buffers per
//! worker thread.
//!
//! The guard owns its `Vec`, so it is `Send` and can be held across `.await`
//! points on the multi-thread runtime. If a future migrates between workers,
//! the buffer is simply returned to whichever thread polled the drop — the
//! pool naturally rebalances over time.

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

use crate::crypto::MAX_CHUNK_SIZE;

/// Cap on cached buffers per worker thread. Bounds steady-state thread-local
/// memory at `MAX_CACHED * MAX_CHUNK_SIZE` (≈256 KiB at 4 × 64 KiB).
const MAX_CACHED: usize = 4;

thread_local! {
    static SCRATCH_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Owned scratch buffer; returns to the thread-local pool on drop.
pub(in crate::server) struct ScratchBuf {
    inner: Option<Vec<u8>>,
}

impl ScratchBuf {
    pub(in crate::server) fn take() -> Self {
        let inner = SCRATCH_POOL
            .with(|cell| cell.borrow_mut().pop())
            .unwrap_or_else(|| Vec::with_capacity(MAX_CHUNK_SIZE));
        Self { inner: Some(inner) }
    }

    /// Extract the inner `Vec`, bypassing the pool return on drop. Use when
    /// the buffer must be moved into a longer-lived owner (e.g. handed off
    /// to a relay task that will drop it on its own).
    pub(in crate::server) fn into_inner(mut self) -> Vec<u8> {
        self.inner.take().expect("buffer present until drop")
    }
}

impl Deref for ScratchBuf {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        self.inner.as_ref().expect("buffer present until drop")
    }
}

impl DerefMut for ScratchBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.inner.as_mut().expect("buffer present until drop")
    }
}

impl Drop for ScratchBuf {
    fn drop(&mut self) {
        let Some(mut buf) = self.inner.take() else { return };
        buf.clear();
        SCRATCH_POOL.with(|cell| {
            let mut pool = cell.borrow_mut();
            if pool.len() < MAX_CACHED {
                pool.push(buf);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_len() -> usize {
        SCRATCH_POOL.with(|cell| cell.borrow().len())
    }

    fn drain_pool() {
        SCRATCH_POOL.with(|cell| cell.borrow_mut().clear());
    }

    #[test]
    fn take_then_drop_returns_buffer_to_pool() {
        drain_pool();
        {
            let mut buf = ScratchBuf::take();
            buf.extend_from_slice(b"hello");
            assert_eq!(buf.len(), 5);
        }
        assert_eq!(pool_len(), 1);
    }

    #[test]
    fn buffer_is_cleared_on_return() {
        drain_pool();
        {
            let mut buf = ScratchBuf::take();
            buf.extend_from_slice(b"dirty data");
        }
        let buf = ScratchBuf::take();
        assert!(buf.is_empty());
        assert!(buf.capacity() >= MAX_CHUNK_SIZE);
    }

    #[test]
    fn pool_capped_at_max_cached() {
        drain_pool();
        let bufs: Vec<_> = (0..MAX_CACHED + 2).map(|_| ScratchBuf::take()).collect();
        drop(bufs);
        assert_eq!(pool_len(), MAX_CACHED);
    }

    #[test]
    fn fresh_take_when_pool_empty_has_chunk_capacity() {
        drain_pool();
        let buf = ScratchBuf::take();
        assert!(buf.capacity() >= MAX_CHUNK_SIZE);
    }
}
