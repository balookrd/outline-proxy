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
use crate::server::constants::MAX_UDP_PAYLOAD_SIZE;

/// Cap on cached buffers per worker thread per pool. Bounds steady-state
/// thread-local memory at `MAX_CACHED * <buf_size>` per pool — for instance
/// `4 × 64 KiB = 256 KiB` for the SS plaintext pool.
const MAX_CACHED: usize = 4;

/// Size of a TCP relay scratch buffer used by VLESS upstream/downstream
/// splice loops. 16 KiB matches the existing `vec![0u8; 16 * 1024]`
/// per-task allocations the buffers replace.
const TCP_RELAY_BUF_LEN: usize = 16 * 1024;

thread_local! {
    static SCRATCH_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static UDP_RECV_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static TCP_RELAY_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
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

/// Owned 64 KiB UDP-recv buffer; returns to a thread-local pool on drop.
///
/// Unlike [`ScratchBuf`] (which is a write-then-read scratch with `len = 0`),
/// `UdpRecvBuf` is allocated and kept at full `MAX_UDP_PAYLOAD_SIZE` length
/// so `UdpSocket::recv(&mut buf)` can write directly into it. The pool does
/// not zero on return: the next take inherits whatever bytes the previous
/// owner left, which is fine because `recv` overwrites the prefix that
/// callers actually read (`&buf[..n]`).
///
/// One `UdpRecvBuf` lives for the lifetime of one upstream UDP relay task,
/// not one datagram, so the pool stays small (typically `MAX_CACHED` per
/// worker thread that handled at least one VLESS UDP session).
pub(in crate::server) struct UdpRecvBuf {
    inner: Option<Vec<u8>>,
}

impl UdpRecvBuf {
    pub(in crate::server) fn take() -> Self {
        let inner = UDP_RECV_POOL
            .with(|cell| cell.borrow_mut().pop())
            .unwrap_or_else(|| vec![0u8; MAX_UDP_PAYLOAD_SIZE]);
        Self { inner: Some(inner) }
    }
}

impl Deref for UdpRecvBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner.as_ref().expect("buffer present until drop").as_slice()
    }
}

impl DerefMut for UdpRecvBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut().expect("buffer present until drop").as_mut_slice()
    }
}

impl Drop for UdpRecvBuf {
    fn drop(&mut self) {
        let Some(buf) = self.inner.take() else { return };
        UDP_RECV_POOL.with(|cell| {
            let mut pool = cell.borrow_mut();
            if pool.len() < MAX_CACHED {
                pool.push(buf);
            }
        });
    }
}

/// Owned 16 KiB TCP-relay scratch buffer; returns to a thread-local pool
/// on drop. Pre-sized to [`TCP_RELAY_BUF_LEN`] so callers can hand a
/// `&mut [u8]` slice straight to `AsyncRead::read`. Same no-zero-on-return
/// rationale as [`UdpRecvBuf`]: callers consume `&buf[..n]`.
pub(in crate::server) struct TcpRelayBuf {
    inner: Option<Vec<u8>>,
}

impl TcpRelayBuf {
    pub(in crate::server) fn take() -> Self {
        let inner = TCP_RELAY_POOL
            .with(|cell| cell.borrow_mut().pop())
            .unwrap_or_else(|| vec![0u8; TCP_RELAY_BUF_LEN]);
        Self { inner: Some(inner) }
    }
}

impl Deref for TcpRelayBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner.as_ref().expect("buffer present until drop").as_slice()
    }
}

impl DerefMut for TcpRelayBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut().expect("buffer present until drop").as_mut_slice()
    }
}

impl Drop for TcpRelayBuf {
    fn drop(&mut self) {
        let Some(buf) = self.inner.take() else { return };
        TCP_RELAY_POOL.with(|cell| {
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
