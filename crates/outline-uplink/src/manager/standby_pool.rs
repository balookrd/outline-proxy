//! Warm-standby connection pool: per-uplink TCP/UDP deques of pre-dialed
//! [`TransportStream`] handles plus refill mutexes that serialize background
//! refill tasks. Length counters are maintained alongside each deque so
//! `/metrics` scrapes can read pool depth without contending with hot-path
//! mutations.

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;

use outline_transport::TransportStream;

/// Deque guarded by an async `Mutex` that also maintains an `AtomicUsize`
/// length counter. The counter is refreshed on `Drop` of the lock guard so
/// observers that only need a size hint (e.g. `/metrics` scrapes) can read
/// it without contending with hot-path mutations.
pub(crate) struct TrackedDeque {
    deque: Mutex<VecDeque<TransportStream>>,
    len: AtomicUsize,
}

impl TrackedDeque {
    pub(crate) fn new() -> Self {
        Self {
            deque: Mutex::new(VecDeque::new()),
            len: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn lock(&self) -> TrackedDequeGuard<'_> {
        TrackedDequeGuard {
            guard: self.deque.lock().await,
            len: &self.len,
        }
    }

    pub(crate) fn len_hint(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }
}

pub(crate) struct TrackedDequeGuard<'a> {
    guard: tokio::sync::MutexGuard<'a, VecDeque<TransportStream>>,
    len: &'a AtomicUsize,
}

impl Deref for TrackedDequeGuard<'_> {
    type Target = VecDeque<TransportStream>;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for TrackedDequeGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for TrackedDequeGuard<'_> {
    fn drop(&mut self) {
        self.len.store(self.guard.len(), Ordering::Relaxed);
    }
}

pub(crate) struct StandbyPool {
    pub(crate) tcp: TrackedDeque,
    pub(crate) udp: TrackedDeque,
    pub(crate) tcp_refill: Mutex<()>,
    pub(crate) udp_refill: Mutex<()>,
}

impl StandbyPool {
    pub(crate) fn new() -> Self {
        Self {
            tcp: TrackedDeque::new(),
            udp: TrackedDeque::new(),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
        }
    }
}
