//! Warm-standby connection pool: per-uplink TCP/UDP deques of pre-dialed
//! [`TransportStream`] handles plus refill mutexes that serialize background
//! refill tasks. Length counters are maintained alongside each deque so
//! `/metrics` scrapes can read pool depth without contending with hot-path
//! mutations.

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Mutex;

use outline_transport::TransportStream;

use crate::types::TransportKind;

#[cfg(test)]
#[path = "tests/standby_pool.rs"]
mod tests;

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

/// Coalesces background refill tasks for one `(uplink, transport)` pool.
///
/// A pool take that discards K stale entries used to spawn K refill tasks, each
/// of which resolved the standby context, took the refill mutex and — with the
/// pool already back at `desired` — immediately dropped it again. The gate keeps
/// at most one *queued* refill task per pool: further requests coalesce into it.
///
/// The claim is released by the task as its first action, BEFORE it does any
/// work. A take that pops an entry after the refill loop has already sampled the
/// pool length must be able to queue a fresh task — otherwise its slot would
/// stay empty until the 15 s maintenance sweep. Releasing on entry (rather than
/// on completion) keeps the pool converging on `desired` while still collapsing
/// the burst of duplicate spawns that motivated the gate.
pub(crate) struct RefillGate {
    /// A refill task is queued and has not started running yet.
    queued: AtomicBool,
    /// Refill tasks actually spawned through this gate, for the life of the
    /// process. Observability seam for the coalescing tests.
    spawned: AtomicU64,
}

impl RefillGate {
    fn new() -> Self {
        Self {
            queued: AtomicBool::new(false),
            spawned: AtomicU64::new(0),
        }
    }

    /// Claim the right to spawn a refill task. `false` means one is already
    /// queued and will pick up this request's work.
    pub(crate) fn try_claim(&self) -> bool {
        let claimed = !self.queued.swap(true, Ordering::AcqRel);
        if claimed {
            self.spawned.fetch_add(1, Ordering::Relaxed);
        }
        claimed
    }

    /// Release the claim. Called by the spawned task before it starts working,
    /// so requests that arrive while it runs can queue a follow-up.
    pub(crate) fn release(&self) {
        self.queued.store(false, Ordering::Release);
    }

    /// Number of refill tasks spawned through this gate.
    #[cfg(test)]
    pub(crate) fn spawned(&self) -> u64 {
        self.spawned.load(Ordering::Relaxed)
    }
}

pub(crate) struct StandbyPool {
    pub(crate) tcp: TrackedDeque,
    pub(crate) udp: TrackedDeque,
    pub(crate) tcp_refill: Mutex<()>,
    pub(crate) udp_refill: Mutex<()>,
    tcp_refill_gate: RefillGate,
    udp_refill_gate: RefillGate,
}

impl StandbyPool {
    pub(crate) fn new() -> Self {
        Self {
            tcp: TrackedDeque::new(),
            udp: TrackedDeque::new(),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
            tcp_refill_gate: RefillGate::new(),
            udp_refill_gate: RefillGate::new(),
        }
    }

    pub(crate) fn refill_gate(&self, transport: TransportKind) -> &RefillGate {
        match transport {
            TransportKind::Tcp => &self.tcp_refill_gate,
            TransportKind::Udp => &self.udp_refill_gate,
        }
    }
}
