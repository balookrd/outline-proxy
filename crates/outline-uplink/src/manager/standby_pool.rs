//! Warm-standby connection pool: per-uplink TCP/UDP pools of pre-dialed
//! [`TransportStream`] handles plus refill mutexes that serialize background
//! refill tasks. Length counters are maintained alongside each pool so
//! `/metrics` scrapes can read pool depth without contending with hot-path
//! mutations.
//!
//! # Wire identity
//!
//! A pool prewarms exactly one wire of its uplink at a time, and the wire it
//! prewarms moves underneath it — `shuffle_wires` rerolls it, wire failover
//! advances it. A carrier dialed on one wire must never be handed to a flow
//! the manager considers to be landing on another: on TCP that fails
//! `do_tcp_ss_setup` and silently retries, but on UDP `UdpWsTransport::
//! from_websocket` is built off the pop with the *wanted* wire's credentials
//! and every reused datagram is then silently dropped, with no protocol-level
//! recovery.
//!
//! That invariant is structural here, not a discipline callers have to
//! remember:
//!
//! * Every carrier carries the wire it was dialed on ([`PooledCarrier`]), so
//!   "which wire is this carrier from" is never inferred from anything that
//!   could have moved since.
//! * The pool-level wire is *inside* the mutex, not an atomic beside it, and
//!   the only way to reach either it or the entries is [`WirePoolGuard`] — so
//!   a rotation's drain-and-restamp is one transaction, with no window for a
//!   concurrent push to slip a carrier in under a marker that is about to
//!   change.
//! * No guard method inserts a carrier without being told which wire it came
//!   from, and none hands one out without being told which wire is wanted.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Mutex;

use outline_transport::TransportStream;
use outline_transport::collections::maybe_shrink_vecdeque;

use crate::types::TransportKind;

#[cfg(test)]
#[path = "tests/standby_pool.rs"]
mod tests;

/// A pooled carrier plus the wire it was actually dialed on.
///
/// The wire rides with the carrier rather than living only in a pool-level
/// marker because the marker is a *statement about the whole pool* and can go
/// out of date the moment anything mutates the pool in two steps. The tag
/// cannot: it is written once, by the code that dialed the carrier, and is
/// checked again by the code that hands it out.
pub(crate) struct PooledCarrier {
    /// `0` is the uplink's primary carrier, `i` is `fallbacks[i - 1]`.
    pub(crate) wire: u8,
    pub(crate) stream: TransportStream,
}

/// What happened to a carrier offered to [`WirePoolGuard::push_for_wire`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PushOutcome {
    /// Pooled; carries the pool's new length.
    Pooled(usize),
    /// The pool already holds `desired` carriers; the stream was dropped.
    Full,
    /// The pool no longer serves the wire this carrier was dialed on; the
    /// stream was dropped. A rotation landed while the dial was in flight.
    WrongWire,
}

/// What [`WirePoolGuard::pop_front_for_wire`] found.
pub(crate) struct PoppedCarrier {
    /// The first carrier the pool held for the wanted wire, if any.
    pub(crate) stream: Option<TransportStream>,
    /// Carriers for other wires dropped while walking to it. Non-zero only if
    /// something got a foreign carrier into the pool despite the guard API —
    /// staged deliberately by tests, or a future regression.
    pub(crate) foreign_dropped: usize,
}

/// One transport's warm pool: the carriers, the wire they belong to, and an
/// `AtomicUsize` length hint refreshed on `Drop` of the lock guard so
/// observers that only need a size (e.g. `/metrics` scrapes) can read it
/// without contending with hot-path mutations.
pub(crate) struct WirePool {
    inner: Mutex<PoolInner>,
    len: AtomicUsize,
}

struct PoolInner {
    entries: VecDeque<PooledCarrier>,
    /// The wire this pool currently prewarms. Lives inside the mutex so that
    /// changing it and changing `entries` is one transaction.
    wire: u8,
}

impl WirePool {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(PoolInner { entries: VecDeque::new(), wire: 0 }),
            len: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn lock(&self) -> WirePoolGuard<'_> {
        WirePoolGuard {
            guard: self.inner.lock().await,
            len: &self.len,
        }
    }

    pub(crate) fn len_hint(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }
}

pub(crate) struct WirePoolGuard<'a> {
    guard: tokio::sync::MutexGuard<'a, PoolInner>,
    len: &'a AtomicUsize,
}

impl WirePoolGuard<'_> {
    /// The wire this pool currently prewarms.
    pub(crate) fn wire(&self) -> u8 {
        self.guard.wire
    }

    pub(crate) fn len(&self) -> usize {
        self.guard.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.guard.entries.is_empty()
    }

    /// Makes `wire` the wire this pool prewarms, dropping every carrier that
    /// was dialed on any other one. Returns how many were dropped.
    ///
    /// Drain and restamp in a single transaction, deliberately: as two steps
    /// (drain under the lock, restamp after it) they leave a window in which
    /// the pool is empty but still marked for the *old* wire — exactly the
    /// state in which a refill dial for that old wire, parked on the lock, is
    /// accepted. Its carrier then sits in a pool that the restamp is about to
    /// declare belongs to the new wire.
    pub(crate) fn claim_wire(&mut self, wire: u8) -> usize {
        let before = self.guard.entries.len();
        self.guard.entries.retain(|entry| entry.wire == wire);
        let dropped = before - self.guard.entries.len();
        self.guard.wire = wire;
        maybe_shrink_vecdeque(&mut self.guard.entries);
        dropped
    }

    /// Pops the first carrier dialed on `wire`, dropping any carrier for
    /// another wire it walks past — those belong to a wire nothing is dialing
    /// any more, so there is nobody left to hand them to.
    pub(crate) fn pop_front_for_wire(&mut self, wire: u8) -> PoppedCarrier {
        let mut foreign_dropped = 0;
        while let Some(entry) = self.guard.entries.pop_front() {
            if entry.wire == wire {
                return PoppedCarrier {
                    stream: Some(entry.stream),
                    foreign_dropped,
                };
            }
            foreign_dropped += 1;
        }
        PoppedCarrier { stream: None, foreign_dropped }
    }

    /// Offers a freshly dialed `stream` to the pool on behalf of `wire`,
    /// capped at `desired` entries.
    ///
    /// The wire check and the capacity check both live here, under the one
    /// guard, so a caller cannot pass one and then lose a race on the other.
    /// A dial that resolved its wire before it started — the only thing on
    /// this path with no upper bound on how long it takes — can find the pool
    /// rotated out from under it by the time it returns; the carrier is
    /// dropped then, because a wasted dial is far cheaper than a
    /// mis-credentialed carrier.
    pub(crate) fn push_for_wire(
        &mut self,
        wire: u8,
        desired: usize,
        stream: TransportStream,
    ) -> PushOutcome {
        if self.guard.wire != wire {
            return PushOutcome::WrongWire;
        }
        if self.guard.entries.len() >= desired {
            return PushOutcome::Full;
        }
        self.guard.entries.push_back(PooledCarrier { wire, stream });
        PushOutcome::Pooled(self.guard.entries.len())
    }

    /// Removes every carrier so the caller can probe them outside the lock
    /// (`validate` / `keepalive`). The pool's wire is left alone: the pool is
    /// not rotating, it is being swept.
    pub(crate) fn take_all(&mut self) -> VecDeque<PooledCarrier> {
        let taken = std::mem::take(&mut self.guard.entries);
        maybe_shrink_vecdeque(&mut self.guard.entries);
        taken
    }

    /// Puts probed survivors back, dropping any whose wire the pool no longer
    /// prewarms. Returns how many were dropped.
    ///
    /// A sweep holds its carriers outside the lock for as long as the probes
    /// take, and the pool looks *empty* for that whole stretch — long enough
    /// for a take to rotate it onto another wire, or for a refill to find it
    /// cold and claim it. Extending unconditionally would then file carriers
    /// from the old wire under the new one's identity, which is precisely the
    /// hand-out the wire tag exists to prevent. Dropping is correct: nothing
    /// is dialing the wire they belong to any more.
    pub(crate) fn restore(&mut self, carriers: impl IntoIterator<Item = PooledCarrier>) -> usize {
        let wire = self.guard.wire;
        let mut dropped = 0;
        for carrier in carriers {
            if carrier.wire == wire {
                self.guard.entries.push_back(carrier);
            } else {
                dropped += 1;
            }
        }
        maybe_shrink_vecdeque(&mut self.guard.entries);
        dropped
    }

    /// Drops every carrier, leaving the pool's wire alone. Returns how many
    /// were dropped.
    pub(crate) fn clear(&mut self) -> usize {
        let dropped = self.guard.entries.len();
        self.guard.entries.clear();
        maybe_shrink_vecdeque(&mut self.guard.entries);
        dropped
    }

    /// Test-only door for staging a carrier the guard API would refuse: one
    /// dialed on `wire` sitting in a pool that prewarms a different one.
    ///
    /// That state is not reachable through any production path any more —
    /// which is the point of the fix, and also why the take path's defence
    /// against it cannot be exercised without a door. Production code has no
    /// such door: every real insertion goes through
    /// [`Self::push_for_wire`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn stage_carrier_for_test(&mut self, wire: u8, stream: TransportStream) {
        self.guard.entries.push_back(PooledCarrier { wire, stream });
    }
}

impl Drop for WirePoolGuard<'_> {
    fn drop(&mut self) {
        self.len.store(self.guard.entries.len(), Ordering::Relaxed);
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
    ///
    /// Gated on `test-helpers` too, not just `cfg(test)`: it backs
    /// `UplinkManager::refill_spawned_count_for_test`, which is exposed to
    /// dependent crates' own test builds (`outline-tun`, `outline-ws-rust`)
    /// through that feature rather than through this crate's own `cargo test`.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn spawned(&self) -> u64 {
        self.spawned.load(Ordering::Relaxed)
    }
}

pub(crate) struct StandbyPool {
    pub(crate) tcp: WirePool,
    pub(crate) udp: WirePool,
    pub(crate) tcp_refill: Mutex<()>,
    pub(crate) udp_refill: Mutex<()>,
    tcp_refill_gate: RefillGate,
    udp_refill_gate: RefillGate,
}

impl StandbyPool {
    pub(crate) fn new() -> Self {
        Self {
            tcp: WirePool::new(),
            udp: WirePool::new(),
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

    /// The pool for `transport`.
    pub(crate) fn wire_pool(&self, transport: TransportKind) -> &WirePool {
        match transport {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }
}
