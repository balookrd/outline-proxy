//! Process-wide budget of live carriers.
//!
//! Every tunnelled flow — TCP or UDP — dials its own carrier, and a carrier is
//! roughly 28× a direct flow in RSS. `[tun] max_carrier_flows` is the ceiling on
//! how many of them may exist at once, so the counter behind it has to be shared
//! by both engines: a per-protocol slice of the cap would let the two paths add
//! up to twice the configured ceiling, which is exactly the hole this closes
//! (the cap used to bind on the UDP path only).
//!
//! Shared the same way as the dial-admission semaphore — one instance built in
//! [`crate::engine`] and handed to both engines.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use outline_metrics as metrics;

pub(crate) struct CarrierSlots {
    used: AtomicUsize,
    cap: usize,
}

/// RAII ownership of one carrier slot.
///
/// The slot is what the cap actually counts, so it must be returned exactly
/// once, on every teardown path — close, RST abort, eviction, engine drop, or a
/// route flip that turns a tunnelled flow into a direct one. A boolean flag on
/// the flow state cannot promise that: the flow record lives behind an async
/// mutex, and the eviction path hands its victim to a background closer, so the
/// "am I still holding it?" check and the release would race. Holding the slot
/// in a guard makes the release a consequence of the flow's own lifetime.
///
/// Dropping the guard early (`take()` out of the flow state) is the supported
/// way to hand a slot back before the flow itself dies.
pub(crate) struct CarrierSlot {
    slots: Arc<CarrierSlots>,
}

impl Drop for CarrierSlot {
    fn drop(&mut self) {
        self.slots.release();
    }
}

impl CarrierSlots {
    pub(crate) fn new(cap: usize) -> Self {
        Self { used: AtomicUsize::new(0), cap }
    }

    /// Configured ceiling; `0` means the cap is disabled.
    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    /// Live carriers right now — published as a gauge, so it is maintained even
    /// when the cap is disabled.
    pub(crate) fn in_use(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// Takes a slot, returning the guard that owns it. `None` means the caller
    /// must evict one of its own tunnelled flows (or refuse the new one).
    ///
    /// The check and the increment are one CAS, not a load followed by a store:
    /// both engines admit flows concurrently, and a torn check-then-act would
    /// let a burst overshoot the cap by however many flows raced through it —
    /// precisely the burst this is here to bound.
    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<CarrierSlot> {
        if self.cap == 0 {
            let taken = self.used.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::set_tun_carrier_flows_active(taken);
            return Some(CarrierSlot { slots: Arc::clone(self) });
        }
        match self.used.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            (used < self.cap).then_some(used + 1)
        }) {
            Ok(previous) => {
                metrics::set_tun_carrier_flows_active(previous + 1);
                Some(CarrierSlot { slots: Arc::clone(self) })
            },
            Err(_) => None,
        }
    }

    /// Takes a slot without consulting the cap.
    ///
    /// Only for the admission path that has *just* evicted one of its own
    /// tunnelled flows: the victim's slot is not free yet — it is released when
    /// the victim's state is dropped, which happens in the background closer —
    /// so a plain `try_acquire` would refuse a newcomer that already paid for
    /// its place. The overshoot is therefore bounded by the number of flows
    /// still draining, and it converges as they finish; without this the cap
    /// would wedge for as long as a single victim took to tear down.
    pub(crate) fn acquire_evicted(self: &Arc<Self>) -> CarrierSlot {
        let taken = self.used.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::set_tun_carrier_flows_active(taken);
        CarrierSlot { slots: Arc::clone(self) }
    }

    /// Returns a slot. Private: slots are given back by dropping their
    /// [`CarrierSlot`] guard, never by hand, so the count cannot drift.
    fn release(&self) {
        if let Ok(previous) = self
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| Some(used.saturating_sub(1)))
        {
            metrics::set_tun_carrier_flows_active(previous.saturating_sub(1));
        }
    }
}

/// Resolves the configured `max_carrier_flows` against `max_flows`, keeping the
/// meaning the UDP path already had: unset (`0`) falls back to `max_flows`, and
/// a carrier cap above the flow-table limit is a silent no-op, so it is clamped.
///
/// Note that unset does **not** mean "no accounting": the tunnelled tables were
/// always bounded by `max_flows`, and dropping that bound here would let the
/// tunnelled table grow without limit whenever the operator left the option out.
pub(crate) fn carrier_flow_cap(max_carrier_flows: usize, max_flows: usize) -> usize {
    if max_carrier_flows == 0 {
        max_flows
    } else {
        max_carrier_flows.min(max_flows)
    }
}

#[cfg(test)]
#[path = "tests/carrier_slots.rs"]
mod tests;
