use std::sync::Arc;

use super::super::carrier_slots::{CarrierSlots, carrier_flow_cap};

#[test]
fn acquires_up_to_cap_then_refuses() {
    let slots = Arc::new(CarrierSlots::new(2));
    let first = slots.try_acquire().expect("first slot");
    let _second = slots.try_acquire().expect("second slot");
    assert!(slots.try_acquire().is_none(), "the cap must bind");
    assert_eq!(slots.in_use(), 2);

    drop(first);
    assert_eq!(slots.in_use(), 1);
    assert!(slots.try_acquire().is_some(), "a released slot is reusable");
}

/// The guard is the whole point: a flow torn down on any path — close, RST
/// abort, eviction, engine drop — gives its slot back because the state that
/// owned it was dropped, not because some teardown branch remembered to.
#[test]
fn dropping_the_guard_returns_the_slot() {
    let slots = Arc::new(CarrierSlots::new(1));
    {
        let _slot = slots.try_acquire().expect("slot");
        assert_eq!(slots.in_use(), 1);
        assert!(slots.try_acquire().is_none());
    }
    assert_eq!(slots.in_use(), 0);
    assert!(slots.try_acquire().is_some(), "the slot came back on drop");
}

/// `0` keeps the historical meaning of `max_carrier_flows`: the cap is off. The
/// counter still tracks live carriers so the gauge reports them, but it never
/// refuses — otherwise enabling the metric would silently start evicting flows
/// on every node that left the option unset.
#[test]
fn zero_cap_means_disabled_and_never_refuses() {
    let slots = Arc::new(CarrierSlots::new(0));
    let held: Vec<_> = (0..1_000)
        .map(|_| slots.try_acquire().expect("never refuses"))
        .collect();
    assert_eq!(slots.in_use(), 1_000);
    assert_eq!(slots.cap(), 0);
    drop(held);
    assert_eq!(slots.in_use(), 0);
}

/// The eviction path pays for its place before the victim's slot is actually
/// free, so this deliberately goes over the cap — and must come back down as
/// the victims finish draining.
#[test]
fn evicted_admission_may_overshoot_and_then_converges() {
    let slots = Arc::new(CarrierSlots::new(1));
    let victim = slots.try_acquire().expect("first slot");
    assert!(slots.try_acquire().is_none(), "cap binds before eviction");

    let newcomer = slots.acquire_evicted();
    assert_eq!(slots.in_use(), 2, "overshoot while the victim drains");

    drop(victim);
    assert_eq!(slots.in_use(), 1, "back within the cap once the victim is gone");
    drop(newcomer);
    assert_eq!(slots.in_use(), 0);
}

#[test]
fn cap_is_reported_as_configured() {
    let slots = Arc::new(CarrierSlots::new(256));
    assert_eq!(slots.cap(), 256);
    assert_eq!(slots.in_use(), 0);
}

/// Mirrors what `tunnelled_flow_cap` did on the UDP path before the counter was
/// shared. Unset must resolve to `max_flows` rather than to "unbounded": the
/// tunnelled tables were always capped by it, and losing that on every node
/// that omits the option would be a regression, not a no-op.
#[test]
fn unset_carrier_cap_falls_back_to_max_flows() {
    assert_eq!(carrier_flow_cap(0, 1024), 1024);
}

#[test]
fn carrier_cap_is_clamped_to_max_flows() {
    assert_eq!(carrier_flow_cap(256, 1024), 256);
    assert_eq!(carrier_flow_cap(4096, 1024), 1024, "a cap above the table limit is a no-op");
}
