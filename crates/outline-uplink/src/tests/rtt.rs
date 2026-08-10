//! Age semantics of a per-wire RTT slot.

use std::time::Duration;

use tokio::time::Instant;

use super::{EXPIRY_HALFLIVES, RttEwma};

const HALFLIFE: Duration = Duration::from_secs(300);

#[test]
fn first_sample_seeds_the_slot_and_later_ones_smooth() {
    let now = Instant::now();
    let mut slot = RttEwma::default();

    slot.record(Some(Duration::from_millis(100)), 0.25, now);
    assert_eq!(slot.value(), Some(Duration::from_millis(100)));

    slot.record(Some(Duration::from_millis(300)), 0.25, now);
    assert_eq!(
        slot.value(),
        Some(Duration::from_millis(150)),
        "the smoothing itself must match the pre-decay update_rtt_ewma contract",
    );
}

#[test]
fn absent_sample_moves_neither_value_nor_timestamp() {
    let now = Instant::now();
    let measured_at = now - Duration::from_secs(120);
    let mut slot = RttEwma::measured(Duration::from_millis(100), measured_at);

    slot.record(None, 0.25, now);

    assert_eq!(slot.value(), Some(Duration::from_millis(100)));
    assert_eq!(
        slot.age(now),
        Some(Duration::from_secs(120)),
        "a cycle that measured nothing must not pass itself off as a fresh measurement",
    );
}

#[test]
fn confidence_halves_every_halflife() {
    let now = Instant::now();
    let fresh = RttEwma::measured(Duration::from_millis(100), now);
    assert!((fresh.confidence(HALFLIFE, now) - 1.0).abs() < 1e-9);

    let one = RttEwma::measured(Duration::from_millis(100), now - HALFLIFE);
    assert!((one.confidence(HALFLIFE, now) - 0.5).abs() < 1e-9);

    let two = RttEwma::measured(Duration::from_millis(100), now - HALFLIFE * 2);
    assert!((two.confidence(HALFLIFE, now) - 0.25).abs() < 1e-9);
}

#[test]
fn confidence_reaches_zero_at_the_expiry_horizon() {
    let now = Instant::now();
    let expired = RttEwma::measured(Duration::from_millis(100), now - HALFLIFE * EXPIRY_HALFLIVES);

    assert_eq!(expired.confidence(HALFLIFE, now), 0.0);
    assert_eq!(
        expired.value(),
        Some(Duration::from_millis(100)),
        "expiry withdraws the slot from ranking; it does not erase what was measured",
    );
    assert_eq!(expired.value_if_unexpired(HALFLIFE, now), None);
}

#[test]
fn zero_halflife_disables_decay() {
    let now = Instant::now();
    let ancient = RttEwma::measured(Duration::from_millis(100), now - Duration::from_secs(86_400));

    assert_eq!(ancient.confidence(Duration::ZERO, now), 1.0);
    assert_eq!(
        ancient.value_if_unexpired(Duration::ZERO, now),
        Some(Duration::from_millis(100)),
        "with the knob off, a day-old slot must rank exactly as it did before decay existed",
    );
}

#[test]
fn unmeasured_slot_carries_no_weight() {
    let now = Instant::now();
    let slot = RttEwma::default();

    assert_eq!(slot.confidence(HALFLIFE, now), 0.0);
    assert_eq!(slot.value(), None);
    assert_eq!(slot.age(now), None);
}

#[test]
fn value_without_timestamp_counts_as_fresh() {
    let now = Instant::now();
    // Defence in depth: every production path stamps, so this asserts the
    // conservative reading of an unstamped value rather than a live case.
    let unstamped = RttEwma {
        value: Some(Duration::from_millis(100)),
        updated_at: None,
    };

    assert_eq!(unstamped.confidence(HALFLIFE, now), 1.0);
    assert_eq!(unstamped.value_if_unexpired(HALFLIFE, now), Some(Duration::from_millis(100)));
}
