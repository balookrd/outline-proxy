use std::time::Duration;

use super::*;

#[test]
fn bounds_are_reachable() {
    let interval = Duration::from_secs(60);
    assert_eq!(jitter_down(interval, 0), interval);
    assert_eq!(jitter_down(interval, JITTER_DOWN_MAX_PERMILLE), Duration::from_secs(42));
    // The draw wraps, so the cut never exceeds the maximum.
    assert_eq!(jitter_down(interval, JITTER_DOWN_MAX_PERMILLE + 1), interval);
}

#[test]
fn zero_interval_stays_zero() {
    assert_eq!(jitter_down(Duration::ZERO, 12345), Duration::ZERO);
}

proptest::proptest! {
    #[test]
    fn never_longer_and_at_most_thirty_percent_shorter(millis in 0u64..86_400_000, rand: u32) {
        let interval = Duration::from_millis(millis);
        let jittered = jitter_down(interval, rand);
        proptest::prop_assert!(jittered <= interval);
        proptest::prop_assert!(jittered >= interval.mul_f64(0.7));
    }
}
