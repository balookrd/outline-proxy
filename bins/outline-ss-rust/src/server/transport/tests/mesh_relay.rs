use std::time::Duration;

use tokio::time::Instant;

use super::StallTracker;
use crate::server::transport::throughput_monitor::ThrottleDetectParams;

/// Window 1s, fire after 3 sustained stall-windows, 30s cooldown.
fn tracker() -> StallTracker {
    StallTracker::new(&ThrottleDetectParams {
        window: Duration::from_secs(1),
        sustain_windows: 3,
        signal_cooldown: Duration::from_secs(30),
        ..Default::default()
    })
}

#[tokio::test]
async fn fast_sends_never_fire() {
    let mut t = tracker();
    let now = Instant::now();
    for _ in 0..10 {
        assert!(!t.observe(Duration::from_millis(100), now), "a fast send is not a stall");
    }
}

#[tokio::test]
async fn one_long_send_spans_the_streak() {
    let mut t = tracker();
    // A single send blocked for 3.5 windows already meets sustain_windows(3).
    assert!(t.observe(Duration::from_millis(3500), Instant::now()));
}

#[tokio::test]
async fn gradual_stall_fires_after_sustain_windows() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), now)); // streak 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // streak 2
    assert!(t.observe(Duration::from_millis(1200), now)); // streak 3 -> fire
}

#[tokio::test]
async fn a_fast_send_resets_the_streak() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // 2
    assert!(!t.observe(Duration::from_millis(100), now)); // fast -> reset to 0
    assert!(!t.observe(Duration::from_millis(1200), now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // 2
    assert!(t.observe(Duration::from_millis(1200), now)); // 3 -> fire
}

#[tokio::test]
async fn cooldown_gates_a_second_hint() {
    let mut t = tracker();
    let t0 = Instant::now();
    assert!(t.observe(Duration::from_millis(3500), t0), "first qualifying stall fires");
    // A second qualifying streak within the 30s cooldown is suppressed.
    assert!(!t.observe(Duration::from_millis(3500), t0 + Duration::from_secs(10)));
    // Past the cooldown it fires again.
    assert!(t.observe(Duration::from_millis(3500), t0 + Duration::from_secs(35)));
}
