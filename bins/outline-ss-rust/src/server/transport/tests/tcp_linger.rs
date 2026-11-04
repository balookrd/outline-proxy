use std::time::Duration;

use super::*;

/// A target that keeps taking a byte at a time renews the no-progress budget
/// forever; the absolute cap ends the wait anyway, so a departed client's
/// upstream cannot stay open for hours.
#[tokio::test(start_paused = true)]
async fn steady_progress_cannot_outlast_the_cap() {
    let budget = Duration::from_secs(4);
    let mut patience = LingerPatience::new(budget);
    let started = tokio::time::Instant::now();
    let mut samples = 0u32;
    while patience.keep_waiting(true) {
        tokio::time::advance(Duration::from_secs(1)).await;
        samples += 1;
        assert!(samples < 1_000, "never gave up on a trickling target");
    }
    let waited = started.elapsed();
    assert!(waited > budget, "progress must renew the budget at least once: {waited:?}");
    assert_eq!(waited, budget * LINGER_HARD_CAP_FACTOR);
}

/// Without progress the wait ends after one budget, well before the cap.
#[tokio::test(start_paused = true)]
async fn no_progress_gives_up_after_one_budget() {
    let budget = Duration::from_secs(4);
    let mut patience = LingerPatience::new(budget);
    let started = tokio::time::Instant::now();
    while patience.keep_waiting(false) {
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    let waited = started.elapsed();
    assert!(waited >= budget && waited < budget * 2, "gave up after {waited:?}");
}
