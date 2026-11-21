use std::time::Duration;

use tokio::time::Instant;

use super::JitteredTicker;

#[tokio::test(start_paused = true)]
async fn gaps_stay_within_the_jitter_range_and_vary() {
    let period = Duration::from_secs(60);
    let mut ticker = JitteredTicker::new(period);
    let mut gaps = Vec::new();
    let mut last = Instant::now();
    for _ in 0..64 {
        ticker.tick().await;
        let now = Instant::now();
        gaps.push(now - last);
        last = now;
    }
    for gap in &gaps {
        assert!(*gap <= period + Duration::from_millis(1), "gap {gap:?} exceeds the period");
        assert!(*gap >= period.mul_f64(0.7), "gap {gap:?} is below the jitter floor");
    }
    gaps.sort();
    gaps.dedup();
    assert!(gaps.len() > 8, "64 ticks produced only {} distinct gaps", gaps.len());
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_tick_does_not_rearm_the_deadline() {
    let period = Duration::from_secs(60);
    let mut ticker = JitteredTicker::new(period);
    let start = Instant::now();
    // Poll and drop `tick()` repeatedly, as a `select!` with busier branches does.
    for _ in 0..10 {
        let _ = tokio::time::timeout(Duration::from_secs(1), ticker.tick()).await;
    }
    ticker.tick().await;
    assert!(Instant::now() - start <= period + Duration::from_millis(1));
}
