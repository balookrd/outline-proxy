use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::time::Instant;

use super::{HEDGE_SCHEDULE, RaceOutcome, race_handshake};

/// What one scripted attempt does: wait `after`, then succeed with its index
/// or fail; `Silent` never finishes.
#[derive(Clone, Copy)]
enum Step {
    Ok(Duration),
    Err(Duration),
    Silent,
}

/// Records when each attempt started and whether it was dropped unfinished.
#[derive(Default)]
struct Log {
    started: Mutex<Vec<Duration>>,
    dropped: Mutex<Vec<Arc<AtomicBool>>>,
}

impl Log {
    fn starts(&self) -> Vec<Duration> {
        self.started.lock().unwrap().clone()
    }

    fn dropped(&self, index: usize) -> bool {
        self.dropped.lock().unwrap()[index].load(Ordering::SeqCst)
    }
}

/// Sets its flag when dropped before being disarmed.
struct DropFlag(Arc<AtomicBool>, bool);

impl Drop for DropFlag {
    fn drop(&mut self) {
        if !self.1 {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

async fn race(script: &[Step], log: &Arc<Log>) -> Result<(usize, RaceOutcome)> {
    let origin = Instant::now();
    race_handshake(
        |index| {
            let step = script[index];
            let log = Arc::clone(log);
            log.started.lock().unwrap().push(origin.elapsed());
            let flag = Arc::new(AtomicBool::new(false));
            log.dropped.lock().unwrap().push(Arc::clone(&flag));
            async move {
                let mut guard = DropFlag(flag, false);
                let result = match step {
                    Step::Ok(after) => {
                        tokio::time::sleep(after).await;
                        Ok(index)
                    },
                    Step::Err(after) => {
                        tokio::time::sleep(after).await;
                        Err(anyhow!("attempt {index} failed"))
                    },
                    Step::Silent => std::future::pending().await,
                };
                guard.1 = true;
                result
            }
        },
        &HEDGE_SCHEDULE,
    )
    .await
}

const MS: fn(u64) -> Duration = Duration::from_millis;

#[tokio::test(start_paused = true)]
async fn fast_first_attempt_wins_without_hedging() {
    let log = Arc::new(Log::default());
    let (winner, outcome) = race(&[Step::Ok(MS(200))], &log).await.unwrap();
    assert_eq!(winner, 0);
    assert_eq!(outcome, RaceOutcome { winner: 0, started: 1 });
    assert!(!outcome.hedged());
    assert_eq!(log.starts(), vec![MS(0)]);
}

#[tokio::test(start_paused = true)]
async fn silent_first_attempt_is_raced_by_a_second_at_one_second() {
    let log = Arc::new(Log::default());
    let start = Instant::now();
    let (winner, outcome) = race(&[Step::Silent, Step::Ok(MS(50))], &log).await.unwrap();
    assert_eq!(winner, 1);
    assert_eq!(outcome, RaceOutcome { winner: 1, started: 2 });
    assert!(outcome.hedged());
    assert_eq!(start.elapsed(), MS(1_050));
    assert_eq!(log.starts(), vec![MS(0), MS(1_000)]);
    assert!(log.dropped(0), "the silent attempt must be abandoned");
}

#[tokio::test(start_paused = true)]
async fn third_attempt_starts_at_three_seconds_and_no_fourth() {
    let log = Arc::new(Log::default());
    let start = Instant::now();
    let (winner, outcome) = race(&[Step::Silent, Step::Silent, Step::Ok(MS(50))], &log)
        .await
        .unwrap();
    assert_eq!(winner, 2);
    assert_eq!(outcome, RaceOutcome { winner: 2, started: 3 });
    assert_eq!(start.elapsed(), MS(3_050));
    assert_eq!(log.starts(), vec![MS(0), MS(1_000), MS(3_000)]);
    assert!(log.dropped(0) && log.dropped(1));
}

#[tokio::test(start_paused = true)]
async fn first_attempt_slower_than_the_hedge_still_wins() {
    let log = Arc::new(Log::default());
    let (winner, outcome) = race(&[Step::Ok(MS(1_200)), Step::Silent], &log).await.unwrap();
    assert_eq!(winner, 0);
    assert_eq!(outcome, RaceOutcome { winner: 0, started: 2 });
    assert!(outcome.hedged());
    assert!(log.dropped(1));
}

#[tokio::test(start_paused = true)]
async fn lone_failure_is_returned_at_once() {
    let log = Arc::new(Log::default());
    let start = Instant::now();
    let error = race(&[Step::Err(MS(100))], &log).await.unwrap_err();
    assert_eq!(error.to_string(), "attempt 0 failed");
    assert_eq!(start.elapsed(), MS(100));
    assert_eq!(log.starts(), vec![MS(0)]);
}

#[tokio::test(start_paused = true)]
async fn failure_beside_an_attempt_in_flight_does_not_end_the_race() {
    let log = Arc::new(Log::default());
    let (winner, _) = race(&[Step::Silent, Step::Err(MS(10)), Step::Ok(MS(10))], &log)
        .await
        .unwrap();
    assert_eq!(winner, 2);
    assert_eq!(log.starts(), vec![MS(0), MS(1_000), MS(3_000)]);
}

#[tokio::test(start_paused = true)]
async fn last_failure_is_returned_once_nothing_is_in_flight() {
    let log = Arc::new(Log::default());
    let error = race(&[Step::Err(MS(1_500)), Step::Err(MS(100))], &log)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "attempt 0 failed");
    assert_eq!(log.starts(), vec![MS(0), MS(1_000)]);
}

#[tokio::test(start_paused = true)]
async fn all_silent_attempts_are_dropped_by_the_callers_timeout() {
    let log = Arc::new(Log::default());
    let script = [Step::Silent, Step::Silent, Step::Silent];
    let result = tokio::time::timeout(Duration::from_secs(10), race(&script, &log)).await;
    assert!(result.is_err(), "the race must stay pending until the caller gives up");
    assert_eq!(log.starts(), vec![MS(0), MS(1_000), MS(3_000)]);
    assert!((0..3).all(|index| log.dropped(index)));
}

// ── Real handshakes through a flow-discarding path ───────────────────────────

/// A path that discards the first dial's flow: the race wins from a fresh
/// source port about one second in, instead of waiting out the carrier budget.
#[tokio::test]
async fn hedge_from_a_fresh_port_beats_a_discarded_flow() {
    let lb = crate::quic::loopback::Loopback::new();
    let (via, relay) = crate::quic::loopback::drop_first_flow(lb.addr).await;
    let server = lb.server.clone();
    let accept = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });

    let start = std::time::Instant::now();
    let ((_endpoint, conn), outcome) = tokio::time::timeout(
        Duration::from_secs(10),
        race_handshake(
            |_| async {
                Ok::<_, anyhow::Error>(
                    lb.connect_via(
                        via,
                        quinn::EndpointConfig::default(),
                        quinn::TransportConfig::default(),
                    )
                    .await,
                )
            },
            &HEDGE_SCHEDULE,
        ),
    )
    .await
    .expect("the race must finish within the carrier budget")
    .unwrap();
    let elapsed = start.elapsed();
    let _server_conn = accept.await.unwrap();
    relay.abort();

    assert_eq!(outcome, RaceOutcome { winner: 1, started: 2 });
    assert!(
        (Duration::from_secs(1)..Duration::from_secs(2)).contains(&elapsed),
        "the hedge should win right after its 1 s start, took {elapsed:?}"
    );
    assert!(conn.close_reason().is_none(), "the winning connection must stay open");
}

/// On a clean path the first attempt finishes long before the first hedge point.
#[tokio::test]
async fn clean_path_never_hedges() {
    let lb = crate::quic::loopback::Loopback::new();
    let server = lb.server.clone();
    let accept = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
    let (_, outcome) = race_handshake(
        |_| async {
            Ok::<_, anyhow::Error>(
                lb.connect(quinn::EndpointConfig::default(), quinn::TransportConfig::default())
                    .await,
            )
        },
        &HEDGE_SCHEDULE,
    )
    .await
    .unwrap();
    let _server_conn = accept.await.unwrap();
    assert_eq!(outcome, RaceOutcome { winner: 0, started: 1 });
}
