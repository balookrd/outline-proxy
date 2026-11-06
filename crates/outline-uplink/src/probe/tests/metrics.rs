use std::time::Duration;

use super::*;

fn key(uplink: &str, probe: &'static str) -> StageKey {
    StageKey {
        group: "main".to_owned(),
        uplink: uplink.to_owned(),
        transport: "udp",
        probe,
    }
}

#[test]
fn a_failure_streak_warns_once_and_reports_its_length_on_recovery() {
    let mut streaks = FailureStreaks::default();
    assert_eq!(streaks.observe(key("a", "dns"), true), StageLog::Quiet);
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::FirstFailure);
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::RepeatFailure(2));
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::RepeatFailure(3));
    assert_eq!(streaks.observe(key("a", "dns"), true), StageLog::Recovered(3));
    assert_eq!(streaks.observe(key("a", "dns"), true), StageLog::Quiet);
    // A new streak warns again.
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::FirstFailure);
}

#[test]
fn streaks_are_kept_per_stage_and_only_while_failing() {
    let mut streaks = FailureStreaks::default();
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::FirstFailure);
    assert_eq!(streaks.observe(key("a", "ws"), false), StageLog::FirstFailure);
    assert_eq!(streaks.observe(key("b", "dns"), false), StageLog::FirstFailure);
    assert_eq!(streaks.failing.len(), 3);
    assert_eq!(streaks.observe(key("a", "ws"), true), StageLog::Recovered(1));
    assert_eq!(streaks.observe(key("a", "dns"), false), StageLog::RepeatFailure(2));
    assert_eq!(streaks.failing.len(), 2);
}

#[tokio::test]
async fn a_stage_that_runs_out_of_budget_is_reported_as_a_failure() {
    let uplink = "metrics-test-stalled-stage";
    let result = run_stage(
        "main",
        uplink,
        "udp",
        "dns",
        Duration::from_millis(20),
        std::future::pending::<Result<()>>(),
    )
    .await;
    let error = format!("{:#}", result.expect_err("a stalled stage must fail"));
    assert_eq!(error, "no answer within 20 ms");
    // The timeout went through the streak bookkeeping like any other failure.
    assert_eq!(STAGE_STREAKS.lock().observe(key(uplink, "dns"), true), StageLog::Recovered(1));
}

#[tokio::test]
async fn a_stage_error_passes_through_unchanged() {
    let result = run_stage(
        "main",
        "metrics-test-failing-stage",
        "udp",
        "dns",
        Duration::from_secs(5),
        async { Err::<(), _>(anyhow!("failed to read DNS probe response")) },
    )
    .await;
    assert_eq!(
        format!("{:#}", result.expect_err("the stage error must propagate")),
        "failed to read DNS probe response"
    );
}
