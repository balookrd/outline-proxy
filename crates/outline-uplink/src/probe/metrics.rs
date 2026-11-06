//! Metrics attribution helpers for the probe sub-paths.
//!
//! Keeps the probe orchestration code in `probe/mod.rs` focused on
//! transport/protocol logic by centralising the `group / uplink / transport /
//! probe` label tuple that every metric emission needs.

use std::collections::HashMap;
use std::future::Future;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use tokio::time::{Instant, timeout};
use tracing::{debug, info, warn};

/// Runs one probe stage under `budget`, records its duration and outcome, and
/// logs why it failed.
///
/// The budget lives here rather than around the call so that a stage which
/// runs out of time is still recorded: an outer `timeout` would drop this
/// future before it reached `record_probe`, leaving the failure out of
/// `probe_runs_total` and the log alike.
pub(super) async fn run_stage<F, T>(
    group: &str,
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    budget: Duration,
    fut: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let started = Instant::now();
    let result = match timeout(budget, fut).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("no answer within {} ms", budget.as_millis())),
    };
    let elapsed = started.elapsed();
    outline_metrics::record_probe(group, uplink, transport, probe, result.is_ok(), elapsed);
    let key = StageKey {
        group: group.to_owned(),
        uplink: uplink.to_owned(),
        transport,
        probe,
    };
    let elapsed_ms = elapsed.as_millis() as u64;
    match (STAGE_STREAKS.lock().observe(key, result.is_ok()), &result) {
        (StageLog::FirstFailure, Err(error)) => warn!(
            group,
            uplink,
            transport,
            probe,
            elapsed_ms,
            error = %format!("{error:#}"),
            "probe stage failed"
        ),
        (StageLog::RepeatFailure(failures), Err(error)) => debug!(
            group,
            uplink,
            transport,
            probe,
            elapsed_ms,
            failures,
            error = %format!("{error:#}"),
            "probe stage still failing"
        ),
        (StageLog::Recovered(failures), _) if failures > 1 => {
            info!(group, uplink, transport, probe, failures, "probe stage recovered")
        },
        _ => {},
    }
    result
}

/// What to log for a stage outcome, given the stage's earlier outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StageLog {
    /// Succeeded, and the previous run did too.
    Quiet,
    /// The first failure after a success (or the first run).
    FirstFailure,
    /// Failed again; carries the length of the streak so far.
    RepeatFailure(u32),
    /// Succeeded after a streak of this many failures.
    Recovered(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct StageKey {
    pub group: String,
    pub uplink: String,
    pub transport: &'static str,
    pub probe: &'static str,
}

/// Failure streaks of the probe stages that are failing right now.
///
/// One warning per streak keeps a dead uplink, probed every few seconds, from
/// flooding the log while an intermittent failure still shows up every time.
/// A stage is dropped from the map on its first success, so the map holds
/// only stages that are failing and cannot grow past the configured ones.
#[derive(Debug, Default)]
pub(super) struct FailureStreaks {
    failing: HashMap<StageKey, u32>,
}

impl FailureStreaks {
    pub(super) fn observe(&mut self, key: StageKey, ok: bool) -> StageLog {
        if ok {
            return match self.failing.remove(&key) {
                Some(failures) => StageLog::Recovered(failures),
                None => StageLog::Quiet,
            };
        }
        let failures = self.failing.entry(key).or_insert(0);
        *failures = failures.saturating_add(1);
        if *failures == 1 {
            StageLog::FirstFailure
        } else {
            StageLog::RepeatFailure(*failures)
        }
    }
}

static STAGE_STREAKS: LazyLock<Mutex<FailureStreaks>> =
    LazyLock::new(|| Mutex::new(FailureStreaks::default()));

/// Bundles the probe-bytes label tuple so data-path code can count payload
/// bytes without repeating the attribution at every `add_probe_bytes` call.
pub(super) struct BytesRecorder<'a> {
    pub group: &'a str,
    pub uplink: &'a str,
    pub transport: &'static str,
    pub probe: &'static str,
}

impl BytesRecorder<'_> {
    pub(super) fn outgoing(&self, bytes: usize) {
        // Probe request bytes flow toward the target: `up` in the harmonized
        // direction vocabulary.
        outline_metrics::add_probe_bytes(
            self.group,
            self.uplink,
            self.transport,
            self.probe,
            "up",
            bytes,
        );
    }

    pub(super) fn incoming(&self, bytes: usize) {
        // Probe response bytes flow back toward the client: `down`.
        outline_metrics::add_probe_bytes(
            self.group,
            self.uplink,
            self.transport,
            self.probe,
            "down",
            bytes,
        );
    }
}

#[cfg(test)]
#[path = "tests/metrics.rs"]
mod tests;
