//! Metrics attribution helpers for the probe sub-paths.
//!
//! Keeps the probe orchestration code in `probe/mod.rs` focused on
//! transport/protocol logic by centralising the `group / uplink / transport /
//! probe` label tuple that every metric emission needs.

use std::future::Future;

use anyhow::Result;
use tokio::time::Instant;

/// Wraps a probe sub-call with duration + success/error metric recording.
/// The inner value is returned on success; errors propagate but are still
/// recorded as an error outcome.
pub(super) async fn record_attempt<F, T>(
    group: &str,
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    fut: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let started = Instant::now();
    let result = fut.await;
    outline_metrics::record_probe(
        group,
        uplink,
        transport,
        probe,
        result.is_ok(),
        started.elapsed(),
    );
    result
}

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
        outline_metrics::add_probe_bytes(
            self.group,
            self.uplink,
            self.transport,
            self.probe,
            "outgoing",
            bytes,
        );
    }

    pub(super) fn incoming(&self, bytes: usize) {
        outline_metrics::add_probe_bytes(
            self.group,
            self.uplink,
            self.transport,
            self.probe,
            "incoming",
            bytes,
        );
    }
}
