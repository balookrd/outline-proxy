use std::sync::Arc;

use tokio::time::{Duration, MissedTickBehavior};

use super::Metrics;
use crate::metrics::process_memory::sample as sample_process_memory;

const INTERVAL_SECS: u64 = 15;

pub(super) fn spawn(metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            refresh(&metrics).await;
        }
    });
}

// Run `/proc/self/{status,smaps}` parsing off the async runtime workers (mirroring
// `outline-client`'s `collect_off_runtime`), so a large mapping table never
// stalls reactor polling.
async fn refresh(metrics: &Arc<Metrics>) {
    match tokio::task::spawn_blocking(sample_process_memory).await {
        Ok(snapshot) => {
            *metrics.process_memory_snapshot.write() = snapshot;
        },
        Err(error) => {
            tracing::debug!(%error, "process metrics sampling task failed");
        },
    }
}
