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

async fn refresh(metrics: &Arc<Metrics>) {
    #[cfg(target_os = "linux")]
    let snapshot = match tokio::task::spawn_blocking(sample_process_memory).await {
        Ok(snapshot) => snapshot,
        Err(_) => return,
    };

    #[cfg(not(target_os = "linux"))]
    let snapshot = sample_process_memory();

    *metrics.process_memory_snapshot.write() = snapshot;
}
