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
            refresh(&metrics);
        }
    });
}

// /proc/self/{status,smaps} are kernel pseudo-files: the read returns instantly
// (single-digit ms even on multi-GiB processes) without touching disk. Doing
// it inline on the tokio runtime avoids burning a one-shot blocking thread
// per sample, which under mimalloc would leak a fresh per-thread segment
// (~64 MiB) into the abandoned pool every 15 seconds.
fn refresh(metrics: &Arc<Metrics>) {
    let snapshot = sample_process_memory();
    *metrics.process_memory_snapshot.write() = snapshot;
}
