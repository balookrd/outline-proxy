//! Metrics facade — re-exports everything from the `outline-metrics`
//! workspace crate so existing `crate::metrics::*` paths keep working.
//!
//! Lives here rather than in the crate: [`spawn_process_metrics_sampler`]
//! wires the main-binary sampler in `crate::memory` to the crate's
//! `update_process_memory` on a 15-second tick; the crate itself must not
//! depend on the sampler (it lives in main because of Linux /proc parsing).

pub use outline_metrics::*;

#[cfg(feature = "metrics")]
pub fn spawn_process_metrics_sampler() {
    tokio::spawn(async move {
        let mut sample_count: u64 = 0;
        loop {
            let sample = crate::memory::sample_process_memory();
            outline_metrics::update_process_memory(
                sample.rss_bytes,
                sample.virtual_bytes,
                sample.heap_bytes,
                sample.heap_allocated_bytes,
                sample.heap_free_bytes,
                sample.heap_mode,
                sample.open_fds,
                sample.thread_count,
                sample.fd_snapshot,
            );
            sample_count = sample_count.saturating_add(1);
            if sample_count.is_multiple_of(4) {
                crate::memory::log_process_fd_snapshot();
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    });
}

#[cfg(not(feature = "metrics"))]
pub fn spawn_process_metrics_sampler() {}

#[cfg(feature = "metrics")]
pub fn init() {
    // Initial prometheus registry init + an initial memory sample so the
    // first scrape sees non-zero process.* gauges.
    outline_metrics::init();
    let sample = crate::memory::sample_process_memory();
    outline_metrics::update_process_memory(
        sample.rss_bytes,
        sample.virtual_bytes,
        sample.heap_bytes,
        sample.heap_allocated_bytes,
        sample.heap_free_bytes,
        sample.heap_mode,
        sample.open_fds,
        sample.thread_count,
        sample.fd_snapshot,
    );
}

#[cfg(not(feature = "metrics"))]
pub fn init() {}
