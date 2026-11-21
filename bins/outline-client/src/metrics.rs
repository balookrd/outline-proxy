//! Main-binary sampler wiring: [`spawn_process_metrics_sampler`] bridges the
//! `/proc`-parsing sampler in `crate::memory` to `outline_metrics::update_process_memory`
//! on a 15-second tick. The `outline_metrics` crate itself must not depend on
//! the sampler (it lives in main because of Linux `/proc` parsing).

/// Runs a `/proc`-walking collector on the blocking pool and hands the result
/// back to the async side.
///
/// The collectors are not cheap: `sample_process_memory` reads every entry of
/// `/proc/self/fd` with one `readlink` per fd and then parses all of
/// `/proc/self/net/{tcp,tcp6,udp,udp6}` line by line. At the 4096-connection
/// accept cap that is thousands of syscalls plus a full connection-table scan
/// per sample — tens of milliseconds with a runtime worker parked on them.
/// On the single-core boxes in the fleet that worker is the *only* one, so an
/// inline sample stalls the relay for the duration. `None` means the blocking
/// task itself failed (panic or runtime shutdown); nothing is published then.
#[cfg(feature = "metrics")]
async fn collect_off_runtime<F, T>(collect: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(collect).await {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::debug!(error = %err, "process metrics sampling task failed");
            None
        },
    }
}

#[cfg(feature = "metrics")]
fn publish_process_memory(sample: crate::memory::ProcessMemorySnapshot) {
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

#[cfg(feature = "metrics")]
pub fn spawn_process_metrics_sampler() {
    tokio::spawn(async move {
        let mut sample_count: u64 = 0;
        loop {
            // Gauges are only touched once the blocking collector has been
            // awaited — the sample never runs on this task's thread.
            if let Some(sample) = collect_off_runtime(crate::memory::sample_process_memory).await {
                publish_process_memory(sample);
            }
            sample_count = sample_count.saturating_add(1);
            if sample_count.is_multiple_of(4) {
                let _ = collect_off_runtime(crate::memory::log_process_fd_snapshot).await;
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
    publish_process_memory(crate::memory::sample_process_memory());
}

#[cfg(not(feature = "metrics"))]
pub fn init() {}

#[cfg(all(test, feature = "metrics"))]
#[path = "tests/metrics.rs"]
mod tests;
