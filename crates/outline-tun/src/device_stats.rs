//! Kernel-side packet counters for the TUN netdev, scraped from sysfs.
//!
//! Every other TUN metric in this crate counts what the process itself handed
//! to — or took from — the fd. None of them can see a packet the *kernel*
//! discarded because a queue was full, and that discard is precisely what
//! separates "the path beyond us is lossy" from "we are the loss". Linux
//! publishes it per-netdev under `/sys/class/net/<dev>/statistics/`, which is
//! the only place it is observable from inside the process.
//!
//! **Direction is named from the process side, and is the inverse of the
//! netdev's own rx/tx.** A packet we `write(2)` into the fd is an *ingress*
//! packet for the interface and lands in `rx_*`; a packet the kernel queues for
//! us to `read(2)` is an *egress* one and lands in `tx_*`. So
//! `direction="read", outcome="dropped"` — sourced from `tx_dropped` — means the
//! kernel threw away a client packet because the read loop had not drained the
//! device txqueue (`txqueuelen`) in time. Getting this mapping backwards
//! inverts the diagnosis, so the translation lives here and nowhere else.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, warn};

use outline_metrics as metrics;

/// How often the netdev counters are re-read. These are cumulative kernel
/// counters, so the interval only bounds how stale a scrape can be, not what is
/// observable — it stays well under a typical Prometheus scrape interval while
/// keeping the syscall cost negligible.
const SCRAPE_INTERVAL: Duration = Duration::from_secs(15);

/// One reading of the netdev's `statistics/` directory, already translated into
/// process-side direction.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct DeviceCounters {
    /// `rx_packets`: packets we successfully wrote into the fd.
    write_ok: u64,
    /// `rx_dropped`: packets the kernel discarded on the way in from our writes.
    write_dropped: u64,
    /// `rx_errors`: our writes the kernel rejected outright.
    write_errors: u64,
    /// `tx_packets`: packets the kernel handed us to read.
    read_ok: u64,
    /// `tx_dropped`: packets the kernel discarded because we did not read them
    /// in time — the read loop falling behind the device queue.
    read_dropped: u64,
    /// `tx_errors`: errors on the kernel's egress path towards our reads.
    read_errors: u64,
}

impl DeviceCounters {
    async fn read(dir: &Path) -> Result<Self> {
        Ok(Self {
            write_ok: read_counter(dir, "rx_packets").await?,
            write_dropped: read_counter(dir, "rx_dropped").await?,
            write_errors: read_counter(dir, "rx_errors").await?,
            read_ok: read_counter(dir, "tx_packets").await?,
            read_dropped: read_counter(dir, "tx_dropped").await?,
            read_errors: read_counter(dir, "tx_errors").await?,
        })
    }

    /// Move each exported counter forward by what happened since `previous`.
    fn publish_delta(&self, previous: &Self) {
        for (direction, outcome, current, prior) in [
            ("write", "ok", self.write_ok, previous.write_ok),
            ("write", "dropped", self.write_dropped, previous.write_dropped),
            ("write", "error", self.write_errors, previous.write_errors),
            ("read", "ok", self.read_ok, previous.read_ok),
            ("read", "dropped", self.read_dropped, previous.read_dropped),
            ("read", "error", self.read_errors, previous.read_errors),
        ] {
            metrics::add_tun_device_packets(direction, outcome, counter_delta(current, prior));
        }
    }
}

/// Delta between two readings of a monotonic kernel counter.
///
/// A netdev counter only goes backwards when the interface is recreated
/// underneath us and starts from zero, in which case the new absolute value
/// *is* the delta. Treating that as a wrap-around subtraction would inject a
/// bogus spike of ~2^64 into the series.
fn counter_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

async fn read_counter(dir: &Path, file: &str) -> Result<u64> {
    let path = dir.join(file);
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    raw.trim()
        .parse()
        .with_context(|| format!("failed to parse {} as a counter", path.display()))
}

/// Start scraping the netdev counters for `device_name` in the background.
///
/// Linux-only: no other platform exposes these counters through sysfs, and the
/// caller gates on that.
pub(crate) fn spawn_collector(device_name: &str) {
    let dir = Path::new("/sys/class/net").join(device_name).join("statistics");
    tokio::spawn(collect_loop(dir, SCRAPE_INTERVAL));
}

async fn collect_loop(dir: PathBuf, interval: Duration) {
    // The first reading is a baseline, never published. The fleet runs a
    // *persistent* TUN device created before the service starts, so at startup
    // these counters already carry whatever the previous process did — counting
    // that as our own first-scrape delta would fabricate a large spike.
    let mut previous = match DeviceCounters::read(&dir).await {
        Ok(counters) => counters,
        Err(error) => {
            warn!(
                dir = %dir.display(),
                error = %format!("{error:#}"),
                "TUN netdev counters unreadable; kernel-side drop metric disabled"
            );
            return;
        },
    };

    // Publish the baseline against itself: every delta is zero, but the six
    // series now exist from the first scrape. Without this, `dropped` and
    // `error` would be absent until the very first drop, and an absent series
    // reads the same as a collector that never started.
    previous.publish_delta(&previous);

    let mut ticker = tokio::time::interval(interval);
    // `interval` fires immediately on its first tick; the baseline above already
    // covers that instant.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match DeviceCounters::read(&dir).await {
            Ok(current) => {
                current.publish_delta(&previous);
                previous = current;
            },
            // A transient read failure must not kill the collector: the device
            // can come back (and the counters with it), and a dead task would
            // silently stop the series with no way to notice.
            Err(error) => debug!(
                dir = %dir.display(),
                error = %format!("{error:#}"),
                "failed to scrape TUN netdev counters"
            ),
        }
    }
}

#[cfg(test)]
#[path = "tests/device_stats.rs"]
mod tests;
