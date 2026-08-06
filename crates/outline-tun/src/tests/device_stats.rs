use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

/// A throwaway `statistics/` directory populated the way sysfs presents it:
/// one decimal counter per file, trailing newline included.
struct FakeStatisticsDir(PathBuf);

impl FakeStatisticsDir {
    fn new(counters: &[(&str, u64)]) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("outline-tun-devstats-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fake statistics dir");
        for (file, value) in counters {
            std::fs::write(dir.join(file), format!("{value}\n")).expect("write counter file");
        }
        Self(dir)
    }
}

impl Drop for FakeStatisticsDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The netdev names its counters from its own point of view, we name ours from
/// the process's, and the two are inverted. Pin the translation: `rx_*` is what
/// we *wrote*, `tx_*` is what we *read*. Every value here is distinct, so a
/// swapped mapping cannot pass.
#[tokio::test]
async fn read_maps_netdev_rx_to_writes_and_tx_to_reads() {
    let dir = FakeStatisticsDir::new(&[
        ("rx_packets", 100),
        ("rx_dropped", 101),
        ("rx_errors", 102),
        ("tx_packets", 200),
        ("tx_dropped", 201),
        ("tx_errors", 202),
    ]);

    let counters = DeviceCounters::read(&dir.0).await.expect("read counters");

    assert_eq!(
        counters,
        DeviceCounters {
            write_ok: 100,
            write_dropped: 101,
            write_errors: 102,
            read_ok: 200,
            read_dropped: 201,
            read_errors: 202,
        }
    );
}

#[tokio::test]
async fn read_fails_when_the_device_is_gone() {
    let missing = std::env::temp_dir().join("outline-tun-devstats-does-not-exist");

    assert!(DeviceCounters::read(&missing).await.is_err());
}

#[test]
fn delta_is_the_difference_while_the_counter_climbs() {
    assert_eq!(counter_delta(15_180, 15_000), 180);
    assert_eq!(counter_delta(15_180, 15_180), 0);
}

/// A recreated interface restarts its counters at zero. The new absolute value
/// is the delta; subtracting would wrap and inject a ~2^64 spike.
#[test]
fn delta_after_a_counter_reset_is_the_new_value() {
    assert_eq!(counter_delta(7, 15_180), 7);
}
