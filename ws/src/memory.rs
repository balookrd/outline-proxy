use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hash};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use tracing::info;

const SHRINK_MIN_CAPACITY: usize = 256;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const TRIM_INTERVAL_SECS: u64 = 30;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
static LAST_TRIM_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemorySnapshot {
    pub rss_bytes: Option<u64>,
    pub heap_bytes: Option<u64>,
}

pub fn maybe_shrink_hash_map<K, V, S>(map: &mut HashMap<K, V, S>)
where
    K: Eq + Hash,
    S: BuildHasher,
{
    if should_shrink(map.len(), map.capacity()) {
        map.shrink_to_fit();
        release_to_os_if_supported();
    }
}

pub fn maybe_shrink_vecdeque<T>(deque: &mut VecDeque<T>) {
    if should_shrink(deque.len(), deque.capacity()) {
        deque.shrink_to_fit();
        release_to_os_if_supported();
    }
}

fn should_shrink(len: usize, capacity: usize) -> bool {
    capacity >= SHRINK_MIN_CAPACITY && len.saturating_mul(4) <= capacity
}

pub fn sample_process_memory() -> ProcessMemorySnapshot {
    ProcessMemorySnapshot {
        rss_bytes: sample_process_rss_bytes(),
        heap_bytes: sample_process_heap_bytes(),
    }
}

fn release_to_os_if_supported() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let last = LAST_TRIM_UNIX_SECS.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) < TRIM_INTERVAL_SECS {
            return;
        }
        if LAST_TRIM_UNIX_SECS
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let before = sample_process_memory();
        let trimmed = unsafe { libc::malloc_trim(0) != 0 };
        let after = sample_process_memory();
        info!(
            trimmed,
            rss_before_bytes = before.rss_bytes,
            rss_after_bytes = after.rss_bytes,
            heap_before_bytes = before.heap_bytes,
            heap_after_bytes = after.heap_bytes,
            rss_released_bytes = released_bytes(before.rss_bytes, after.rss_bytes),
            heap_released_bytes = released_bytes(before.heap_bytes, after.heap_bytes),
            "malloc_trim invoked"
        );
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn released_bytes(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(before), Some(after)) if before >= after => Some(before - after),
        (Some(_), Some(_)) => Some(0),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn sample_process_rss_bytes() -> Option<u64> {
    sample_proc_status_kib("VmRSS").map(|value_kib| value_kib.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
fn sample_process_rss_bytes() -> Option<u64> {
    None
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn sample_process_heap_bytes() -> Option<u64> {
    let heap = unsafe { libc::mallinfo2().uordblks };
    if heap > 0 {
        Some(heap as u64)
    } else {
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024))
    }
}

#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
fn sample_process_heap_bytes() -> Option<u64> {
    sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
fn sample_process_heap_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn sample_proc_status_kib(field: &str) -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let value = line.strip_prefix(field)?.trim();
        let value = value.strip_prefix(':')?.trim();
        let number = value.split_whitespace().next()?.parse::<u64>().ok()?;
        return Some(number);
    }
    None
}
