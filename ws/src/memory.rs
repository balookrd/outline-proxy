use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::fs;
use std::hash::{BuildHasher, Hash};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use tokio::time::sleep;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::info;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use crate::metrics;

const SHRINK_MIN_CAPACITY: usize = 256;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const TRIM_INTERVAL_SECS: u64 = 30;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
static LAST_TRIM_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct ProcessMemorySnapshot {
    pub rss_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub heap_bytes: Option<u64>,
    pub heap_allocated_bytes: Option<u64>,
    pub heap_free_bytes: Option<u64>,
    pub heap_mode: &'static str,
    pub open_fds: Option<u64>,
    pub thread_count: Option<u64>,
    pub fd_snapshot: Option<ProcessFdSnapshot>,
}

impl Default for ProcessMemorySnapshot {
    fn default() -> Self {
        Self {
            rss_bytes: None,
            virtual_bytes: None,
            heap_bytes: None,
            heap_allocated_bytes: None,
            heap_free_bytes: None,
            heap_mode: "unavailable",
            open_fds: None,
            thread_count: None,
            fd_snapshot: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessFdSnapshot {
    pub total: u64,
    pub sockets: u64,
    pub pipes: u64,
    pub anon_inodes: u64,
    pub regular_files: u64,
    pub other: u64,
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
    let fd_snapshot = sample_process_fd_snapshot();
    let (heap_bytes, heap_allocated_bytes, heap_free_bytes, heap_mode) =
        sample_process_heap_state();
    let snapshot = ProcessMemorySnapshot {
        rss_bytes: sample_process_rss_bytes(),
        virtual_bytes: sample_process_virtual_bytes(),
        heap_bytes,
        heap_allocated_bytes,
        heap_free_bytes,
        heap_mode,
        open_fds: fd_snapshot.map(|snapshot| snapshot.total),
        thread_count: sample_process_thread_count(),
        fd_snapshot,
    };
    if snapshot.rss_bytes.is_none()
        && snapshot.virtual_bytes.is_none()
        && snapshot.heap_bytes.is_none()
        && snapshot.open_fds.is_none()
        && snapshot.thread_count.is_none()
    {
        debug!(
            "process resource sampler did not produce rss, virtual, heap, open_fds, or thread_count values"
        );
    }
    snapshot
}

pub fn log_process_fd_snapshot() {
    #[cfg(target_os = "linux")]
    {
        if let Some(snapshot) = sample_process_fd_snapshot() {
            info!(
                open_fds = snapshot.total,
                socket_fds = snapshot.sockets,
                pipe_fds = snapshot.pipes,
                anon_inode_fds = snapshot.anon_inodes,
                regular_file_fds = snapshot.regular_files,
                other_fds = snapshot.other,
                "process fd snapshot"
            );
        } else {
            debug!("process fd snapshot unavailable");
        }
    }
}

pub fn spawn_periodic_trim_loop(interval: Duration) {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            trim_memory_now("periodic", false);
        }
    });

    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = interval;
        debug!("periodic malloc_trim loop requested but unsupported on this platform or allocator");
    }
}

fn release_to_os_if_supported() {
    trim_memory_now("opportunistic", true);
}

fn trim_memory_now(reason: &'static str, respect_min_interval: bool) {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        if respect_min_interval && should_skip_trim_due_to_interval() {
            return;
        }

        let before = sample_process_memory();
        let trimmed = unsafe { libc::malloc_trim(0) != 0 };
        let after = sample_process_memory();
        let rss_released_bytes = released_bytes(before.rss_bytes, after.rss_bytes);
        let heap_released_bytes = released_bytes(before.heap_bytes, after.heap_bytes);
        metrics::record_malloc_trim(
            reason,
            trimmed,
            before.rss_bytes,
            after.rss_bytes,
            rss_released_bytes,
            before.heap_allocated_bytes,
            after.heap_allocated_bytes,
            heap_released_bytes,
        );
        info!(
            reason,
            trimmed,
            rss_before_bytes = before.rss_bytes,
            rss_after_bytes = after.rss_bytes,
            heap_before_bytes = before.heap_bytes,
            heap_after_bytes = after.heap_bytes,
            rss_released_bytes,
            heap_released_bytes,
            "malloc_trim invoked"
        );
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (reason, respect_min_interval);
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

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn should_skip_trim_due_to_interval() -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let last = LAST_TRIM_UNIX_SECS.load(Ordering::Relaxed);
    if now_secs.saturating_sub(last) < TRIM_INTERVAL_SECS {
        return true;
    }
    LAST_TRIM_UNIX_SECS
        .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
}

#[cfg(target_os = "linux")]
fn sample_process_rss_bytes() -> Option<u64> {
    sample_proc_statm_resident_bytes()
        .or_else(|| sample_proc_status_kib("VmRSS").map(|value_kib| value_kib.saturating_mul(1024)))
}

#[cfg(not(target_os = "linux"))]
fn sample_process_rss_bytes() -> Option<u64> {
    None
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    let heap = unsafe { libc::mallinfo() };
    let allocated = heap.uordblks.max(0) as u64;
    let free = heap.fordblks.max(0) as u64;
    (
        Some(allocated.saturating_add(free)),
        Some(allocated),
        Some(free),
        "exact",
    )
}

#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    (
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        None,
        "estimated",
    )
}

#[cfg(all(not(target_os = "linux"),))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    (None, None, None, "unavailable")
}

#[cfg(target_os = "linux")]
fn sample_process_virtual_bytes() -> Option<u64> {
    sample_proc_statm_virtual_bytes().or_else(|| {
        sample_proc_status_kib("VmSize").map(|value_kib| value_kib.saturating_mul(1024))
    })
}

#[cfg(not(target_os = "linux"))]
fn sample_process_virtual_bytes() -> Option<u64> {
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

#[cfg(target_os = "linux")]
fn sample_proc_statm_resident_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = page_size_bytes()?;
    Some(resident_pages.saturating_mul(page_size))
}

#[cfg(target_os = "linux")]
fn sample_proc_statm_virtual_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let total_pages = statm.split_whitespace().next()?.parse::<u64>().ok()?;
    let page_size = page_size_bytes()?;
    Some(total_pages.saturating_mul(page_size))
}

#[cfg(target_os = "linux")]
fn sample_process_fd_snapshot() -> Option<ProcessFdSnapshot> {
    let mut snapshot = ProcessFdSnapshot::default();
    let entries = fs::read_dir("/proc/self/fd").ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        snapshot.total = snapshot.total.saturating_add(1);
        let target = fs::read_link(entry.path()).ok();
        match target.as_ref().and_then(|path| path.to_str()) {
            Some(value) if value.starts_with("socket:") => {
                snapshot.sockets = snapshot.sockets.saturating_add(1);
            }
            Some(value) if value.starts_with("pipe:") => {
                snapshot.pipes = snapshot.pipes.saturating_add(1);
            }
            Some(value) if value.starts_with("anon_inode:") => {
                snapshot.anon_inodes = snapshot.anon_inodes.saturating_add(1);
            }
            Some(value)
                if value.starts_with('/')
                    || value.starts_with("./")
                    || value.starts_with("../") =>
            {
                snapshot.regular_files = snapshot.regular_files.saturating_add(1);
            }
            _ => {
                snapshot.other = snapshot.other.saturating_add(1);
            }
        }
    }
    Some(snapshot)
}

#[cfg(not(target_os = "linux"))]
fn sample_process_fd_snapshot() -> Option<ProcessFdSnapshot> {
    None
}

#[cfg(target_os = "linux")]
fn sample_process_thread_count() -> Option<u64> {
    let mut task_entries = 0u64;
    if let Ok(entries) = fs::read_dir("/proc/self/task") {
        for entry in entries {
            if entry.is_ok() {
                task_entries = task_entries.saturating_add(1);
            }
        }
        if task_entries > 0 {
            return Some(task_entries);
        }
    }

    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let value = line.strip_prefix("Threads")?.trim();
        let value = value.strip_prefix(':')?.trim();
        let number = value.split_whitespace().next()?.parse::<u64>().ok()?;
        return Some(number);
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn sample_process_thread_count() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn page_size_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size > 0 {
            return Some(page_size as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn sample_process_thread_count_reports_positive_value() {
        let count = super::sample_process_thread_count();
        assert!(matches!(count, Some(value) if value > 0));
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn sample_process_memory_reports_exact_heap_state() {
        let sample = super::sample_process_memory();
        assert_eq!(sample.heap_mode, "exact");
        assert!(sample.heap_allocated_bytes.is_some());
        assert!(sample.heap_bytes.is_some());
    }

    #[cfg(all(target_os = "linux", not(target_env = "gnu")))]
    #[test]
    fn sample_process_memory_reports_nonempty_heap_state() {
        let sample = super::sample_process_memory();
        assert_ne!(sample.heap_mode, "unavailable");
    }
}
