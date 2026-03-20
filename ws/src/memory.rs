use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::fs;
use std::hash::{BuildHasher, Hash};
#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
use tokio::time::sleep;
use tracing::debug;
#[cfg(any(target_os = "linux", feature = "allocator-jemalloc"))]
use tracing::info;
#[cfg(feature = "allocator-jemalloc")]
use tracing::warn;

#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
use crate::metrics;
#[cfg(feature = "allocator-jemalloc")]
use tikv_jemalloc_sys as jemalloc_sys;

const SHRINK_MIN_CAPACITY: usize = 256;
#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
const TRIM_INTERVAL_SECS: u64 = 30;

#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
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
        fd_snapshot,
    };
    if snapshot.rss_bytes.is_none()
        && snapshot.virtual_bytes.is_none()
        && snapshot.heap_bytes.is_none()
        && snapshot.open_fds.is_none()
    {
        debug!("process resource sampler did not produce rss, virtual, heap, or open_fds values");
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
    #[cfg(feature = "allocator-jemalloc")]
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            trim_memory_now("periodic", false);
        }
    });

    #[cfg(all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    ))]
    tokio::spawn(async move {
        loop {
            sleep(interval).await;
            trim_memory_now("periodic", false);
        }
    });

    #[cfg(not(any(
        feature = "allocator-jemalloc",
        all(
            target_os = "linux",
            target_env = "gnu",
            not(feature = "allocator-jemalloc")
        )
    )))]
    {
        let _ = interval;
        debug!("periodic malloc_trim loop requested but unsupported on this platform or allocator");
    }
}

fn release_to_os_if_supported() {
    trim_memory_now("opportunistic", true);
}

fn trim_memory_now(reason: &'static str, respect_min_interval: bool) {
    #[cfg(feature = "allocator-jemalloc")]
    {
        if respect_min_interval && should_skip_trim_due_to_interval() {
            return;
        }

        let before = sample_process_memory();
        let background_thread_enabled = ensure_jemalloc_background_thread();
        let epoch_advanced = jemalloc_advance_epoch();
        let after = sample_process_memory();
        let rss_released_bytes = released_bytes(before.rss_bytes, after.rss_bytes);
        let heap_released_bytes = released_bytes(before.heap_bytes, after.heap_bytes);
        metrics::record_malloc_trim(
            reason,
            background_thread_enabled || epoch_advanced,
            before.rss_bytes,
            after.rss_bytes,
            rss_released_bytes,
            before.heap_allocated_bytes,
            after.heap_allocated_bytes,
            heap_released_bytes,
        );
        info!(
            reason,
            background_thread_enabled,
            epoch_advanced,
            rss_before_bytes = before.rss_bytes,
            rss_after_bytes = after.rss_bytes,
            heap_before_bytes = before.heap_bytes,
            heap_after_bytes = after.heap_bytes,
            rss_released_bytes,
            heap_released_bytes,
            "jemalloc background maintenance invoked"
        );
    }
    #[cfg(all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    ))]
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
    #[cfg(not(all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )))]
    {
        let _ = (reason, respect_min_interval);
    }
}

#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
fn released_bytes(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(before), Some(after)) if before >= after => Some(before - after),
        (Some(_), Some(_)) => Some(0),
        _ => None,
    }
}

#[cfg(any(
    feature = "allocator-jemalloc",
    all(
        target_os = "linux",
        target_env = "gnu",
        not(feature = "allocator-jemalloc")
    )
))]
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

#[cfg(feature = "allocator-jemalloc")]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    let _ = jemalloc_advance_epoch();
    let allocated = jemalloc_read_size_stat(b"stats.allocated\0");
    let active = jemalloc_read_size_stat(b"stats.active\0");
    if allocated.is_some() || active.is_some() {
        let free = match (allocated, active) {
            (Some(allocated), Some(active)) if active >= allocated => Some(active - allocated),
            (Some(_), Some(_)) => Some(0),
            _ => None,
        };
        return (active.or(allocated), allocated, free, "jemalloc");
    }

    (None, None, None, "unavailable")
}

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    not(feature = "allocator-jemalloc")
))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    let heap = unsafe { libc::mallinfo2() };
    if heap.uordblks > 0 || heap.fordblks > 0 {
        return (
            Some((heap.uordblks + heap.fordblks) as u64),
            Some(heap.uordblks as u64),
            Some(heap.fordblks as u64),
            "exact",
        );
    }

    (
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        None,
        "estimated",
    )
}

#[cfg(all(
    target_os = "linux",
    not(target_env = "gnu"),
    not(feature = "allocator-jemalloc")
))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    (
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        sample_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024)),
        None,
        "estimated",
    )
}

#[cfg(all(not(target_os = "linux"), not(feature = "allocator-jemalloc")))]
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

#[cfg(feature = "allocator-jemalloc")]
fn jemalloc_advance_epoch() -> bool {
    use std::ffi::c_void;
    let mut epoch: u64 = 1;
    let mut epoch_len = std::mem::size_of::<u64>();

    unsafe {
        jemalloc_sys::mallctl(
            c"epoch".as_ptr(),
            &mut epoch as *mut _ as *mut c_void,
            &mut epoch_len,
            &mut epoch as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
        ) == 0
    }
}

#[cfg(feature = "allocator-jemalloc")]
fn jemalloc_read_size_stat(name: &[u8]) -> Option<u64> {
    use std::ffi::c_void;
    use std::ptr;

    unsafe {
        let mut value: usize = 0;
        let mut value_len = std::mem::size_of::<usize>();
        if jemalloc_sys::mallctl(
            name.as_ptr() as *const _,
            &mut value as *mut _ as *mut c_void,
            &mut value_len,
            ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        Some(value as u64)
    }
}

#[cfg(feature = "allocator-jemalloc")]
fn ensure_jemalloc_background_thread() -> bool {
    use std::ffi::c_void;

    unsafe {
        let mut enabled = false;
        let mut enabled_len = std::mem::size_of::<bool>();
        if jemalloc_sys::mallctl(
            c"background_thread".as_ptr(),
            &mut enabled as *mut _ as *mut c_void,
            &mut enabled_len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            metrics::record_malloc_trim_error("background_thread_read");
            warn!("failed to read jemalloc background_thread state");
            return false;
        }
        if enabled {
            return true;
        }

        let mut desired = true;
        if jemalloc_sys::mallctl(
            c"background_thread".as_ptr(),
            &mut enabled as *mut _ as *mut c_void,
            &mut enabled_len,
            &mut desired as *mut _ as *mut c_void,
            std::mem::size_of::<bool>(),
        ) != 0
        {
            metrics::record_malloc_trim_error("background_thread_enable");
            warn!("failed to enable jemalloc background_thread");
            return false;
        }

        true
    }
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
    use super::sample_process_memory;

    #[cfg(feature = "allocator-jemalloc")]
    #[test]
    fn sample_process_memory_reports_jemalloc_heap_state() {
        let sample = sample_process_memory();
        assert_eq!(sample.heap_mode, "jemalloc");
        assert!(sample.heap_allocated_bytes.is_some());
        assert!(sample.heap_bytes.is_some());
    }

    #[cfg(all(not(feature = "allocator-jemalloc"), target_os = "linux"))]
    #[test]
    fn sample_process_memory_reports_nonempty_heap_state() {
        let sample = sample_process_memory();
        assert_ne!(sample.heap_mode, "unavailable");
    }
}
