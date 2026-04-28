#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::info;

// Snapshot data types live in the `outline-metrics` crate (they cross the
// producer/consumer boundary between the sampler here and the prometheus
// renderer); re-exported so existing `crate::memory::Process*` imports keep
// working.
pub use outline_metrics::{ProcessFdSnapshot, ProcessMemorySnapshot, SocketStateCount};

pub fn sample_process_memory() -> ProcessMemorySnapshot {
    let fd_snapshot = sample_process_fd_snapshot();
    let open_fds = fd_snapshot.as_ref().map(|snapshot| snapshot.total);
    let (heap_bytes, heap_allocated_bytes, heap_free_bytes, heap_mode) =
        sample_process_heap_state();
    let snapshot = ProcessMemorySnapshot {
        rss_bytes: sample_process_rss_bytes(),
        virtual_bytes: sample_process_virtual_bytes(),
        heap_bytes,
        heap_allocated_bytes,
        heap_free_bytes,
        heap_mode,
        open_fds,
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
            if let Some(states) = snapshot.socket_states.as_ref() {
                let mut tcp_close_wait = 0u64;
                let mut tcp_fin_wait2 = 0u64;
                let mut tcp_time_wait = 0u64;
                let mut tcp_established = 0u64;
                for entry in states {
                    if entry.protocol == "tcp" {
                        match entry.state {
                            "close_wait" => tcp_close_wait += entry.count,
                            "fin_wait2" => tcp_fin_wait2 += entry.count,
                            "time_wait" => tcp_time_wait += entry.count,
                            "established" => tcp_established += entry.count,
                            _ => {},
                        }
                    }
                }
                info!(
                    tcp_established,
                    tcp_close_wait, tcp_fin_wait2, tcp_time_wait, "process socket-state snapshot"
                );
            }
        } else {
            debug!("process fd snapshot unavailable");
        }
    }
}

#[cfg(target_os = "linux")]
fn sample_process_rss_bytes() -> Option<u64> {
    read_proc_statm_resident_bytes()
        .or_else(|| read_proc_status_kib("VmRSS").map(|value_kib| value_kib.saturating_mul(1024)))
}

#[cfg(not(target_os = "linux"))]
fn sample_process_rss_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    let estimated_heap_bytes =
        read_proc_status_kib("VmData").map(|value_kib| value_kib.saturating_mul(1024));
    (estimated_heap_bytes, estimated_heap_bytes, None, "estimated")
}

#[cfg(not(target_os = "linux"))]
fn sample_process_heap_state() -> (Option<u64>, Option<u64>, Option<u64>, &'static str) {
    (None, None, None, "unavailable")
}

#[cfg(target_os = "linux")]
fn sample_process_virtual_bytes() -> Option<u64> {
    read_proc_statm_virtual_bytes().or_else(|| {
        read_proc_status_kib("VmSize").map(|value_kib| value_kib.saturating_mul(1024))
    })
}

#[cfg(not(target_os = "linux"))]
fn sample_process_virtual_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn read_proc_status_kib(field: &str) -> Option<u64> {
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
fn read_proc_statm_resident_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = page_size_bytes()?;
    Some(resident_pages.saturating_mul(page_size))
}

#[cfg(target_os = "linux")]
fn read_proc_statm_virtual_bytes() -> Option<u64> {
    let statm = fs::read_to_string("/proc/self/statm").ok()?;
    let total_pages = statm.split_whitespace().next()?.parse::<u64>().ok()?;
    let page_size = page_size_bytes()?;
    Some(total_pages.saturating_mul(page_size))
}

#[cfg(target_os = "linux")]
fn sample_process_fd_snapshot() -> Option<ProcessFdSnapshot> {
    let mut snapshot = ProcessFdSnapshot::default();
    let mut socket_inodes: HashSet<u64> = HashSet::new();
    let entries = fs::read_dir("/proc/self/fd").ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        snapshot.total = snapshot.total.saturating_add(1);
        let target = fs::read_link(entry.path()).ok();
        match target.as_ref().and_then(|path| path.to_str()) {
            Some(value) if value.starts_with("socket:") => {
                snapshot.sockets = snapshot.sockets.saturating_add(1);
                if let Some(inode) = parse_inode_from_link(value, "socket:") {
                    socket_inodes.insert(inode);
                }
            },
            Some(value) if value.starts_with("pipe:") => {
                snapshot.pipes = snapshot.pipes.saturating_add(1);
            },
            Some(value) if value.starts_with("anon_inode:") => {
                snapshot.anon_inodes = snapshot.anon_inodes.saturating_add(1);
            },
            Some(value)
                if value.starts_with('/')
                    || value.starts_with("./")
                    || value.starts_with("../") =>
            {
                snapshot.regular_files = snapshot.regular_files.saturating_add(1);
            },
            _ => {
                snapshot.other = snapshot.other.saturating_add(1);
            },
        }
    }
    snapshot.socket_states = Some(sample_socket_states(&socket_inodes));
    Some(snapshot)
}

/// Parses `socket:[12345]` (or `pipe:[…]`) into the inode number.
#[cfg(target_os = "linux")]
fn parse_inode_from_link(value: &str, prefix: &str) -> Option<u64> {
    let rest = value.strip_prefix(prefix)?;
    let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn sample_socket_states(owned_inodes: &HashSet<u64>) -> Vec<SocketStateCount> {
    use std::collections::BTreeMap;

    // Map (protocol, family, state) -> count, for our own sockets only.
    let mut counts: BTreeMap<(&'static str, &'static str, &'static str), u64> = BTreeMap::new();
    let sources = [
        ("tcp", "ipv4", "/proc/self/net/tcp"),
        ("tcp", "ipv6", "/proc/self/net/tcp6"),
        ("udp", "ipv4", "/proc/self/net/udp"),
        ("udp", "ipv6", "/proc/self/net/udp6"),
    ];

    for (protocol, family, path) in sources {
        let Ok(content) = fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let Some((state_hex, inode)) = parse_proc_net_line(line) else { continue };
            if !owned_inodes.contains(&inode) {
                continue;
            }
            let state_name = match protocol {
                "tcp" => tcp_state_str(state_hex),
                "udp" => udp_state_str(state_hex),
                _ => "unknown",
            };
            *counts.entry((protocol, family, state_name)).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .map(|((protocol, family, state), count)| SocketStateCount {
            protocol,
            family,
            state,
            count,
        })
        .collect()
}

/// Extract `(state_hex, inode)` from a `/proc/net/{tcp,udp}*` data line.
///
/// Format: `sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode …`
/// — that's `st` at index 3 and `inode` at index 9.
#[cfg(target_os = "linux")]
fn parse_proc_net_line(line: &str) -> Option<(u8, u64)> {
    let mut it = line.split_ascii_whitespace();
    let _sl = it.next()?;
    let _local = it.next()?;
    let _remote = it.next()?;
    let st = it.next()?;
    let _tx_rx = it.next()?;
    let _tr_tm = it.next()?;
    let _retrnsmt = it.next()?;
    let _uid = it.next()?;
    let _timeout = it.next()?;
    let inode = it.next()?;
    let state_hex = u8::from_str_radix(st, 16).ok()?;
    let inode = inode.parse::<u64>().ok()?;
    Some((state_hex, inode))
}

#[cfg(target_os = "linux")]
fn tcp_state_str(state: u8) -> &'static str {
    // From include/net/tcp_states.h
    match state {
        0x01 => "established",
        0x02 => "syn_sent",
        0x03 => "syn_recv",
        0x04 => "fin_wait1",
        0x05 => "fin_wait2",
        0x06 => "time_wait",
        0x07 => "close",
        0x08 => "close_wait",
        0x09 => "last_ack",
        0x0A => "listen",
        0x0B => "closing",
        0x0C => "new_syn_recv",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn udp_state_str(state: u8) -> &'static str {
    // UDP only really uses TCP_ESTABLISHED (connected) and TCP_CLOSE (unbound/unconnected).
    match state {
        0x01 => "connected",
        0x07 => "unconnected",
        _ => "unknown",
    }
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
#[path = "tests/memory.rs"]
mod tests;
