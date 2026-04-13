use super::METRICS;
use crate::memory::{ProcessFdSnapshot, sample_process_memory};
use std::time::Duration;
use tokio::time::sleep;

pub fn init() {
    let _ = METRICS.build_info.with_label_values(&[env!("CARGO_PKG_VERSION")]);
    let _ = METRICS.start_time_seconds.get();
    let initial_sample = sample_process_memory();
    update_process_memory(
        initial_sample.rss_bytes,
        initial_sample.virtual_bytes,
        initial_sample.heap_bytes,
        initial_sample.heap_allocated_bytes,
        initial_sample.heap_free_bytes,
        initial_sample.heap_mode,
        initial_sample.open_fds,
        initial_sample.thread_count,
        initial_sample.fd_snapshot,
    );
    METRICS.bytes_total.reset();
    METRICS.udp_datagrams_total.reset();
    METRICS.udp_oversized_dropped_total.reset();
    METRICS.tun_ip_fragments_total.reset();
    METRICS.tun_ip_reassemblies_total.reset();
    METRICS.tun_ip_fragment_sets_active.reset();
    for kind in ["socket", "pipe", "anon_inode", "regular_file", "other"] {
        METRICS.process_fd_by_type.with_label_values(&[kind]).set(0.0);
    }
    for source in [
        "direct",
        "socks_tcp",
        "socks_udp",
        "tun_udp",
        "tun_tcp",
        "standby_tcp",
        "standby_udp",
        "probe_ws",
        "probe_http",
        "probe_dns",
    ] {
        for mode in ["http1", "h2", "h3"] {
            METRICS
                .transport_connects_active
                .with_label_values(&[source, mode])
                .set(0);
            for result in ["started", "success", "error"] {
                let _ = METRICS
                    .transport_connects_total
                    .with_label_values(&[source, mode, result]);
            }
        }
    }
    for source in ["socks_tcp", "socks_udp", "tun_tcp", "tun_udp", "probe_http", "probe_dns"] {
        for protocol in ["tcp", "udp"] {
            METRICS
                .upstream_transports_active
                .with_label_values(&[source, protocol])
                .set(0);
            for result in ["opened", "closed"] {
                let _ = METRICS
                    .upstream_transports_total
                    .with_label_values(&[source, protocol, result]);
            }
        }
    }
    for command in ["connect", "udp_associate", "udp_in_tcp"] {
        let _ = METRICS.socks_requests_total.with_label_values(&[command]);
    }
    for direction in ["incoming", "outgoing"] {
        let _ = METRICS.udp_oversized_dropped_total.with_label_values(&[direction]);
    }
    for protocol in ["tcp", "udp"] {
        for direction in ["client_to_upstream", "upstream_to_client"] {
            METRICS
                .bytes_total
                .with_label_values(&[protocol, direction, super::BYPASS_UPLINK_LABEL])
                .inc_by(0);
        }
    }
    for direction in ["client_to_upstream", "upstream_to_client"] {
        METRICS
            .udp_datagrams_total
            .with_label_values(&[direction, super::BYPASS_UPLINK_LABEL])
            .inc_by(0);
    }
    for protocol in ["tcp", "udp"] {
        let _ = METRICS.sessions_active.with_label_values(&[protocol]);
        METRICS
            .session_recent_p95_seconds
            .with_label_values(&[protocol])
            .set(0.0);
        METRICS.session_recent_samples.with_label_values(&[protocol]).set(0);
    }
    for mode in ["active_active", "active_passive"] {
        METRICS.selection_mode_info.with_label_values(&[mode]).set(0);
    }
    for scope in ["per_flow", "per_uplink", "global"] {
        METRICS.routing_scope_info.with_label_values(&[scope]).set(0);
    }
    for result in
        ["started", "connected", "cancelled", "failed", "timeout", "discarded_closed_flow"]
    {
        let _ = METRICS.tun_tcp_async_connects_total.with_label_values(&[result]);
    }
    METRICS.tun_tcp_async_connects_active.set(0);
    for reason in ["all_uplinks_failed", "transport_error", "connect_failed", "other"] {
        let _ = METRICS.tun_udp_forward_errors_total.with_label_values(&[reason]);
    }
    for ip_family in ["ipv4", "ipv6"] {
        METRICS
            .tun_icmp_local_replies_total
            .with_label_values(&[ip_family])
            .inc_by(0);
        METRICS
            .tun_ip_fragments_total
            .with_label_values(&[ip_family])
            .inc_by(0);
        METRICS
            .tun_ip_fragment_sets_active
            .with_label_values(&[ip_family])
            .set(0);
        for result in ["success", "timeout", "overlap", "inconsistent", "resource_limit"] {
            METRICS
                .tun_ip_reassemblies_total
                .with_label_values(&[ip_family, result])
                .inc_by(0);
        }
    }
}

pub fn spawn_process_metrics_sampler() {
    tokio::spawn(async move {
        let mut sample_count: u64 = 0;
        loop {
            let sample = sample_process_memory();
            update_process_memory(
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
            if sample_count % 4 == 0 {
                crate::memory::log_process_fd_snapshot();
            }
            sleep(Duration::from_secs(15)).await;
        }
    });
}

pub fn update_process_memory(
    rss_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    heap_bytes: Option<u64>,
    heap_allocated_bytes: Option<u64>,
    heap_free_bytes: Option<u64>,
    heap_mode: &'static str,
    open_fds: Option<u64>,
    thread_count: Option<u64>,
    fd_snapshot: Option<ProcessFdSnapshot>,
) {
    METRICS
        .process_resident_memory_bytes
        .set(rss_bytes.unwrap_or(0) as f64);
    METRICS
        .process_virtual_memory_bytes
        .set(virtual_bytes.unwrap_or(0) as f64);
    METRICS.process_heap_memory_bytes.set(heap_bytes.unwrap_or(0) as f64);
    METRICS
        .process_heap_allocated_bytes
        .set(heap_allocated_bytes.unwrap_or(0) as f64);
    METRICS
        .process_heap_free_bytes
        .set(heap_free_bytes.unwrap_or(0) as f64);
    for mode in ["exact", "estimated", "unavailable"] {
        METRICS
            .process_heap_mode_info
            .with_label_values(&[mode])
            .set(if mode == heap_mode { 1 } else { 0 });
    }
    METRICS.process_open_fds.set(open_fds.unwrap_or(0) as f64);
    METRICS.process_threads.set(thread_count.unwrap_or(0) as f64);
    let snapshot = fd_snapshot.unwrap_or_default();
    METRICS
        .process_fd_by_type
        .with_label_values(&["socket"])
        .set(snapshot.sockets as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["pipe"])
        .set(snapshot.pipes as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["anon_inode"])
        .set(snapshot.anon_inodes as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["regular_file"])
        .set(snapshot.regular_files as f64);
    METRICS
        .process_fd_by_type
        .with_label_values(&["other"])
        .set(snapshot.other as f64);
}
