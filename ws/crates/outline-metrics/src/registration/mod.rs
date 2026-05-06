use super::Metrics;
use prometheus::Registry;

mod core;
mod macros;
mod probe;
mod process;
mod transport;
#[cfg(feature = "tun")]
mod tun;
pub(super) mod uplink;

impl Metrics {
    pub(super) fn new() -> Self {
        let registry = Registry::new();
        let c = core::build(&registry);
        let u = uplink::build(&registry);
        let p = probe::build(&registry);
        let proc = process::build(&registry);
        let t = transport::build(&registry);
        #[cfg(feature = "tun")]
        let tun = tun::build(&registry);

        Self {
            registry,
            build_info: c.build_info,
            start_time_seconds: c.start_time_seconds,
            socks_requests_total: c.socks_requests_total,
            sessions_active: c.sessions_active,
            session_duration_seconds: c.session_duration_seconds,
            bytes_total: c.bytes_total,
            udp_datagrams_total: c.udp_datagrams_total,
            udp_oversized_dropped_total: c.udp_oversized_dropped_total,
            uplink_selected_total: u.uplink_selected_total,
            uplink_runtime_failures_total: u.uplink_runtime_failures_total,
            uplink_runtime_failures_suppressed_total: u.uplink_runtime_failures_suppressed_total,
            uplink_runtime_failure_causes_total: u.uplink_runtime_failure_causes_total,
            uplink_runtime_failure_signatures_total: u.uplink_runtime_failure_signatures_total,
            uplink_runtime_failure_other_details_total: u
                .uplink_runtime_failure_other_details_total,
            uplink_failovers_total: u.uplink_failovers_total,
            uplink_health: u.uplink_health,
            uplink_latency_seconds: u.uplink_latency_seconds,
            uplink_rtt_ewma_seconds: u.uplink_rtt_ewma_seconds,
            uplink_penalty_seconds: u.uplink_penalty_seconds,
            uplink_effective_latency_seconds: u.uplink_effective_latency_seconds,
            uplink_score_seconds: u.uplink_score_seconds,
            uplink_weight: u.uplink_weight,
            uplink_cooldown_seconds: u.uplink_cooldown_seconds,
            uplink_standby_ready: u.uplink_standby_ready,
            uplink_active_wire_index: u.uplink_active_wire_index,
            uplink_active_wire_pin_remaining_seconds: u.uplink_active_wire_pin_remaining_seconds,
            uplink_configured_fallbacks_count: u.uplink_configured_fallbacks_count,
            selection_mode_info: u.selection_mode_info,
            routing_scope_info: u.routing_scope_info,
            global_active_uplink_info: u.global_active_uplink_info,
            per_uplink_active_uplink_info: u.per_uplink_active_uplink_info,
            sticky_routes_total: u.sticky_routes_total,
            sticky_routes_by_uplink: u.sticky_routes_by_uplink,
            probe_runs_total: p.probe_runs_total,
            probe_duration_seconds: p.probe_duration_seconds,
            probe_bytes_total: p.probe_bytes_total,
            probe_wakeups_total: p.probe_wakeups_total,
            warm_standby_acquire_total: p.warm_standby_acquire_total,
            warm_standby_refill_total: p.warm_standby_refill_total,
            process_resident_memory_bytes: proc.process_resident_memory_bytes,
            process_virtual_memory_bytes: proc.process_virtual_memory_bytes,
            process_heap_allocated_bytes: proc.process_heap_allocated_bytes,
            process_heap_mode_info: proc.process_heap_mode_info,
            process_open_fds: proc.process_open_fds,
            process_threads: proc.process_threads,
            process_fd_by_type: proc.process_fd_by_type,
            process_sockets_by_state: proc.process_sockets_by_state,
            transport_connects_total: t.transport_connects_total,
            transport_connects_active: t.transport_connects_active,
            upstream_transports_total: t.upstream_transports_total,
            upstream_transports_active: t.upstream_transports_active,
            metrics_http_requests_total: t.metrics_http_requests_total,
            #[cfg(feature = "tun")]
            tun_packets_total: tun.tun_packets_total,
            #[cfg(feature = "tun")]
            tun_flows_total: tun.tun_flows_total,
            #[cfg(feature = "tun")]
            tun_flow_duration_seconds: tun.tun_flow_duration_seconds,
            #[cfg(feature = "tun")]
            tun_flows_active: tun.tun_flows_active,
            #[cfg(feature = "tun")]
            tun_icmp_local_replies_total: tun.tun_icmp_local_replies_total,
            #[cfg(feature = "tun")]
            tun_udp_forward_errors_total: tun.tun_udp_forward_errors_total,
            #[cfg(feature = "tun")]
            tun_ip_fragments_total: tun.tun_ip_fragments_total,
            #[cfg(feature = "tun")]
            tun_ip_reassemblies_total: tun.tun_ip_reassemblies_total,
            #[cfg(feature = "tun")]
            tun_ip_fragment_sets_active: tun.tun_ip_fragment_sets_active,
            #[cfg(feature = "tun")]
            tun_max_flows: tun.tun_max_flows,
            #[cfg(feature = "tun")]
            tun_idle_timeout_seconds: tun.tun_idle_timeout_seconds,
            #[cfg(feature = "tun")]
            tun_tcp_events_total: tun.tun_tcp_events_total,
            #[cfg(feature = "tun")]
            tun_tcp_async_connects_total: tun.tun_tcp_async_connects_total,
            #[cfg(feature = "tun")]
            tun_tcp_async_connects_active: tun.tun_tcp_async_connects_active,
            #[cfg(feature = "tun")]
            tun_tcp_flows_active: tun.tun_tcp_flows_active,
            #[cfg(feature = "tun")]
            tun_tcp_inflight_segments: tun.tun_tcp_inflight_segments,
            #[cfg(feature = "tun")]
            tun_tcp_inflight_bytes: tun.tun_tcp_inflight_bytes,
            #[cfg(feature = "tun")]
            tun_tcp_pending_server_bytes: tun.tun_tcp_pending_server_bytes,
            #[cfg(feature = "tun")]
            tun_tcp_buffered_client_segments: tun.tun_tcp_buffered_client_segments,
            #[cfg(feature = "tun")]
            tun_tcp_zero_window_flows: tun.tun_tcp_zero_window_flows,
            #[cfg(feature = "tun")]
            tun_tcp_backlog_pressure_flows: tun.tun_tcp_backlog_pressure_flows,
            #[cfg(feature = "tun")]
            tun_tcp_backlog_pressure_seconds: tun.tun_tcp_backlog_pressure_seconds,
            #[cfg(feature = "tun")]
            tun_tcp_ack_progress_stall_flows: tun.tun_tcp_ack_progress_stall_flows,
            #[cfg(feature = "tun")]
            tun_tcp_ack_progress_stall_seconds: tun.tun_tcp_ack_progress_stall_seconds,
            #[cfg(feature = "tun")]
            tun_tcp_congestion_window_bytes: tun.tun_tcp_congestion_window_bytes,
            #[cfg(feature = "tun")]
            tun_tcp_slow_start_threshold_bytes: tun.tun_tcp_slow_start_threshold_bytes,
            #[cfg(feature = "tun")]
            tun_tcp_retransmission_timeout_seconds: tun.tun_tcp_retransmission_timeout_seconds,
            #[cfg(feature = "tun")]
            tun_tcp_smoothed_rtt_seconds: tun.tun_tcp_smoothed_rtt_seconds,
        }
    }
}
