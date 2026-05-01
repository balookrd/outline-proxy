use super::*;
use crate::snapshot_types::ProcessFdSnapshot;
use crate::snapshot_types::{UplinkManagerSnapshot, UplinkSnapshot};
use parking_lot::{Mutex, MutexGuard};
use std::sync::LazyLock;

static METRICS_TEST_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn test_guard() -> MutexGuard<'static, ()> {
    METRICS_TEST_GUARD.lock()
}

fn empty_snapshot() -> UplinkManagerSnapshot {
    UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_active".to_string(),
        routing_scope: "per_flow".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: Vec::new(),
        sticky_routes: Vec::new(),
        auto_failback: false,
    }
}

fn snapshot_uplink(name: &str) -> UplinkSnapshot {
    UplinkSnapshot {
        index: 0,
        name: name.to_string(),
        group: "main".to_string(),
        transport: "ws".to_string(),
        tcp_mode: Some("ws_h1".to_string()),
        udp_mode: Some("ws_h1".to_string()),
        weight: 1.0,
        tcp_healthy: None,
        udp_healthy: None,
        tcp_latency_ms: None,
        udp_latency_ms: None,
        tcp_rtt_ewma_ms: None,
        udp_rtt_ewma_ms: None,
        tcp_penalty_ms: None,
        udp_penalty_ms: None,
        tcp_effective_latency_ms: None,
        udp_effective_latency_ms: None,
        tcp_score_ms: None,
        udp_score_ms: None,
        cooldown_tcp_ms: None,
        cooldown_udp_ms: None,
        last_checked_ago_ms: None,
        last_error: None,
        standby_tcp_ready: 0,
        standby_udp_ready: 0,
        tcp_consecutive_failures: 0,
        udp_consecutive_failures: 0,
        h3_tcp_downgrade_until_ms: None,
        h3_udp_downgrade_until_ms: None,
        tcp_mode_capped_to: None,
        udp_mode_capped_to: None,
        last_active_tcp_ago_ms: None,
        last_active_udp_ago_ms: None,
    }
}

#[test]
fn render_prometheus_exports_session_histogram() {
    let _guard = test_guard();
    init();
    let session = track_session("tcp");
    session.finish(true);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains("outline_ws_rust_session_duration_seconds_bucket"));
    assert!(rendered.contains("protocol=\"tcp\""));
    assert!(rendered.contains("result=\"success\""));
}

#[test]
fn render_prometheus_exports_process_memory_metrics() {
    let _guard = test_guard();
    init();
    update_process_memory(
        Some(1234),
        Some(4321),
        Some(5678),
        Some(5678),
        Some(256),
        "estimated",
        Some(42),
        Some(9),
        Some(ProcessFdSnapshot {
            total: 42,
            sockets: 20,
            pipes: 10,
            anon_inodes: 5,
            regular_files: 6,
            other: 1,
            socket_states: Some(vec![
                crate::snapshot_types::SocketStateCount {
                    protocol: "tcp",
                    family: "ipv4",
                    state: "established",
                    count: 12,
                },
                crate::snapshot_types::SocketStateCount {
                    protocol: "tcp",
                    family: "ipv4",
                    state: "close_wait",
                    count: 3,
                },
            ]),
        }),
    );

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains("outline_ws_rust_process_resident_memory_bytes 1234"));
    assert!(rendered.contains("outline_ws_rust_process_virtual_memory_bytes 4321"));
    assert!(rendered.contains("outline_ws_rust_process_heap_allocated_bytes 5678"));
    assert!(rendered.contains("outline_ws_rust_process_heap_mode_info{mode=\"estimated\"} 1"));
    assert!(rendered.contains("outline_ws_rust_process_open_fds 42"));
    assert!(rendered.contains("outline_ws_rust_process_threads 9"));
    assert!(rendered.contains("outline_ws_rust_process_fd_by_type{kind=\"socket\"} 20"));
    assert!(rendered.contains("outline_ws_rust_process_fd_by_type{kind=\"pipe\"} 10"));
    assert!(rendered.contains(
        "outline_ws_rust_process_sockets_by_state{family=\"ipv4\",protocol=\"tcp\",state=\"established\"} 12"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_process_sockets_by_state{family=\"ipv4\",protocol=\"tcp\",state=\"close_wait\"} 3"
    ));
}

#[test]
fn render_prometheus_exports_transport_connect_metrics() {
    let _guard = test_guard();
    init();
    add_transport_connects_active("tun_tcp", "h2", 2);
    record_transport_connect("tun_tcp", "h2", "started");
    record_transport_connect("tun_tcp", "h2", "success");
    record_transport_connect("probe_http", "h3", "error");
    record_runtime_failure_suppressed("udp", "main", "primary");
    add_upstream_transports_active("tun_tcp", "tcp", 1);
    record_upstream_transport("tun_tcp", "tcp", "opened");
    record_upstream_transport("tun_tcp", "tcp", "closed");

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(
        rendered
            .contains("outline_ws_rust_transport_connects_active{mode=\"h2\",source=\"tun_tcp\"}")
    );
    assert!(rendered.contains(
        "outline_ws_rust_transport_connects_total{mode=\"h2\",result=\"started\",source=\"tun_tcp\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_transport_connects_total{mode=\"h2\",result=\"success\",source=\"tun_tcp\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_transport_connects_total{mode=\"h3\",result=\"error\",source=\"probe_http\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_uplink_runtime_failures_suppressed_total{group=\"main\",transport=\"udp\",uplink=\"primary\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_upstream_transports_active{protocol=\"tcp\",source=\"tun_tcp\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_upstream_transports_total{protocol=\"tcp\",result=\"opened\",source=\"tun_tcp\"}"
    ));
}

#[test]
fn render_prometheus_exports_traffic_metrics_with_uplink_labels() {
    let _guard = test_guard();
    init();
    add_bytes("tcp", "client_to_upstream", "main", "nuxt", 128);
    add_bytes("udp", "upstream_to_client", "main", "senko", 256);
    add_bytes("tcp", "upstream_to_client", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL, 512);
    add_probe_bytes("main", "primary", "tcp", "http", "outgoing", 64);
    add_probe_bytes("main", "primary", "udp", "dns", "incoming", 96);
    record_probe_wakeup("main", "primary", "udp", "runtime_failure", "sent");
    record_probe_wakeup("main", "primary", "udp", "runtime_failure", "suppressed");
    record_runtime_failure_cause("tcp", "main", "primary", "timeout");
    record_runtime_failure_signature("tcp", "main", "primary", "read_failed");
    record_runtime_failure_other_detail("tcp", "main", "primary", "failed_to_read_chunk");
    add_udp_datagram("client_to_upstream", "main", "nuxt");
    add_udp_datagram("upstream_to_client", "main", "senko");
    add_udp_datagram("upstream_to_client", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL);
    record_dropped_oversized_udp_packet("incoming");

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains(
        "outline_ws_rust_bytes_total{direction=\"client_to_upstream\",group=\"main\",protocol=\"tcp\",uplink=\"nuxt\"} 128"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_bytes_total{direction=\"upstream_to_client\",group=\"main\",protocol=\"udp\",uplink=\"senko\"} 256"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_bytes_total{direction=\"upstream_to_client\",group=\"direct\",protocol=\"tcp\",uplink=\"direct\"} 512"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_probe_bytes_total{direction=\"outgoing\",group=\"main\",probe=\"http\",transport=\"tcp\",uplink=\"primary\"} 64"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_probe_bytes_total{direction=\"incoming\",group=\"main\",probe=\"dns\",transport=\"udp\",uplink=\"primary\"} 96"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_probe_wakeups_total{group=\"main\",reason=\"runtime_failure\",result=\"sent\",transport=\"udp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_probe_wakeups_total{group=\"main\",reason=\"runtime_failure\",result=\"suppressed\",transport=\"udp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_uplink_runtime_failure_causes_total{cause=\"timeout\",group=\"main\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_uplink_runtime_failure_signatures_total{group=\"main\",signature=\"read_failed\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_uplink_runtime_failure_other_details_total{detail=\"failed_to_read_chunk\",group=\"main\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_udp_datagrams_total{direction=\"client_to_upstream\",group=\"main\",uplink=\"nuxt\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_udp_datagrams_total{direction=\"upstream_to_client\",group=\"main\",uplink=\"senko\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_udp_datagrams_total{direction=\"upstream_to_client\",group=\"direct\",uplink=\"direct\"} 1"
    ));
    assert!(
        rendered.contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"incoming\"} 1")
    );
}

#[test]
fn render_prometheus_exports_routing_selection_info() {
    let _guard = test_guard();
    init();

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: Some("senko".to_string()),
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: Vec::new(),
        sticky_routes: Vec::new(),
        auto_failback: false,
    }])
    .expect("render metrics");

    assert!(rendered.contains(
        "outline_ws_rust_selection_mode_info{group=\"main\",mode=\"active_passive\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_routing_scope_info{group=\"main\",scope=\"global\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_global_active_uplink_info{group=\"main\",uplink=\"senko\"} 1"
    ));
}

// Pull DIRECT_GROUP_LABEL into scope via existing glob import.

#[test]
fn render_prometheus_clears_previous_global_active_uplink() {
    let _guard = test_guard();
    init();

    render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: Some("senko".to_string()),
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![snapshot_uplink("senko"), snapshot_uplink("nuxt")],
        sticky_routes: Vec::new(),
        auto_failback: false,
    }])
    .expect("render first metrics");

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: Some("nuxt".to_string()),
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![snapshot_uplink("senko"), snapshot_uplink("nuxt")],
        sticky_routes: Vec::new(),
        auto_failback: false,
    }])
    .expect("render second metrics");

    assert!(rendered.contains(
        "outline_ws_rust_global_active_uplink_info{group=\"main\",uplink=\"senko\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_global_active_uplink_info{group=\"main\",uplink=\"nuxt\"} 1"
    ));
}

#[cfg(feature = "tun")]
#[test]
fn init_exports_zero_value_tun_udp_forward_error_series() {
    let _guard = test_guard();
    init();

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(
        metric_value(
            &rendered,
            "outline_ws_rust_tun_udp_forward_errors_total{reason=\"all_uplinks_failed\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(
            &rendered,
            "outline_ws_rust_tun_udp_forward_errors_total{reason=\"transport_error\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(
            &rendered,
            "outline_ws_rust_tun_udp_forward_errors_total{reason=\"connect_failed\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(&rendered, "outline_ws_rust_tun_udp_forward_errors_total{reason=\"other\"}",)
            .is_some()
    );
    assert!(metric_value(
        &rendered,
        "outline_ws_rust_tun_icmp_local_replies_total{ip_family=\"ipv4\"}",
    )
    .is_some());
    assert!(rendered.contains("outline_ws_rust_tun_icmp_local_replies_total{ip_family=\"ipv6\"}"));
    assert!(rendered.contains("outline_ws_rust_tun_ip_fragments_total{ip_family=\"ipv4\"}"));
    assert!(rendered.contains("outline_ws_rust_tun_ip_fragments_total{ip_family=\"ipv6\"}"));
    assert!(rendered.contains(
        "outline_ws_rust_tun_ip_reassemblies_total{ip_family=\"ipv4\",result=\"success\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_tun_ip_reassemblies_total{ip_family=\"ipv6\",result=\"timeout\"}"
    ));
    assert!(rendered.contains("outline_ws_rust_tun_ip_fragment_sets_active{ip_family=\"ipv4\"}"));
    assert!(rendered.contains("outline_ws_rust_tun_ip_fragment_sets_active{ip_family=\"ipv6\"}"));
}

#[cfg(feature = "tun")]
#[test]
fn render_prometheus_exports_ipv6_fragment_activity_counters() {
    let _guard = test_guard();
    init();

    record_tun_ip_fragment_received("ipv6");
    record_tun_ip_fragment_received("ipv6");
    record_tun_ip_reassembly("ipv6", "success");
    set_tun_ip_fragment_sets_active("ipv6", 1);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    let fragments =
        metric_value(&rendered, "outline_ws_rust_tun_ip_fragments_total{ip_family=\"ipv6\"}")
            .expect("ipv6 fragment counter");
    assert!(fragments >= 2.0);
    let reassemblies = metric_value(
        &rendered,
        "outline_ws_rust_tun_ip_reassemblies_total{ip_family=\"ipv6\",result=\"success\"}",
    )
    .expect("ipv6 reassembly counter");
    assert!(reassemblies >= 1.0);
    assert!(rendered.contains("outline_ws_rust_tun_ip_fragment_sets_active{ip_family=\"ipv6\"}"));
}

#[test]
fn init_exports_zero_value_request_and_session_series() {
    let _guard = test_guard();
    init();

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains("outline_ws_rust_requests_total{command=\"connect\"} 0"));
    assert!(rendered.contains("outline_ws_rust_requests_total{command=\"udp_associate\"} 0"));
    assert!(rendered.contains("outline_ws_rust_requests_total{command=\"udp_in_tcp\"} 0"));
    assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"tcp\"} 0"));
    assert!(rendered.contains("outline_ws_rust_sessions_active{protocol=\"udp\"} 0"));
    assert!(
        rendered.contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"incoming\"} 0")
    );
    assert!(
        rendered.contains("outline_ws_rust_udp_oversized_dropped_total{direction=\"outgoing\"} 0")
    );
    assert!(rendered.contains(
        "outline_ws_rust_bytes_total{direction=\"client_to_upstream\",group=\"direct\",protocol=\"tcp\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_bytes_total{direction=\"upstream_to_client\",group=\"direct\",protocol=\"udp\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_udp_datagrams_total{direction=\"client_to_upstream\",group=\"direct\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_rust_udp_datagrams_total{direction=\"upstream_to_client\",group=\"direct\",uplink=\"direct\"} 0"
    ));
}

#[cfg(feature = "tun")]
fn metric_value(rendered: &str, metric: &str) -> Option<f64> {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(metric)?.trim().parse::<f64>().ok())
}
