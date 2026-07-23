use super::*;
use crate::snapshot_types::ProcessFdSnapshot;
use crate::snapshot_types::{UplinkManagerSnapshot, UplinkSnapshot};
use parking_lot::{Mutex, MutexGuard};
use std::sync::LazyLock;

mod counter_cache;
mod transport;

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
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
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
        tcp_health_effective: None,
        udp_health_effective: None,
        tcp_latency_ms: None,
        udp_latency_ms: None,
        tcp_rtt_ewma_ms: None,
        udp_rtt_ewma_ms: None,
        tcp_active_wire_rtt_ewma_ms: None,
        udp_active_wire_rtt_ewma_ms: None,
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
        cert_not_after_unix_ms: None,
        standby_tcp_ready: 0,
        standby_udp_ready: 0,
        tcp_consecutive_failures: 0,
        udp_consecutive_failures: 0,
        tcp_downstream_throttle_count: 0,
        udp_downstream_throttle_count: 0,
        tcp_throttle_ago_ms: None,
        udp_throttle_ago_ms: None,
        h3_tcp_downgrade_until_ms: None,
        h3_udp_downgrade_until_ms: None,
        tcp_mode_capped_to: None,
        udp_mode_capped_to: None,
        tcp_xhttp_submode: None,
        udp_xhttp_submode: None,
        tcp_xhttp_submode_block_remaining_ms: None,
        udp_xhttp_submode_block_remaining_ms: None,
        last_active_tcp_ago_ms: None,
        last_active_udp_ago_ms: None,
        configured_fallbacks: Vec::new(),
        configured_wire_chain: Vec::new(),
        tcp_active_wire: 0,
        udp_active_wire: 0,
        tcp_active_wire_pin_remaining_ms: None,
        udp_active_wire_pin_remaining_ms: None,
        shuffle_wires: false,
        carrier_downgrade: true,
        padding_override: None,
        shuffle_timer_secs: None,
        tcp_wires_failed_in_round: 0,
        udp_wires_failed_in_round: 0,
        fingerprint_profile_strategy: "none".to_string(),
        fingerprint_profile_name: None,
        admin_disabled: false,
    }
}

#[test]
fn render_prometheus_exports_session_histogram() {
    let _guard = test_guard();
    init();
    let session = track_session("tcp");
    session.finish(true);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains("outline_ws_session_duration_seconds_bucket"));
    assert!(rendered.contains("protocol=\"tcp\""));
    assert!(rendered.contains("result=\"success\""));
}

#[test]
fn render_prometheus_exports_cluster_soft_switch_and_resume_metrics() {
    let _guard = test_guard();
    init();
    record_soft_switch("main", "migrated");
    record_soft_switch("main", "redial_failed");
    record_resume_lookup("tcp", "group", "hit");
    record_resume_lookup("udp", "uplink", "miss");

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(
        rendered.contains("outline_ws_soft_switch_total{group=\"main\",outcome=\"migrated\"} 1")
    );
    assert!(
        rendered
            .contains("outline_ws_soft_switch_total{group=\"main\",outcome=\"redial_failed\"} 1")
    );
    // The prometheus text exposition renders label pairs sorted by label name.
    assert!(rendered.contains(
        "outline_ws_resume_lookup_total{result=\"hit\",scope=\"group\",transport=\"tcp\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_resume_lookup_total{result=\"miss\",scope=\"uplink\",transport=\"udp\"} 1"
    ));
}

#[test]
fn render_prometheus_exports_uplink_cert_expiry_gauge() {
    let _guard = test_guard();
    init();

    let mut snapshot = empty_snapshot();
    let mut with_cert = snapshot_uplink("nuxt");
    // 2126-05-09 15:45:52 UTC = 4_934_015_152 s, supplied in milliseconds.
    with_cert.cert_not_after_unix_ms = Some(4_934_015_152_000);
    snapshot.uplinks.push(with_cert);
    // An uplink with no measured certificate (e.g. plain Shadowsocks).
    snapshot.uplinks.push(snapshot_uplink("senko"));

    let rendered = render_prometheus(&[snapshot]).expect("render metrics");

    let line = rendered
        .lines()
        .find(|l| {
            l.starts_with("outline_ws_uplink_cert_expiry_timestamp_seconds{")
                && l.contains("uplink=\"nuxt\"")
        })
        .expect("cert-expiry gauge present for the uplink with a certificate");
    // Exported in seconds, not milliseconds. Parse the value so the assertion
    // is robust to integer-vs-float text formatting of the gauge.
    let value: f64 = line.rsplit(' ').next().unwrap().parse().expect("numeric gauge value");
    assert_eq!(value, 4_934_015_152.0);

    // An uplink with no certificate must not emit the gauge at all.
    assert!(
        !rendered.lines().any(|l| {
            l.starts_with("outline_ws_uplink_cert_expiry_timestamp_seconds")
                && l.contains("uplink=\"senko\"")
        }),
        "uplink without a measured certificate must not emit the cert-expiry gauge"
    );
}

#[test]
fn render_prometheus_exports_group_bypass_active_for_opted_in_groups() {
    let _guard = test_guard();
    init();

    let mut bypassing = empty_snapshot();
    bypassing.group = "edge".to_string();
    bypassing.bypass_when_down = true;
    bypassing.bypass_active_tcp = true;
    bypassing.bypass_active_udp = false;
    // Opt-out group: must not publish the series at all — absence is the
    // "option off" signal the dashboards key on.
    let plain = empty_snapshot();

    let rendered = render_prometheus(&[bypassing, plain]).expect("render metrics");
    assert!(
        rendered.contains("outline_ws_group_bypass_active{group=\"edge\",transport=\"tcp\"} 1")
    );
    assert!(
        rendered.contains("outline_ws_group_bypass_active{group=\"edge\",transport=\"udp\"} 0")
    );
    assert!(
        !rendered.contains("outline_ws_group_bypass_active{group=\"main\""),
        "group without bypass_when_down must not emit the gauge"
    );
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
    assert!(rendered.contains("outline_ws_process_resident_memory_bytes 1234"));
    assert!(rendered.contains("outline_ws_process_virtual_memory_bytes 4321"));
    assert!(rendered.contains("outline_ws_process_heap_allocated_bytes 5678"));
    assert!(rendered.contains("outline_ws_process_heap_mode_info{mode=\"estimated\"} 1"));
    assert!(rendered.contains("outline_ws_process_open_fds 42"));
    assert!(rendered.contains("outline_ws_process_threads 9"));
    assert!(rendered.contains("outline_ws_process_fd_by_type{kind=\"socket\"} 20"));
    assert!(rendered.contains("outline_ws_process_fd_by_type{kind=\"pipe\"} 10"));
    assert!(rendered.contains(
        "outline_ws_process_sockets_by_state{family=\"ipv4\",protocol=\"tcp\",state=\"established\"} 12"
    ));
    assert!(rendered.contains(
        "outline_ws_process_sockets_by_state{family=\"ipv4\",protocol=\"tcp\",state=\"close_wait\"} 3"
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
        rendered.contains("outline_ws_transport_connects_active{mode=\"h2\",source=\"tun_tcp\"}")
    );
    assert!(rendered.contains(
        "outline_ws_transport_connects_total{mode=\"h2\",result=\"started\",source=\"tun_tcp\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_transport_connects_total{mode=\"h2\",result=\"success\",source=\"tun_tcp\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_transport_connects_total{mode=\"h3\",result=\"error\",source=\"probe_http\"}"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_runtime_failures_suppressed_total{group=\"main\",transport=\"udp\",uplink=\"primary\"}"
    ));
    assert!(
        rendered
            .contains("outline_ws_upstream_transports_active{protocol=\"tcp\",source=\"tun_tcp\"}")
    );
    assert!(rendered.contains(
        "outline_ws_upstream_transports_total{protocol=\"tcp\",result=\"opened\",source=\"tun_tcp\"}"
    ));
}

#[test]
fn render_prometheus_exports_traffic_metrics_with_uplink_labels() {
    let _guard = test_guard();
    init();
    add_bytes("tcp", "up", "main", "nuxt", 128);
    add_bytes("udp", "down", "main", "senko", 256);
    add_bytes("tcp", "down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL, 512);
    add_probe_bytes("main", "primary", "tcp", "http", "up", 64);
    add_probe_bytes("main", "primary", "udp", "dns", "down", 96);
    record_probe_wakeup("main", "primary", "udp", "runtime_failure", "sent");
    record_probe_wakeup("main", "primary", "udp", "runtime_failure", "suppressed");
    record_runtime_failure_cause("tcp", "main", "primary", "timeout");
    record_runtime_failure_signature("tcp", "main", "primary", "read_failed");
    record_runtime_failure_other_detail("tcp", "main", "primary", "failed_to_read_chunk");
    add_udp_datagram("up", "main", "nuxt");
    add_udp_datagram("down", "main", "senko");
    add_udp_datagram("down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL);
    record_dropped_oversized_udp_packet("up", "socks_client");
    record_dropped_malformed_udp_packet("parse");

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains(
        "outline_ws_bytes_total{direction=\"up\",group=\"main\",protocol=\"tcp\",uplink=\"nuxt\"} 128"
    ));
    assert!(rendered.contains(
        "outline_ws_bytes_total{direction=\"down\",group=\"main\",protocol=\"udp\",uplink=\"senko\"} 256"
    ));
    assert!(rendered.contains(
        "outline_ws_bytes_total{direction=\"down\",group=\"direct\",protocol=\"tcp\",uplink=\"direct\"} 512"
    ));
    assert!(rendered.contains(
        "outline_ws_probe_bytes_total{direction=\"up\",group=\"main\",probe=\"http\",transport=\"tcp\",uplink=\"primary\"} 64"
    ));
    assert!(rendered.contains(
        "outline_ws_probe_bytes_total{direction=\"down\",group=\"main\",probe=\"dns\",transport=\"udp\",uplink=\"primary\"} 96"
    ));
    assert!(rendered.contains(
        "outline_ws_probe_wakeups_total{group=\"main\",reason=\"runtime_failure\",result=\"sent\",transport=\"udp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_probe_wakeups_total{group=\"main\",reason=\"runtime_failure\",result=\"suppressed\",transport=\"udp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_runtime_failure_causes_total{cause=\"timeout\",group=\"main\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_runtime_failure_signatures_total{group=\"main\",signature=\"read_failed\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_runtime_failure_other_details_total{detail=\"failed_to_read_chunk\",group=\"main\",transport=\"tcp\",uplink=\"primary\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_datagrams_total{direction=\"up\",group=\"main\",uplink=\"nuxt\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_datagrams_total{direction=\"down\",group=\"main\",uplink=\"senko\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_datagrams_total{direction=\"down\",group=\"direct\",uplink=\"direct\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_oversized_dropped_total{cause=\"socks_client\",direction=\"up\"} 1"
    ));
    assert!(rendered.contains("outline_ws_udp_malformed_dropped_total{cause=\"parse\"} 1"));
    assert!(rendered.contains("outline_ws_udp_malformed_dropped_total{cause=\"reassembly\"} 0"));
}

#[test]
fn render_prometheus_exports_uplink_fingerprint_profile_strategy_info() {
    let _guard = test_guard();
    init();

    let mut stable = snapshot_uplink("senko");
    stable.fingerprint_profile_strategy = "per_host_stable".to_string();
    let off = snapshot_uplink("nuxt"); // default = "none"

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![stable, off],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render metrics");

    // Active strategy reports 1, the others 0 — same info-style shape
    // as `selection_mode_info`. The metric is published unconditionally
    // (even for the default `none` strategy) so an absent series is a
    // pipeline bug, not "feature off".
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"per_host_stable\",uplink=\"senko\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"none\",uplink=\"senko\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"random\",uplink=\"senko\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"process_stable\",uplink=\"senko\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"none\",uplink=\"nuxt\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"per_host_stable\",uplink=\"nuxt\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"process_stable\",uplink=\"nuxt\"} 0"
    ));
}

#[test]
fn render_prometheus_publishes_process_stable_strategy_label() {
    // ProcessStable is the recommended default; the gauge must
    // expose a series for it just like the other two strategies
    // so an alert "no uplink is on process_stable" or a panel
    // "how many uplinks rotated to random" can fire / render.
    let _guard = test_guard();
    init();

    let mut process = snapshot_uplink("aeza");
    process.fingerprint_profile_strategy = "process_stable".to_string();

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![process],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render metrics");

    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"process_stable\",uplink=\"aeza\"} 1"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"per_host_stable\",uplink=\"aeza\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"random\",uplink=\"aeza\"} 0"
    ));
}

#[test]
fn render_prometheus_clears_stale_uplink_fingerprint_profile_strategy() {
    // First scrape pins `senko` to per_host_stable. Second scrape
    // flips the override to `none`. The previous `strategy=per_host_stable`
    // gauge MUST flip back to 0; otherwise an operator looking at the
    // dashboard would see "stable" forever after a single transient
    // override.
    let _guard = test_guard();
    init();

    let mut stable = snapshot_uplink("senko");
    stable.fingerprint_profile_strategy = "per_host_stable".to_string();
    render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![stable],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render first metrics");

    let off = snapshot_uplink("senko"); // default = "none"
    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![off],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render second metrics");

    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"per_host_stable\",uplink=\"senko\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_fingerprint_profile_strategy_info{group=\"main\",strategy=\"none\",uplink=\"senko\"} 1"
    ));
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
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render metrics");

    assert!(
        rendered
            .contains("outline_ws_selection_mode_info{group=\"main\",mode=\"active_passive\"} 1")
    );
    assert!(rendered.contains("outline_ws_routing_scope_info{group=\"main\",scope=\"global\"} 1"));
    assert!(
        rendered
            .contains("outline_ws_global_active_uplink_info{group=\"main\",uplink=\"senko\"} 1")
    );
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
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
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
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render second metrics");

    assert!(
        rendered
            .contains("outline_ws_global_active_uplink_info{group=\"main\",uplink=\"senko\"} 0")
    );
    assert!(
        rendered.contains("outline_ws_global_active_uplink_info{group=\"main\",uplink=\"nuxt\"} 1")
    );
}

#[test]
fn render_prometheus_exports_mode_downgrade_state() {
    let _guard = test_guard();
    init();

    let mut uplink = snapshot_uplink("nuxt");
    uplink.h3_tcp_downgrade_until_ms = Some(45_000);
    uplink.tcp_mode_capped_to = Some("xhttp_h2".to_string());

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![uplink],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render metrics");

    assert!(
        rendered.contains(
            "outline_ws_uplink_mode_downgrade_remaining_seconds{group=\"main\",transport=\"tcp\",uplink=\"nuxt\"}",
        ),
        "remaining_seconds gauge missing in:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ws_uplink_mode_downgrade_capped_to_info{group=\"main\",mode=\"xhttp_h2\",transport=\"tcp\",uplink=\"nuxt\"} 1",
        ),
        "active cap label not set to 1 in:\n{rendered}"
    );
    // Spot-check that two unrelated mode labels are emitted at 0 — without
    // a stable zero-fill the dashboard cannot tell "no cap" apart from "scrape
    // missed".
    assert!(
        rendered.contains(
            "outline_ws_uplink_mode_downgrade_capped_to_info{group=\"main\",mode=\"ws_h3\",transport=\"tcp\",uplink=\"nuxt\"} 0",
        ),
        "non-active cap label not zeroed in:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ws_uplink_mode_downgrade_capped_to_info{group=\"main\",mode=\"quic\",transport=\"tcp\",uplink=\"nuxt\"} 0",
        ),
        "non-active cap label not zeroed in:\n{rendered}"
    );
}

#[test]
fn render_prometheus_clears_previous_mode_downgrade_window() {
    let _guard = test_guard();
    init();

    let mut downgraded = snapshot_uplink("nuxt");
    downgraded.h3_tcp_downgrade_until_ms = Some(30_000);
    downgraded.tcp_mode_capped_to = Some("xhttp_h2".to_string());

    render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![downgraded],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render first metrics");

    let rendered = render_prometheus(&[UplinkManagerSnapshot {
        group: "main".to_string(),
        generated_at_unix_ms: 0,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "global".to_string(),
        global_active_uplink: None,
        global_active_reason: None,
        tcp_active_uplink: None,
        tcp_active_reason: None,
        udp_active_uplink: None,
        udp_active_reason: None,
        uplinks: vec![snapshot_uplink("nuxt")],
        sticky_routes: Vec::new(),
        sticky_routes_total: 0,
        sticky_routes_by_uplink: Vec::new(),
        auto_failback: false,
        shared_resume: false,
        bypass_when_down: false,
        bypass_active_tcp: false,
        bypass_active_udp: false,
    }])
    .expect("render second metrics");

    assert!(
        !rendered.contains("outline_ws_uplink_mode_downgrade_remaining_seconds{"),
        "remaining_seconds series should be cleared after window expires:\n{rendered}"
    );
    assert!(
        !rendered.contains("outline_ws_uplink_mode_downgrade_capped_to_info{"),
        "capped_to_info series should be cleared after window expires:\n{rendered}"
    );
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
            "outline_ws_tun_udp_forward_errors_total{reason=\"all_uplinks_failed\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(
            &rendered,
            "outline_ws_tun_udp_forward_errors_total{reason=\"transport_error\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(
            &rendered,
            "outline_ws_tun_udp_forward_errors_total{reason=\"connect_failed\"}",
        )
        .is_some()
    );
    assert!(
        metric_value(&rendered, "outline_ws_tun_udp_forward_errors_total{reason=\"other\"}",)
            .is_some()
    );
    assert!(
        metric_value(&rendered, "outline_ws_tun_icmp_local_replies_total{ip_family=\"ipv4\"}",)
            .is_some()
    );
    assert!(rendered.contains("outline_ws_tun_icmp_local_replies_total{ip_family=\"ipv6\"}"));
    assert!(rendered.contains("outline_ws_tun_ip_fragments_total{ip_family=\"ipv4\"}"));
    assert!(rendered.contains("outline_ws_tun_ip_fragments_total{ip_family=\"ipv6\"}"));
    assert!(
        rendered.contains(
            "outline_ws_tun_ip_reassemblies_total{ip_family=\"ipv4\",result=\"success\"}"
        )
    );
    assert!(
        rendered.contains(
            "outline_ws_tun_ip_reassemblies_total{ip_family=\"ipv6\",result=\"timeout\"}"
        )
    );
    assert!(rendered.contains("outline_ws_tun_ip_fragment_sets_active{ip_family=\"ipv4\"}"));
    assert!(rendered.contains("outline_ws_tun_ip_fragment_sets_active{ip_family=\"ipv6\"}"));
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
        metric_value(&rendered, "outline_ws_tun_ip_fragments_total{ip_family=\"ipv6\"}")
            .expect("ipv6 fragment counter");
    assert!(fragments >= 2.0);
    let reassemblies = metric_value(
        &rendered,
        "outline_ws_tun_ip_reassemblies_total{ip_family=\"ipv6\",result=\"success\"}",
    )
    .expect("ipv6 reassembly counter");
    assert!(reassemblies >= 1.0);
    assert!(rendered.contains("outline_ws_tun_ip_fragment_sets_active{ip_family=\"ipv6\"}"));
}

#[test]
fn init_exports_zero_value_request_and_session_series() {
    let _guard = test_guard();
    init();

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains("outline_ws_requests_total{command=\"connect\"} 0"));
    assert!(rendered.contains("outline_ws_requests_total{command=\"udp_associate\"} 0"));
    assert!(rendered.contains("outline_ws_requests_total{command=\"udp_in_tcp\"} 0"));
    assert!(rendered.contains("outline_ws_sessions_active{protocol=\"tcp\"} 0"));
    assert!(rendered.contains("outline_ws_sessions_active{protocol=\"udp\"} 0"));
    assert!(rendered.contains(
        "outline_ws_udp_oversized_dropped_total{cause=\"socks_in_tcp\",direction=\"down\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_bytes_total{direction=\"up\",group=\"direct\",protocol=\"tcp\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_bytes_total{direction=\"down\",group=\"direct\",protocol=\"udp\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_datagrams_total{direction=\"up\",group=\"direct\",uplink=\"direct\"} 0"
    ));
    assert!(rendered.contains(
        "outline_ws_udp_datagrams_total{direction=\"down\",group=\"direct\",uplink=\"direct\"} 0"
    ));
}

#[cfg(feature = "tun")]
fn metric_value(rendered: &str, metric: &str) -> Option<f64> {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(metric)?.trim().parse::<f64>().ok())
}

// ── Per-uplink open-connection / leak-detection metrics ─────────────────

#[test]
fn uplink_open_connections_gauge_round_trips() {
    let _guard = test_guard();
    init();

    add_uplink_open_connections("main", "tcp", "primary", 3);
    add_uplink_open_connections("main", "tcp", "primary", -1);
    add_uplink_open_connections("main", "udp", "secondary", 2);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(
        rendered.contains(
            "outline_ws_uplink_open_connections{group=\"main\",transport=\"tcp\",uplink=\"primary\"} 2",
        ),
        "tcp gauge missing or wrong in:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ws_uplink_open_connections{group=\"main\",transport=\"udp\",uplink=\"secondary\"} 2",
        ),
        "udp gauge missing or wrong in:\n{rendered}"
    );
}

#[test]
fn uplink_close_classification_active_vs_inactive_vs_unknown() {
    let _guard = test_guard();
    init();
    crate::active_uplink::reset_for_tests();

    // Group running in `Global` scope with `senko` currently active.
    set_global_active_uplink("g1", Some("senko"));
    assert_eq!(
        current_active_uplink("g1", "tcp").as_deref(),
        Some("senko"),
        "global active should win for both transports"
    );

    record_uplink_connection_close("g1", "tcp", "senko", "active");
    record_uplink_connection_close("g1", "tcp", "nuxt", "inactive");

    // Group running in `PerUplink` scope (no global) with split TCP/UDP.
    set_per_uplink_active_uplink("g2", "tcp", Some("alpha"));
    set_per_uplink_active_uplink("g2", "udp", Some("beta"));
    assert_eq!(current_active_uplink("g2", "tcp").as_deref(), Some("alpha"));
    assert_eq!(current_active_uplink("g2", "udp").as_deref(), Some("beta"));
    record_uplink_connection_close("g2", "udp", "beta", "active");
    record_uplink_connection_close("g2", "udp", "alpha", "inactive");

    // Group running in `PerFlow` (no active publication at all): the binding
    // resolves to `None` and the close lands in the `unknown` bucket.
    assert!(current_active_uplink("g3", "tcp").is_none());
    record_uplink_connection_close("g3", "tcp", "edge", "unknown");

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(rendered.contains(
        "outline_ws_uplink_connection_close_total{classification=\"active\",group=\"g1\",transport=\"tcp\",uplink=\"senko\"} 1"
    ), "active close missing in:\n{rendered}");
    assert!(rendered.contains(
        "outline_ws_uplink_connection_close_total{classification=\"inactive\",group=\"g1\",transport=\"tcp\",uplink=\"nuxt\"} 1"
    ), "inactive close missing in:\n{rendered}");
    assert!(rendered.contains(
        "outline_ws_uplink_connection_close_total{classification=\"active\",group=\"g2\",transport=\"udp\",uplink=\"beta\"} 1"
    ), "per-uplink active close missing in:\n{rendered}");
    assert!(rendered.contains(
        "outline_ws_uplink_connection_close_total{classification=\"inactive\",group=\"g2\",transport=\"udp\",uplink=\"alpha\"} 1"
    ), "per-uplink inactive close missing in:\n{rendered}");
    assert!(rendered.contains(
        "outline_ws_uplink_connection_close_total{classification=\"unknown\",group=\"g3\",transport=\"tcp\",uplink=\"edge\"} 1"
    ), "per-flow unknown close missing in:\n{rendered}");
}

#[cfg(feature = "tun")]
#[test]
fn tun_tcp_flow_gauges_emit_same_series_as_per_call_helpers() {
    let _guard = test_guard();
    init();

    // Pre-resolved per-flow handles must land on exactly the same
    // `(group, uplink)` series the per-call `add_tun_tcp_*` helpers would,
    // including the value accumulated across repeated `.add()` calls.
    let handles = tun_tcp_flow_gauges("fg_grp", "fg_up");
    handles.flows_active.add(1);
    handles.inflight_bytes.add(4096);
    handles.inflight_bytes.add(-96); // net 4000
    handles.smoothed_rtt_seconds.add(0.25);

    // A failover to a second uplink resolves a distinct handle set → distinct
    // series, exactly like re-calling the per-call path with a new label.
    let after_failover = tun_tcp_flow_gauges("fg_grp", "fg_up2");
    after_failover.inflight_bytes.add(128);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    assert!(
        rendered.contains("outline_ws_tun_tcp_flows_active{group=\"fg_grp\",uplink=\"fg_up\"} 1"),
        "flows_active series missing:\n{rendered}"
    );
    assert!(
        rendered
            .contains("outline_ws_tun_tcp_inflight_bytes{group=\"fg_grp\",uplink=\"fg_up\"} 4000"),
        "inflight_bytes net value wrong:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ws_tun_tcp_smoothed_rtt_seconds{group=\"fg_grp\",uplink=\"fg_up\"} 0.25"
        ),
        "smoothed_rtt gauge missing:\n{rendered}"
    );
    assert!(
        rendered
            .contains("outline_ws_tun_tcp_inflight_bytes{group=\"fg_grp\",uplink=\"fg_up2\"} 128"),
        "post-failover uplink series missing:\n{rendered}"
    );
}

#[cfg(feature = "tun")]
#[test]
fn tun_tcp_bbr_handles_emit_gauges_and_a_monotonic_loss_counter() {
    // Reads absolute counter values, so it must hold the guard: `init()` resets
    // counter vecs, wiping every series — unique labels do not protect it.
    let _guard = test_guard();
    init();

    let handles = tun_tcp_flow_gauges("bbr_grp", "bbr_up");
    handles.bbr_btlbw_bytes_per_second.add(10_000_000);
    handles.bbr_pacing_rate_bytes_per_second.add(8_500_000);
    handles.bbr_loss_cap_bytes_per_second.add(8_500_000);
    handles.bbr_loss_capped_flows.add(1);
    handles.bbr_min_rtt_seconds.add(0.02);
    handles.bbr_loss_episodes_total.inc_by(2);
    handles.bbr_loss_episodes_total.inc_by(1);

    // A flow closing unwinds its gauge contributions; the counter never rewinds.
    handles.bbr_loss_cap_bytes_per_second.add(-8_500_000);
    handles.bbr_loss_capped_flows.add(-1);

    let rendered = render_prometheus(&[empty_snapshot()]).expect("render metrics");
    for expected in [
        "outline_ws_tun_tcp_bbr_btlbw_bytes_per_second{group=\"bbr_grp\",uplink=\"bbr_up\"} 10000000",
        "outline_ws_tun_tcp_bbr_pacing_rate_bytes_per_second{group=\"bbr_grp\",uplink=\"bbr_up\"} 8500000",
        "outline_ws_tun_tcp_bbr_loss_cap_bytes_per_second{group=\"bbr_grp\",uplink=\"bbr_up\"} 0",
        "outline_ws_tun_tcp_bbr_loss_capped_flows{group=\"bbr_grp\",uplink=\"bbr_up\"} 0",
        "outline_ws_tun_tcp_bbr_min_rtt_seconds{group=\"bbr_grp\",uplink=\"bbr_up\"} 0.02",
        "outline_ws_tun_tcp_bbr_loss_episodes_total{group=\"bbr_grp\",uplink=\"bbr_up\"} 3",
    ] {
        assert!(rendered.contains(expected), "missing `{expected}` in:\n{rendered}");
    }
}
