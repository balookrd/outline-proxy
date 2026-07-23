use std::time::Duration;

use url::Url;

use super::*;
use crate::config::{CipherKind, FallbackTransport, TransportMode, UplinkTransport};
use crate::config::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
    VlessUdpMuxLimits, WsProbeConfig,
};

fn make_uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://127.0.0.1:1/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// Minimal Shadowsocks-over-WS fallback wire, enough to give an uplink a
/// multi-wire chain for `shuffle_timer` rotation.
fn make_fallback(host: &str) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://{host}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn make_group(name: &str, uplink_names: &[&str]) -> UplinkGroupConfig {
    UplinkGroupConfig {
        name: name.to_string(),
        uplinks: uplink_names.iter().map(|n| make_uplink(n)).collect(),
        probe: ProbeConfig {
            interval: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            max_concurrent: 4,
            max_dials: 2,
            min_failures: 3,
            attempts: 1,
            skip_when_active: true,
            liveness_interval: std::time::Duration::from_secs(300),
            endpoint_check: false,
            endpoint_check_timeout: Duration::from_millis(2000),
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
            tls: None,
        },
        load_balancing: LoadBalancingConfig {
            mode: LoadBalancingMode::ActiveActive,
            routing_scope: RoutingScope::PerFlow,
            shared_resume: false,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.25,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            mode_downgrade_duration: Duration::from_secs(60),
            runtime_failure_window: Duration::from_secs(60),
            chunk0_failure_window: Duration::from_secs(300),
            global_udp_strict_health: false,
            udp_ws_keepalive_interval: None,
            tcp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            warm_probe_keepalive_interval: None,
            auto_failback: false,
            health_weighted_selection: false,
            health_weight_floor: 0.05,
            vless_udp_mux_limits: VlessUdpMuxLimits::default(),
            tcp_mid_session_retry_buffer_bytes: 256 * 1024,
            tcp_mid_session_retry_budget: 1,
            tcp_mid_session_retry_overflow_policy: crate::OverflowPolicy::Soft,
            tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
            tcp_symmetric_replay_enabled: true,
            tcp_symmetric_replay_max_bytes: 1_048_576,
            tun_suppress_icmp_reply_when_down: false,
            tun_icmp_liveness_window: None,
            bypass_when_down: false,
        },
    }
}

// ── validate_uplink_names ─────────────────────────────────────────────────

#[test]
fn validate_rejects_duplicate_uplink_name_across_groups() {
    let groups = vec![
        make_group("g1", &["uplink-a", "uplink-b"]),
        make_group("g2", &["uplink-b", "uplink-c"]), // "uplink-b" is a duplicate
    ];
    let err = validate_uplink_names(&groups).unwrap_err();
    assert!(err.to_string().contains("uplink-b"), "error should name the duplicate uplink");
    assert!(
        err.to_string().contains("g1") && err.to_string().contains("g2"),
        "error should mention both groups"
    );
}

#[test]
fn validate_accepts_unique_uplink_names_across_groups() {
    let groups = vec![
        make_group("g1", &["uplink-a", "uplink-b"]),
        make_group("g2", &["uplink-c", "uplink-d"]),
    ];
    assert!(validate_uplink_names(&groups).is_ok());
}

#[test]
fn validate_accepts_empty_group_list() {
    // An empty list has no uplinks to conflict — validation passes.
    assert!(validate_uplink_names(&[]).is_ok());
}

#[test]
fn validate_rejects_duplicate_within_same_group() {
    let groups = vec![make_group("g1", &["uplink-a", "uplink-a"])];
    assert!(
        validate_uplink_names(&groups).is_err(),
        "duplicate within a single group must be rejected"
    );
}

// ── UplinkRegistry::new ───────────────────────────────────────────────────

#[test]
fn registry_new_rejects_empty_group_list() {
    let err = UplinkRegistry::new_for_test(vec![]).unwrap_err();
    assert!(err.to_string().contains("no uplink groups"));
}

#[tokio::test]
async fn apply_new_groups_swaps_visible_to_existing_clones() {
    let reg = UplinkRegistry::new_for_test(vec![make_group("g1", &["u1"])]).unwrap();
    let clone = reg.clone();
    assert_eq!(clone.default_group_name(), "g1");
    reg.apply_new_groups(
        vec![make_group("g2", &["u2"])],
        Arc::new(outline_transport::DnsCache::default()),
        None,
    )
    .await
    .unwrap();
    // The pre-swap clone observes the new state via the shared ArcSwap.
    assert_eq!(clone.default_group_name(), "g2");
    assert!(clone.group_by_name("g1").is_none());
    assert!(clone.group_by_name("g2").is_some());
}

#[tokio::test]
async fn apply_new_groups_spawns_shuffle_timer_loops_for_new_managers() {
    // A hot-apply must spawn the same set of background loops bootstrap does.
    // The anti-DPI wire rotation (`shuffle_timer`) used to be missing here, so
    // it silently died on the first `/control/apply` and never came back until
    // the process was restarted.
    let reg = UplinkRegistry::new_for_test(vec![make_group("g1", &["u1"])]).unwrap();

    let mut group = make_group("g2", &["u2"]);
    group.uplinks[0].fallbacks =
        vec![make_fallback("fb1.example.com"), make_fallback("fb2.example.com")];
    group.uplinks[0].shuffle_timer = Some(Duration::from_millis(5));

    reg.apply_new_groups(vec![group], Arc::new(outline_transport::DnsCache::default()), None)
        .await
        .unwrap();

    let manager = reg.group_by_name("g2").expect("hot-applied group must be present");
    // The reroll picks uniformly out of a 3-wire chain per transport, so a
    // single tick lands back on `(0, 0)` with probability 1/9 — over the ~400
    // ticks this window allows, staying on the primary wire for both
    // transports means no rotation loop is running at all.
    let rotated = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if manager.active_wire(0, TransportKind::Tcp) != 0
                || manager.active_wire(0, TransportKind::Udp) != 0
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(rotated.is_ok(), "hot-applied manager must run its shuffle_timer rotation loop");
}

#[tokio::test]
async fn shared_connection_gc_loop_survives_apply_new_groups() {
    // The shared-connection sweeper is process-wide, not owned by any group.
    // It used to ride the first group's shutdown watch, so the per-manager
    // shutdown a hot-apply sends to the displaced managers killed it — and
    // nothing respawned it. From then on soft-closed / DNS-rotated H2/H3
    // connections held their FDs open for the rest of the process lifetime.
    let reg = UplinkRegistry::new_for_test(vec![make_group("g1", &["u1"])]).unwrap();
    let gc = reg.spawn_shared_connection_gc_loop();

    reg.apply_new_groups(
        vec![make_group("g2", &["u2"])],
        Arc::new(outline_transport::DnsCache::default()),
        None,
    )
    .await
    .unwrap();

    // Give the task a chance to observe any shutdown signal it is subscribed to.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !gc.is_finished(),
        "the process-wide shared-connection GC loop must outlive a hot-apply"
    );
}

#[tokio::test]
async fn shared_connection_gc_loop_stops_on_registry_shutdown() {
    // Symmetric guard for the fix above: decoupling the sweeper from the
    // per-group shutdown must not make it immortal — a full registry shutdown
    // still has to stop it.
    let reg = UplinkRegistry::new_for_test(vec![make_group("g1", &["u1"])]).unwrap();
    let gc = reg.spawn_shared_connection_gc_loop();

    reg.shutdown();

    tokio::time::timeout(Duration::from_secs(2), gc)
        .await
        .expect("GC loop must exit on registry shutdown")
        .expect("GC loop must not panic");
}
