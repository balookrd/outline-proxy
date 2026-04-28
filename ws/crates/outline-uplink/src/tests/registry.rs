use std::time::Duration;

use url::Url;

use super::*;
use crate::config::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
    VlessUdpMuxLimits, WsProbeConfig,
};
use crate::config::{CipherKind, UplinkTransport, WsTransportMode};

fn make_uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://127.0.0.1:1/tcp").unwrap()),
        tcp_ws_mode: WsTransportMode::Http1,
        udp_ws_url: None,
        udp_ws_mode: WsTransportMode::Http1,
        vless_ws_url: None,
        vless_ws_mode: WsTransportMode::Http1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
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
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        },
        load_balancing: LoadBalancingConfig {
            mode: LoadBalancingMode::ActiveActive,
            routing_scope: RoutingScope::PerFlow,
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
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            auto_failback: false,
            vless_udp_mux_limits: VlessUdpMuxLimits::default(),
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
    assert!(
        err.to_string().contains("uplink-b"),
        "error should name the duplicate uplink"
    );
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
