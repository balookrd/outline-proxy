use std::sync::Arc;
use std::time::Duration;

use url::Url;

use outline_transport::TransportMode;
use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
    UplinkGroupConfig, UplinkManager, UplinkRegistry, UplinkTransport, VlessUdpMuxLimits,
    WsProbeConfig,
};

use super::*;
use crate::proxy::config::TcpTimeouts;

fn make_uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse(&format!("wss://{name}.example.com/tcp")).unwrap()),
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://{name}.example.com/udp")).unwrap()),
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: shadowsocks_crypto::CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        shuffle_timer: None,
    }
}

fn make_probe() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(120),
        timeout: Duration::from_secs(10),
        max_concurrent: 4,
        max_dials: 2,
        min_failures: 3,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn make_lb(bypass_when_down: bool) -> LoadBalancingConfig {
    LoadBalancingConfig {
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
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        bypass_when_down,
    }
}

/// Single-uplink manager. A freshly-built manager has no probe verdict yet
/// (`healthy = None`), which `has_any_healthy` reports as "no healthy
/// uplink" — the same state a fully-down group is in.
fn make_manager(group: &str, bypass_when_down: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        group,
        vec![make_uplink(group)],
        make_probe(),
        make_lb(bypass_when_down),
    )
    .unwrap()
}

fn make_group_config(name: &str, bypass_when_down: bool) -> UplinkGroupConfig {
    UplinkGroupConfig {
        name: name.to_string(),
        uplinks: vec![make_uplink(name)],
        probe: make_probe(),
        load_balancing: make_lb(bypass_when_down),
    }
}

fn no_router_config() -> ProxyConfig {
    ProxyConfig {
        socks5_auth: None,
        dns_cache: Arc::new(outline_transport::DnsCache::default()),
        router: None,
        direct_fwmark: None,
        tcp_timeouts: TcpTimeouts::DEFAULT,
    }
}

/// When the routing table references a group name that is not in the
/// registry, `classify_decision` must fall back to the registry's default
/// group rather than panicking or returning an error.  This is consistent
/// with the TCP dispatch path (`resolve_single_target`).
#[tokio::test]
async fn classify_decision_unknown_group_falls_back_to_default() {
    let manager = make_manager("my-default", false);
    let registry = UplinkRegistry::from_single_manager(manager);

    // The routing table resolved to group "nonexistent" which is not in the registry.
    let route = classify_decision(&registry, RouteTarget::Group("nonexistent".into()), None).await;

    // Must fall back to the registry's default group name.
    match route {
        UdpPacketRoute::Tunnel(name) => {
            assert_eq!(&*name, registry.default_group_name(), "must fall back to default group")
        },
        other => panic!("expected Tunnel(default), got {other:?}"),
    }
}

#[tokio::test]
async fn classify_decision_bypass_group_down_resolves_direct() {
    let manager = make_manager("main", true);
    let registry = UplinkRegistry::from_single_manager(manager);

    let route = classify_decision(&registry, RouteTarget::Group("main".into()), None).await;
    assert!(matches!(route, UdpPacketRoute::Direct), "expected Direct, got {route:?}");
}

#[tokio::test]
async fn classify_decision_bypass_group_with_healthy_udp_stays_tunnel() {
    let manager = make_manager("main", true);
    manager.test_set_udp_health(0, true, 50).await;
    let registry = UplinkRegistry::from_single_manager(manager);

    let route = classify_decision(&registry, RouteTarget::Group("main".into()), None).await;
    match route {
        UdpPacketRoute::Tunnel(name) => assert_eq!(&*name, "main"),
        other => panic!("expected Tunnel(main), got {other:?}"),
    }
}

#[tokio::test]
async fn classify_decision_down_group_without_bypass_stays_tunnel() {
    let manager = make_manager("main", false);
    let registry = UplinkRegistry::from_single_manager(manager);

    let route = classify_decision(&registry, RouteTarget::Group("main".into()), None).await;
    match route {
        UdpPacketRoute::Tunnel(name) => assert_eq!(&*name, "main"),
        other => panic!("expected Tunnel(main), got {other:?}"),
    }
}

#[tokio::test]
async fn classify_decision_explicit_fallback_wins_over_bypass() {
    let registry = UplinkRegistry::new_for_test(vec![
        make_group_config("main", true),
        make_group_config("backup", false),
    ])
    .unwrap();
    registry
        .group_by_name("backup")
        .unwrap()
        .test_set_udp_health(0, true, 40)
        .await;

    let route = classify_decision(
        &registry,
        RouteTarget::Group("main".into()),
        Some(RouteTarget::Group("backup".into())),
    )
    .await;
    match route {
        UdpPacketRoute::Tunnel(name) => assert_eq!(&*name, "backup"),
        other => panic!("expected Tunnel(backup), got {other:?}"),
    }
}

/// Without a routing table every datagram lands on the default group;
/// `bypass_when_down` must still divert it to the direct socket while the
/// group is fully down, and hand it back once any uplink recovers.
#[tokio::test]
async fn resolve_udp_packet_route_without_router_honours_bypass() {
    let manager = make_manager("main", true);
    let registry = UplinkRegistry::from_single_manager(manager.clone());
    let config = no_router_config();
    let mut cache = new_udp_route_cache();
    let target = TargetAddr::Domain("example.com".into(), 443);

    let route = resolve_udp_packet_route(&mut cache, &config, &registry, &target).await;
    assert!(matches!(route, UdpPacketRoute::Direct), "expected Direct, got {route:?}");

    manager.test_set_udp_health(0, true, 50).await;
    let route = resolve_udp_packet_route(&mut cache, &config, &registry, &target).await;
    match route {
        UdpPacketRoute::Tunnel(name) => assert_eq!(&*name, "main"),
        other => panic!("expected Tunnel(main), got {other:?}"),
    }
}

/// The per-association direct socket must be pre-allocated whenever a
/// `bypass_when_down` group could divert packets to it — even with no
/// routing table — and stay elided in the plain no-router/no-bypass case.
#[tokio::test]
async fn direct_udp_possible_accounts_for_bypass_groups() {
    let config = no_router_config();

    let plain = UplinkRegistry::from_single_manager(make_manager("main", false));
    assert!(!direct_udp_possible(&config, &plain));

    let bypass = UplinkRegistry::from_single_manager(make_manager("main", true));
    assert!(direct_udp_possible(&config, &bypass));
}
