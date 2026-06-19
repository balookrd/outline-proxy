use std::net::Ipv4Addr;
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

const FWMARK: u32 = 0x7;

fn uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://{name}.example.com/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://{name}.example.com/udp")).unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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
        padding: None,
        shuffle_timer: None,
    }
}

fn probe_disabled() -> ProbeConfig {
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

fn lb(bypass_when_down: bool) -> LoadBalancingConfig {
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
        health_weighted_selection: false,
        health_weight_floor: 0.05,
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
fn manager(group: &str, bypass_when_down: bool) -> UplinkManager {
    UplinkManager::new_for_test(group, vec![uplink(group)], probe_disabled(), lb(bypass_when_down))
        .unwrap()
}

fn group_config(name: &str, bypass_when_down: bool) -> UplinkGroupConfig {
    UplinkGroupConfig {
        name: name.to_string(),
        uplinks: vec![uplink(name)],
        probe: probe_disabled(),
        load_balancing: lb(bypass_when_down),
    }
}

/// Router-less proxy config (`router: None`) with a direct fwmark, so the
/// bypass fall-through in `resolve_dispatch` is observable.
fn no_router_config() -> ProxyConfig {
    ProxyConfig {
        socks5_auth: None,
        dns_cache: Arc::new(outline_transport::DnsCache::default()),
        router: None,
        direct_fwmark: Some(FWMARK),
        tcp_timeouts: TcpTimeouts::DEFAULT,
        #[cfg(feature = "h3")]
        reverse: None,
    }
}

fn target() -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 443)
}

fn route_kind(route: &Route) -> &'static str {
    match route {
        Route::Direct { .. } => "Direct",
        Route::Drop => "Drop",
        Route::Group { .. } => "Group",
        #[cfg(feature = "h3")]
        Route::Reverse { .. } => "Reverse",
    }
}

// `resolve_reverse_route` is the first-class reverse path: a reverse group
// needs no `[[uplink_group]]`. Live-peer hits are covered end-to-end (smoke +
// in-process e2e, which need a real QUIC peer); here we cover the no-peer
// branches with an empty registry.
#[cfg(feature = "h3")]
#[test]
fn reverse_no_peer_no_uplink_honors_fallback_else_drops() {
    use crate::reverse::ReverseRegistry;
    let mut config = no_router_config();
    config.reverse = Some(ReverseRegistry::new([Arc::from("reverse")], 8));
    // Registry without a same-named "reverse" uplink group.
    let registry = UplinkRegistry::from_single_manager(manager("main", false));

    // Reverse group, no peer, no uplink fallback, no route fallback → Drop
    // (never leaks to the default group).
    assert_eq!(
        route_kind(&resolve_reverse_route(&config, &registry, "reverse", None).expect("reverse")),
        "Drop"
    );
    // With a declared route fallback, honor it.
    let fb = RouteTarget::Direct;
    assert_eq!(
        route_kind(
            &resolve_reverse_route(&config, &registry, "reverse", Some(&fb)).expect("reverse")
        ),
        "Direct"
    );
    // A group that is not a reverse group → None (normal uplink path).
    assert!(resolve_reverse_route(&config, &registry, "other", None).is_none());
}

#[cfg(feature = "h3")]
#[test]
fn reverse_no_peer_with_same_named_uplink_falls_through() {
    use crate::reverse::ReverseRegistry;
    let mut config = no_router_config();
    config.reverse = Some(ReverseRegistry::new([Arc::from("reverse")], 8));
    // A same-named "reverse" uplink group exists → no peer falls through to it
    // (operator's explicit fallback), so resolve_reverse_route yields None.
    let registry = UplinkRegistry::from_single_manager(manager("reverse", false));
    assert!(resolve_reverse_route(&config, &registry, "reverse", None).is_none());
}

#[tokio::test]
async fn no_router_bypass_group_down_dispatches_direct() {
    let registry = UplinkRegistry::from_single_manager(manager("main", true));
    let config = no_router_config();

    match resolve_dispatch(&config, &registry, &target(), TransportKind::Tcp).await {
        Route::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn no_router_bypass_group_healthy_stays_group() {
    let main = manager("main", true);
    main.test_set_tcp_health(0, true, 50).await;
    let registry = UplinkRegistry::from_single_manager(main);
    let config = no_router_config();

    match resolve_dispatch(&config, &registry, &target(), TransportKind::Tcp).await {
        Route::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn no_router_down_group_without_bypass_stays_group() {
    let registry = UplinkRegistry::from_single_manager(manager("main", false));
    let config = no_router_config();

    match resolve_dispatch(&config, &registry, &target(), TransportKind::Tcp).await {
        Route::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn fallback_strategy_bypasses_down_group_to_direct() {
    let registry = UplinkRegistry::from_single_manager(manager("main", true));

    let route = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("main".into()),
        None,
        TransportKind::Tcp,
        |t| t,
    )
    .await;
    assert_eq!(route, RouteTarget::Direct);
}

#[tokio::test]
async fn fallback_strategy_explicit_fallback_wins_over_bypass() {
    let registry = UplinkRegistry::new_for_test(vec![
        group_config("main", true),
        group_config("backup", false),
    ])
    .unwrap();
    registry
        .group_by_name("backup")
        .unwrap()
        .test_set_tcp_health(0, true, 40)
        .await;

    let route = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("main".into()),
        Some(RouteTarget::Group("backup".into())),
        TransportKind::Tcp,
        |t| t,
    )
    .await;
    assert_eq!(route, RouteTarget::Group("backup".into()));
}

/// A declared fallback that lands on a group which is itself fully down and
/// opted into the bypass resolves direct — one level deep, mirroring the
/// TUN-side recursion through `materialize_target`.
#[tokio::test]
async fn fallback_strategy_fallback_group_bypasses_to_direct() {
    let registry = UplinkRegistry::new_for_test(vec![
        group_config("main", false),
        group_config("backup", true),
    ])
    .unwrap();

    let route = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("main".into()),
        Some(RouteTarget::Group("backup".into())),
        TransportKind::Tcp,
        |t| t,
    )
    .await;
    assert_eq!(route, RouteTarget::Direct);
}

/// The unknown-group default substitute is health-checked the same way a
/// declared fallback group is.
#[tokio::test]
async fn fallback_strategy_unknown_group_default_substitute_bypasses() {
    let registry = UplinkRegistry::from_single_manager(manager("main", true));

    let route = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("nonexistent".into()),
        None,
        TransportKind::Tcp,
        |t| t,
    )
    .await;
    assert_eq!(route, RouteTarget::Direct);
}

/// Bypass is per-transport on the SOCKS5 path: a TCP-healthy group keeps
/// tunnelling TCP even while its UDP side is fully down, and vice versa.
#[tokio::test]
async fn fallback_strategy_bypass_is_per_transport() {
    let main = manager("main", true);
    main.test_set_tcp_health(0, true, 50).await;
    let registry = UplinkRegistry::from_single_manager(main);

    let tcp = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("main".into()),
        None,
        TransportKind::Tcp,
        |t| t,
    )
    .await;
    assert_eq!(tcp, RouteTarget::Group("main".into()));

    let udp = apply_fallback_strategy(
        &registry,
        RouteTarget::Group("main".into()),
        None,
        TransportKind::Udp,
        |t| t,
    )
    .await;
    assert_eq!(udp, RouteTarget::Direct);
}
