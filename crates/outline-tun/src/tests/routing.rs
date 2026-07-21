use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use outline_routing::{RouteRule, RouteTarget, RoutingTable, RoutingTableConfig};
use outline_transport::TransportMode;
use outline_uplink::{
    LoadBalancingConfig, ProbeConfig, TransportKind, UplinkConfig, UplinkGroupConfig,
    UplinkManager, UplinkRegistry, UplinkTransport, WsProbeConfig,
};
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;

use super::{TunRoute, TunRouting};

const FWMARK: u32 = 0x77;

fn uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(format!("wss://{name}.example.com/tcp").parse().unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(format!("wss://{name}.example.com/udp").parse().unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
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
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn lb(bypass_when_down: bool) -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: outline_uplink::LoadBalancingMode::ActiveActive,
        routing_scope: outline_uplink::RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
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
        vless_udp_mux_limits: outline_uplink::VlessUdpMuxLimits::default(),
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

async fn table(default: RouteTarget, fallback: Option<RouteTarget>) -> Arc<RoutingTable> {
    Arc::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: vec![],
            default_target: default,
            default_fallback: fallback,
        })
        .await
        .unwrap(),
    )
}

fn target() -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 443)
}

#[tokio::test]
async fn no_table_bypass_group_down_resolves_direct() {
    let manager = manager("main", true);
    let registry = UplinkRegistry::from_single_manager(manager);
    let routing = TunRouting::new(registry, None, Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn no_table_bypass_group_healthy_stays_group() {
    let manager = manager("main", true);
    manager.test_set_tcp_health(0, true, 50).await;
    let registry = UplinkRegistry::from_single_manager(manager);
    let routing = TunRouting::new(registry, None, Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn no_table_down_group_without_bypass_stays_group() {
    let manager = manager("main", false);
    let registry = UplinkRegistry::from_single_manager(manager);
    let routing = TunRouting::new(registry, None, Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn table_bypass_group_down_resolves_direct() {
    let registry = UplinkRegistry::new_for_test(vec![group_config("main", true)]).unwrap();
    let table = table(RouteTarget::Group("main".into()), None).await;
    let routing = TunRouting::new(registry, Some(table), Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

/// Routing over a single `main` group (opted into the bypass) whose TCP side
/// is healthy and whose UDP side has no probe verdict yet — the state
/// `has_any_healthy` reports as "no healthy uplink".
async fn tcp_healthy_routing() -> TunRouting {
    let registry = UplinkRegistry::new_for_test(vec![group_config("main", true)]).unwrap();
    registry
        .group_by_name("main")
        .unwrap()
        .test_set_tcp_health(0, true, 50)
        .await;
    let table = table(RouteTarget::Group("main".into()), None).await;
    TunRouting::new(registry, Some(table), Some(FWMARK), false)
}

/// The bypass criterion is scoped to the flow's own transport: a group whose
/// TCP side is healthy keeps carrying TCP flows.
#[tokio::test]
async fn table_tcp_healthy_group_carries_tcp_flow() {
    let routing = tcp_healthy_routing().await;

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

/// ...and the same group bypasses UDP flows, which its dead UDP side cannot
/// carry. A healthy TCP side must not pin UDP traffic to the tunnel — this is
/// the SOCKS5 dispatch rule (`apply_fallback_strategy` scopes the health walk
/// to the requested transport), now applied on the TUN path too.
#[tokio::test]
async fn table_tcp_healthy_group_bypasses_udp_flow() {
    let routing = tcp_healthy_routing().await;

    match routing.resolve(&target(), TransportKind::Udp).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

/// ICMP echo has no transport of its own, so it keeps the both-transports
/// criterion: a group with a healthy TCP side is not down, and the echo path
/// must not see it bypassed just because UDP is dead.
#[tokio::test]
async fn any_transport_scope_holds_partially_healthy_group() {
    let routing = tcp_healthy_routing().await;

    match routing.resolve_any_transport(&target()).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

/// A fully-down group is bypassed under the any-transport scope as well.
#[tokio::test]
async fn any_transport_scope_bypasses_fully_down_group() {
    let registry = UplinkRegistry::new_for_test(vec![group_config("main", true)]).unwrap();
    let table = table(RouteTarget::Group("main".into()), None).await;
    let routing = TunRouting::new(registry, Some(table), Some(FWMARK), false);

    match routing.resolve_any_transport(&target()).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn explicit_route_fallback_wins_over_bypass() {
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
    let table =
        table(RouteTarget::Group("main".into()), Some(RouteTarget::Group("backup".into()))).await;
    let routing = TunRouting::new(registry, Some(table), Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "backup"),
        other => panic!("expected Group(backup), got {}", route_kind(&other)),
    }
}

/// A declared fallback group that is itself fully down and opted into the
/// bypass re-evaluates `bypass_when_down` on recursion — the flow escapes
/// direct rather than parking on a dead fallback group.
#[tokio::test]
async fn fallback_group_with_bypass_down_resolves_direct() {
    let registry = UplinkRegistry::new_for_test(vec![
        group_config("main", false),
        group_config("backup", true),
    ])
    .unwrap();
    let table =
        table(RouteTarget::Group("main".into()), Some(RouteTarget::Group("backup".into()))).await;
    let routing = TunRouting::new(registry, Some(table), Some(FWMARK), false);

    match routing.resolve(&target(), TransportKind::Tcp).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

fn route_kind(route: &TunRoute) -> &'static str {
    match route {
        TunRoute::Group { .. } => "Group",
        TunRoute::Direct { .. } => "Direct",
        TunRoute::Drop { .. } => "Drop",
    }
}

// ── SNI-based UDP routing (`resolve_udp_sni`, two-pass domain-then-IP) ────────

fn domain_rule(domains: &[&str], target: RouteTarget) -> RouteRule {
    RouteRule {
        inline_prefixes: Vec::new(),
        files: Vec::new(),
        inline_domains: domains.iter().map(|s| s.to_string()).collect(),
        domain_files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target,
        fallback: None,
        invert: false,
    }
}

/// Table exercising both passes: two domain rules (Direct / Group), a CIDR
/// rule (Drop for 10/8), and a Group default.
async fn sni_table() -> Arc<RoutingTable> {
    let cidr_drop = RouteRule {
        inline_prefixes: vec!["10.0.0.0/8".into()],
        files: Vec::new(),
        inline_domains: Vec::new(),
        domain_files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target: RouteTarget::Drop,
        fallback: None,
        invert: false,
    };
    Arc::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: vec![
                domain_rule(&["bypass.example"], RouteTarget::Direct),
                domain_rule(&["tunnel.example"], RouteTarget::Group("main".into())),
                cidr_drop,
            ],
            default_target: RouteTarget::Group("main".into()),
            default_fallback: None,
        })
        .await
        .unwrap(),
    )
}

fn ip_in_10() -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(10, 1, 2, 3), 443)
}

async fn sni_routing(ipsec_bypass: bool) -> TunRouting {
    let registry = UplinkRegistry::new_for_test(vec![group_config("main", false)]).unwrap();
    TunRouting::new(registry, Some(sni_table().await), Some(FWMARK), ipsec_bypass)
}

#[tokio::test]
async fn sni_domain_rule_steers_route_over_ip() {
    let routing = sni_routing(false).await;
    // SNI `bypass.example` → Direct, even though the literal IP (10/8) alone
    // would Drop. The domain pass wins.
    match routing.resolve_udp_sni(Some("api.bypass.example"), &ip_in_10()).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn sni_domain_rule_selects_group() {
    let routing = sni_routing(false).await;
    match routing.resolve_udp_sni(Some("tunnel.example"), &target()).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn sni_miss_falls_through_to_ip_rule() {
    let routing = sni_routing(false).await;
    // SNI matches no domain rule; the IP (10/8) does → Drop.
    match routing.resolve_udp_sni(Some("nomatch.example"), &ip_in_10()).await {
        TunRoute::Drop { .. } => {},
        other => panic!("expected Drop, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn sni_miss_and_ip_miss_uses_default_group() {
    let routing = sni_routing(false).await;
    // Neither the SNI nor the IP (8.8.8.8) match a rule → table default.
    match routing.resolve_udp_sni(Some("nomatch.example"), &target()).await {
        TunRoute::Group { name, .. } => assert_eq!(&*name, "main"),
        other => panic!("expected Group, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn no_sni_routes_by_ip_only() {
    let routing = sni_routing(false).await;
    // No SNI key → IP-only pass, identical to `resolve_udp`: 10/8 → Drop.
    match routing.resolve_udp_sni(None, &ip_in_10()).await {
        TunRoute::Drop { .. } => {},
        other => panic!("expected Drop, got {}", route_kind(&other)),
    }
}

#[tokio::test]
async fn ipsec_bypass_short_circuits_before_sni() {
    let routing = sni_routing(true).await;
    // A UDP/4500 (IKE NAT-T) datagram is Direct regardless of the SNI rule.
    let ike = TargetAddr::IpV4(Ipv4Addr::new(1, 1, 1, 1), 4500);
    match routing.resolve_udp_sni(Some("tunnel.example"), &ike).await {
        TunRoute::Direct { fwmark } => assert_eq!(fwmark, Some(FWMARK)),
        other => panic!("expected Direct, got {}", route_kind(&other)),
    }
}
