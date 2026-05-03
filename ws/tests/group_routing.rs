//! Integration tests for uplink group isolation and inter-group fallback.
//!
//! These tests verify that:
//! - Groups are fully isolated: failures in one group don't affect another.
//! - The routing table dispatches to the correct group based on CIDR rules.
//! - Fallback kicks in when the primary group has no healthy uplinks.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use outline_routing::{
    RouteRule, RouteTarget, RoutingTable, RoutingTableConfig,
};
use outline_transport::TransportMode;
use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportKind, UplinkConfig,
    UplinkGroupConfig, UplinkRegistry, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;
use url::Url;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(120),
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
    }
}

fn lb() -> LoadBalancingConfig {
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
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        auto_failback: false,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
    }
}

fn make_uplink(name: &str, url: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse(url).unwrap()),
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("{url}/udp")).unwrap()),
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
    }
}

fn two_group_registry() -> UplinkRegistry {
    UplinkRegistry::new(vec![
        UplinkGroupConfig {
            name: "main".to_string(),
            uplinks: vec![
                make_uplink("primary", "wss://main.example.com/tcp"),
                make_uplink("secondary", "wss://main2.example.com/tcp"),
            ],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
        UplinkGroupConfig {
            name: "backup".to_string(),
            uplinks: vec![make_uplink("edge", "wss://backup.example.com/tcp")],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
    ], std::sync::Arc::new(outline_transport::DnsCache::default()))
    .unwrap()
}

fn route_rule(
    prefixes: &[&str],
    target: RouteTarget,
    fallback: Option<RouteTarget>,
) -> RouteRule {
    RouteRule {
        inline_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target,
        fallback,
        invert: false,
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(a, b, c, d), 443)
}

// ── 1. Group isolation ───────────────────────────────────────────────────────

#[tokio::test]
async fn groups_have_independent_health_state() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    // Initially both are un-probed (healthy = None → has_any_healthy = false).
    assert!(!main.has_any_healthy(TransportKind::Tcp).await);
    assert!(!backup.has_any_healthy(TransportKind::Tcp).await);

    // Make "main" group's uplinks healthy.
    main.test_set_tcp_health(0, true, 50).await;
    main.test_set_tcp_health(1, true, 60).await;

    // "main" is now healthy; "backup" remains unknown.
    assert!(main.has_any_healthy(TransportKind::Tcp).await);
    assert!(!backup.has_any_healthy(TransportKind::Tcp).await);

    // Make "backup" healthy — both groups independent.
    backup.test_set_tcp_health(0, true, 40).await;
    assert!(main.has_any_healthy(TransportKind::Tcp).await);
    assert!(backup.has_any_healthy(TransportKind::Tcp).await);

    // Fail all uplinks in "main" — "backup" is unaffected.
    main.test_set_tcp_health(0, false, 0).await;
    main.test_set_tcp_health(1, false, 0).await;
    assert!(!main.has_any_healthy(TransportKind::Tcp).await);
    assert!(backup.has_any_healthy(TransportKind::Tcp).await);
}

#[tokio::test]
async fn runtime_failure_in_one_group_does_not_affect_another() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    // Both healthy initially.
    main.test_set_tcp_health(0, true, 50).await;
    backup.test_set_tcp_health(0, true, 40).await;

    // Report a runtime failure on main's uplink 0 (probe disabled → flips healthy).
    main.report_runtime_failure(
        0,
        TransportKind::Tcp,
        &anyhow::anyhow!("connection reset"),
    )
    .await;

    // main's uplink 0 is now unhealthy.
    assert_eq!(main.test_tcp_healthy(0).await, Some(false));

    // backup's uplink is completely unaffected.
    assert_eq!(backup.test_tcp_healthy(0).await, Some(true));
    assert!(backup.has_any_healthy(TransportKind::Tcp).await);
}

#[tokio::test]
async fn groups_have_independent_sticky_routes() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    main.test_set_tcp_health(0, true, 50).await;
    main.test_set_tcp_health(1, true, 60).await;
    backup.test_set_tcp_health(0, true, 40).await;

    let target = v4(8, 8, 8, 8);

    // Select candidates in each group — creates sticky routes per-manager.
    let main_candidates = main.tcp_candidates(&target).await;
    let backup_candidates = backup.tcp_candidates(&target).await;
    assert!(!main_candidates.is_empty());
    assert!(!backup_candidates.is_empty());

    // The group name on the snapshot is correct.
    let main_snapshot = main.snapshot().await;
    let backup_snapshot = backup.snapshot().await;
    assert_eq!(main_snapshot.group, "main");
    assert_eq!(backup_snapshot.group, "backup");
}

// ── 2. Routing table dispatch ────────────────────────────────────────────────

#[tokio::test]
async fn routing_table_dispatches_to_correct_group() {
    let cfg = RoutingTableConfig {
        rules: vec![
            route_rule(&["10.0.0.0/8"], RouteTarget::Direct, None),
            route_rule(
                &["1.0.0.0/8"],
                RouteTarget::Group("main".into()),
                Some(RouteTarget::Group("backup".into())),
            ),
        ],
        default_target: RouteTarget::Group("backup".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // 10.x.x.x → Direct
    let d = table.resolve(&v4(10, 1, 2, 3)).await;
    assert_eq!(d.primary, RouteTarget::Direct);

    // 1.x.x.x → main, fallback = backup
    let d = table.resolve(&v4(1, 1, 1, 1)).await;
    assert_eq!(d.primary, RouteTarget::Group("main".into()));
    assert_eq!(d.fallback, Some(RouteTarget::Group("backup".into())));

    // Unmatched → backup (default)
    let d = table.resolve(&v4(8, 8, 8, 8)).await;
    assert_eq!(d.primary, RouteTarget::Group("backup".into()));
    assert_eq!(d.fallback, None);
}

#[tokio::test]
async fn routing_table_drop_target_works() {
    let cfg = RoutingTableConfig {
        rules: vec![route_rule(&["192.168.0.0/16"], RouteTarget::Drop, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    assert_eq!(table.resolve(&v4(192, 168, 1, 1)).await.primary, RouteTarget::Drop);
    assert_eq!(
        table.resolve(&v4(8, 8, 8, 8)).await.primary,
        RouteTarget::Group("main".into())
    );
}

// ── 3. Fallback between groups ───────────────────────────────────────────────

#[tokio::test]
async fn fallback_activates_when_primary_group_all_unhealthy() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    // Make main fully unhealthy, backup healthy.
    main.test_set_tcp_health(0, false, 0).await;
    main.test_set_tcp_health(1, false, 0).await;
    backup.test_set_tcp_health(0, true, 40).await;

    // Build routing: default → main, fallback → backup.
    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: Some(RouteTarget::Group("backup".into())),
    };
    let table = Arc::new(RoutingTable::compile(&cfg).await.unwrap());

    let decision = table.resolve(&v4(8, 8, 8, 8)).await;
    assert_eq!(decision.primary, RouteTarget::Group("main".into()));
    assert_eq!(decision.fallback, Some(RouteTarget::Group("backup".into())));

    // Primary is unhealthy → fallback should be used.
    assert!(!main.has_any_healthy(TransportKind::Tcp).await);
    assert!(backup.has_any_healthy(TransportKind::Tcp).await);

    let effective = if let RouteTarget::Group(name) = &decision.primary {
        let mgr = registry.group_by_name(name).unwrap();
        if mgr.has_any_healthy(TransportKind::Tcp).await {
            &decision.primary
        } else {
            decision.fallback.as_ref().unwrap_or(&decision.primary)
        }
    } else {
        &decision.primary
    };
    assert_eq!(*effective, RouteTarget::Group("backup".into()));
}

#[tokio::test]
async fn no_fallback_when_primary_is_healthy() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    main.test_set_tcp_health(0, true, 50).await;
    backup.test_set_tcp_health(0, true, 40).await;

    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: Some(RouteTarget::Group("backup".into())),
    };
    let table = Arc::new(RoutingTable::compile(&cfg).await.unwrap());

    let decision = table.resolve(&v4(8, 8, 8, 8)).await;
    assert!(main.has_any_healthy(TransportKind::Tcp).await);

    let effective = if let RouteTarget::Group(name) = &decision.primary {
        let mgr = registry.group_by_name(name).unwrap();
        if mgr.has_any_healthy(TransportKind::Tcp).await {
            &decision.primary
        } else {
            decision.fallback.as_ref().unwrap_or(&decision.primary)
        }
    } else {
        &decision.primary
    };
    assert_eq!(*effective, RouteTarget::Group("main".into()));
}

#[tokio::test]
async fn fallback_direct_when_primary_group_down() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();

    main.test_set_tcp_health(0, false, 0).await;
    main.test_set_tcp_health(1, false, 0).await;

    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: Some(RouteTarget::Direct),
    };
    let table = Arc::new(RoutingTable::compile(&cfg).await.unwrap());

    let decision = table.resolve(&v4(8, 8, 8, 8)).await;
    assert!(!main.has_any_healthy(TransportKind::Tcp).await);

    let effective = if let RouteTarget::Group(name) = &decision.primary {
        let mgr = registry.group_by_name(name).unwrap();
        if mgr.has_any_healthy(TransportKind::Tcp).await {
            &decision.primary
        } else {
            decision.fallback.as_ref().unwrap_or(&decision.primary)
        }
    } else {
        &decision.primary
    };
    assert_eq!(*effective, RouteTarget::Direct);
}

#[tokio::test]
async fn fallback_drop_when_primary_group_down() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();

    main.test_set_tcp_health(0, false, 0).await;
    main.test_set_tcp_health(1, false, 0).await;

    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: Some(RouteTarget::Drop),
    };
    let table = Arc::new(RoutingTable::compile(&cfg).await.unwrap());

    let decision = table.resolve(&v4(8, 8, 8, 8)).await;
    assert!(!main.has_any_healthy(TransportKind::Tcp).await);

    let effective = if let RouteTarget::Group(name) = &decision.primary {
        let mgr = registry.group_by_name(name).unwrap();
        if mgr.has_any_healthy(TransportKind::Tcp).await {
            &decision.primary
        } else {
            decision.fallback.as_ref().unwrap_or(&decision.primary)
        }
    } else {
        &decision.primary
    };
    assert_eq!(*effective, RouteTarget::Drop);
}

// ── 4. UDP isolation ─────────────────────────────────────────────────────────

#[tokio::test]
async fn udp_health_is_independent_across_groups() {
    let registry = two_group_registry();
    let main = registry.group_by_name("main").unwrap();
    let backup = registry.group_by_name("backup").unwrap();

    main.test_set_udp_health(0, true, 50).await;
    assert!(main.has_any_healthy(TransportKind::Udp).await);
    assert!(!backup.has_any_healthy(TransportKind::Udp).await);

    backup.test_set_udp_health(0, true, 40).await;
    assert!(backup.has_any_healthy(TransportKind::Udp).await);

    // Fail main's UDP — backup unaffected.
    main.test_set_udp_health(0, false, 0).await;
    main.test_set_udp_health(1, false, 0).await;
    assert!(!main.has_any_healthy(TransportKind::Udp).await);
    assert!(backup.has_any_healthy(TransportKind::Udp).await);
}

// ── 5. Registry construction validation ──────────────────────────────────────

#[test]
fn registry_rejects_duplicate_uplink_names_across_groups() {
    let result = UplinkRegistry::new(vec![
        UplinkGroupConfig {
            name: "g1".to_string(),
            uplinks: vec![make_uplink("shared-name", "wss://a.example.com/tcp")],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
        UplinkGroupConfig {
            name: "g2".to_string(),
            uplinks: vec![make_uplink("shared-name", "wss://b.example.com/tcp")],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
    ], std::sync::Arc::new(outline_transport::DnsCache::default()));
    let err = result.unwrap_err();
    assert!(
        format!("{err:#}").contains("shared-name"),
        "error should mention the duplicate name: {err:#}"
    );
}

#[test]
fn registry_rejects_duplicate_group_names() {
    let result = UplinkRegistry::new(vec![
        UplinkGroupConfig {
            name: "same".to_string(),
            uplinks: vec![make_uplink("u1", "wss://a.example.com/tcp")],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
        UplinkGroupConfig {
            name: "same".to_string(),
            uplinks: vec![make_uplink("u2", "wss://b.example.com/tcp")],
            probe: probe_disabled(),
            load_balancing: lb(),
        },
    ], std::sync::Arc::new(outline_transport::DnsCache::default()));
    let err = result.unwrap_err();
    assert!(
        format!("{err:#}").contains("same"),
        "error should mention the duplicate group: {err:#}"
    );
}

// ── 6. Versioned invalidation ────────────────────────────────────────────────

#[tokio::test]
async fn routing_table_version_starts_at_zero() {
    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();
    assert_eq!(table.version(), 0);
}

// ── 7. Inverted rules ────────────────────────────────────────────────────────

fn inverted_rule(
    prefixes: &[&str],
    target: RouteTarget,
    fallback: Option<RouteTarget>,
) -> RouteRule {
    RouteRule {
        inline_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target,
        fallback,
        invert: true,
    }
}

#[tokio::test]
async fn inverted_rule_routes_everything_not_in_set_through_primary() {
    // Policy: "tunnel via `main`, but send 10.0.0.0/8 and 192.168.0.0/16
    // directly." Expressed with an inverted rule: only addresses NOT in
    // the private ranges match the tunnel rule; private ranges fall
    // through to the default (Direct).
    let cfg = RoutingTableConfig {
        rules: vec![inverted_rule(
            &["10.0.0.0/8", "192.168.0.0/16"],
            RouteTarget::Group("main".into()),
            None,
        )],
        default_target: RouteTarget::Direct,
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // Public IP: not in private ranges → inverted rule matches → tunnel.
    assert_eq!(
        table.resolve(&v4(8, 8, 8, 8)).await.primary,
        RouteTarget::Group("main".into())
    );
    // Private IP: in the set → inverted rule does NOT match → default (Direct).
    assert_eq!(
        table.resolve(&v4(10, 1, 2, 3)).await.primary,
        RouteTarget::Direct
    );
    assert_eq!(
        table.resolve(&v4(192, 168, 1, 1)).await.primary,
        RouteTarget::Direct
    );
}

// ── 8. UDP route cache invalidation ──────────────────────────────────────────

/// Mirrors the cache logic in `proxy::udp::resolve_udp_packet_route`:
/// capture the routing-table version BEFORE resolving so a hot-reload that
/// races with resolution invalidates the cached entry on the next lookup.
#[tokio::test]
async fn route_cache_invalidates_after_version_bump() {
    use std::collections::HashMap;

    let cfg = RoutingTableConfig {
        rules: vec![route_rule(&["1.0.0.0/8"], RouteTarget::Direct, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // Cache: TargetAddr → (decision, version).
    let mut cache: HashMap<TargetAddr, (RouteTarget, u64)> = HashMap::new();
    let target = v4(1, 2, 3, 4);

    // First resolve: cache miss → resolve & insert with pre-read version.
    let (decision, version) = table.resolve_versioned(&target).await;
    assert_eq!(decision.primary, RouteTarget::Direct);
    assert_eq!(version, 0);
    cache.insert(target.clone(), (decision.primary.clone(), version));

    // Next lookup with unchanged version: cache hit.
    let current = table.version();
    let hit = cache.get(&target).map(|(_, v)| *v == current).unwrap_or(false);
    assert!(hit, "expected cache hit when version unchanged");

    // Simulate watcher reload: bump version.
    table.version.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

    // Next lookup: cache miss (version mismatch) → re-resolve.
    let current = table.version();
    let hit = cache.get(&target).map(|(_, v)| *v == current).unwrap_or(false);
    assert!(!hit, "cache must invalidate after version bump");

    // Re-resolve and re-cache under the new version.
    let (new_decision, new_version) = table.resolve_versioned(&target).await;
    assert_eq!(new_version, 1);
    cache.insert(target.clone(), (new_decision.primary, new_version));
    let hit_again = cache.get(&target).map(|(_, v)| *v == current).unwrap_or(false);
    assert!(hit_again, "re-resolved entry should be a hit at current version");
}
