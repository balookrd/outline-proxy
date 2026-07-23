use super::*;
use crate::proxy::udp::tests::{make_group_config, make_manager, no_router_config};

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
