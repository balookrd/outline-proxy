use std::time::Duration;

use url::Url;

use outline_transport::WsTransportMode;
use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
    UplinkManager, UplinkRegistry, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};

use super::*;

/// When the routing table references a group name that is not in the
/// registry, `classify_decision` must fall back to the registry's default
/// group rather than panicking or returning an error.  This is consistent
/// with the TCP dispatch path (`resolve_single_target`).
#[tokio::test]
async fn classify_decision_unknown_group_falls_back_to_default() {
    let uplink = UplinkConfig {
        name: "default-uplink".to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://127.0.0.1:1/tcp").unwrap()),
        tcp_ws_mode: WsTransportMode::Http1,
        udp_ws_url: None,
        udp_ws_mode: WsTransportMode::Http1,
        vless_ws_url: None,
        vless_ws_mode: WsTransportMode::Http1,
        tcp_addr: None,
        udp_addr: None,
        cipher: shadowsocks_crypto::CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,        };
    let probe = ProbeConfig {
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
    };
    let lb = LoadBalancingConfig {
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
    };

    let manager = UplinkManager::new_for_test("my-default", vec![uplink], probe, lb).unwrap();
    let registry = UplinkRegistry::from_single_manager(manager);

    // The routing table resolved to group "nonexistent" which is not in the registry.
    let route = classify_decision(
        &registry,
        RouteTarget::Group("nonexistent".into()),
        None,
    )
    .await;

    // Must fall back to the registry's default group name.
    match route {
        UdpPacketRoute::Tunnel(name) => {
            assert_eq!(&*name, registry.default_group_name(), "must fall back to default group")
        }
        other => panic!("expected Tunnel(default), got {other:?}"),
    }
}
