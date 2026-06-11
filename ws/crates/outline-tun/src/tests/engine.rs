use std::time::Duration;

use outline_transport::TransportMode;
use outline_uplink::{
    LoadBalancingConfig, ProbeConfig, UplinkConfig, UplinkManager, UplinkTransport, WsProbeConfig,
};
use shadowsocks_crypto::CipherKind;

use super::echo_reply_suppressed_for_down_group;
use crate::routing::TunRouting;
use crate::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};

/// Single-uplink manager (TCP + UDP capable, probes disabled) with the
/// ICMP suppression and bypass flags under test. A freshly-built manager
/// has no probe verdict yet (`healthy = None`), which `has_any_healthy`
/// reports as "no healthy uplink" — the same state a fully-down group is in.
fn icmp_gate_manager(suppress_when_down: bool, bypass_when_down: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![UplinkConfig {
            name: "primary".to_string(),
            transport: UplinkTransport::Ws,
            tcp_ws_url: Some("wss://main.example.com/tcp".parse().unwrap()),
            tcp_mode: TransportMode::WsH1,
            udp_ws_url: Some("wss://main.example.com/udp".parse().unwrap()),
            udp_mode: TransportMode::WsH1,
            vless_ws_url: None,
            vless_xhttp_url: None,
            vless_mode: TransportMode::WsH1,
            tcp_addr: None,
            udp_addr: None,
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
            shuffle_timer: None,
        }],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            skip_when_active: true,
            liveness_interval: Duration::from_secs(300),
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
            tls: None,
        },
        LoadBalancingConfig {
            mode: outline_uplink::LoadBalancingMode::ActiveActive,
            routing_scope: outline_uplink::RoutingScope::PerFlow,
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
            vless_udp_mux_limits: outline_uplink::VlessUdpMuxLimits::default(),
            tcp_mid_session_retry_buffer_bytes: 256 * 1024,
            tcp_mid_session_retry_budget: 1,
            tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
            tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
            tcp_symmetric_replay_enabled: true,
            tcp_symmetric_replay_max_bytes: 1_048_576,
            tun_suppress_icmp_reply_when_down: suppress_when_down,
            bypass_when_down,
        },
    )
    .unwrap()
}

fn ipv4_echo_request_to(destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0u8; IPV4_HEADER_LEN + 8];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 8) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&destination);
    packet[IPV4_HEADER_LEN] = 8;
    packet
}

fn ipv6_echo_request_to(destination: std::net::Ipv6Addr) -> Vec<u8> {
    let mut packet = vec![0u8; IPV6_HEADER_LEN + 8];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER_LEN] = 128;
    packet
}

#[tokio::test]
async fn suppresses_echo_reply_when_opted_in_group_has_no_healthy_uplink() {
    let manager = icmp_gate_manager(true, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    // No probe verdict yet → no healthy uplink → suppressed.
    assert!(echo_reply_suppressed_for_down_group(&routing, &packet).await);

    // Explicitly-down uplinks stay suppressed.
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;
    assert!(echo_reply_suppressed_for_down_group(&routing, &packet).await);

    let v6 = ipv6_echo_request_to(std::net::Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888));
    assert!(echo_reply_suppressed_for_down_group(&routing, &v6).await);
}

#[tokio::test]
async fn replies_while_any_transport_has_a_healthy_uplink() {
    let manager = icmp_gate_manager(true, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    manager.test_set_tcp_health(0, true, 50).await;
    manager.test_set_udp_health(0, false, 0).await;
    assert!(!echo_reply_suppressed_for_down_group(&routing, &packet).await);

    // TCP down but UDP healthy still counts as a live group.
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, true, 50).await;
    assert!(!echo_reply_suppressed_for_down_group(&routing, &packet).await);
}

#[tokio::test]
async fn replies_when_group_did_not_opt_in() {
    let manager = icmp_gate_manager(false, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;

    let packet = ipv4_echo_request_to([8, 8, 8, 8]);
    assert!(!echo_reply_suppressed_for_down_group(&routing, &packet).await);
}

#[tokio::test]
async fn unparseable_destination_never_suppresses() {
    let manager = icmp_gate_manager(true, false);
    let routing = TunRouting::from_single_manager(manager);

    // Too short to carry a destination field — the gate steps aside and
    // leaves validation to the reply builder.
    assert!(!echo_reply_suppressed_for_down_group(&routing, &[0x45u8; 8]).await);
}

/// With `bypass_when_down` the destination of a down group resolves to
/// `TunRoute::Direct`, so the gate never fires: traffic keeps flowing via
/// the bypass, and the echo reply correctly reports a live path instead of
/// signalling a dead tunnel.
#[tokio::test]
async fn replies_when_down_group_bypasses_to_direct() {
    let manager = icmp_gate_manager(true, true);
    let routing = TunRouting::from_single_manager(manager.clone());
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;

    let packet = ipv4_echo_request_to([8, 8, 8, 8]);
    assert!(!echo_reply_suppressed_for_down_group(&routing, &packet).await);
}
