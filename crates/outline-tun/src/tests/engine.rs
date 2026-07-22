use std::time::Duration;

use outline_transport::TransportMode;
use outline_uplink::{
    LoadBalancingConfig, ProbeConfig, UplinkConfig, UplinkManager, UplinkTransport, WsProbeConfig,
};
use shadowsocks_crypto::CipherKind;

use super::{echo_reply_suppressed_for_down_group, packet_l4_checksum};
use crate::routing::TunRouting;
use crate::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, L4Checksum};

/// Single-uplink manager (TCP + UDP capable, probes disabled) with the
/// ICMP suppression and bypass flags under test. A freshly-built manager
/// has no probe verdict yet (`healthy = None`), which `has_any_healthy`
/// reports as "no healthy uplink" — the same state a fully-down group is in.
fn icmp_gate_manager(suppress_when_down: bool, bypass_when_down: bool) -> UplinkManager {
    icmp_gate_manager_with_probes(suppress_when_down, bypass_when_down, false)
}

/// As above, but able to turn the probe config on — the freshness half of the
/// gate only applies to a group that actually probes.
fn icmp_gate_manager_with_probes(
    suppress_when_down: bool,
    bypass_when_down: bool,
    probes_enabled: bool,
) -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![UplinkConfig {
            name: "primary".to_string(),
            transport: UplinkTransport::Ss,
            tcp_ws_url: Some("wss://main.example.com/tcp".parse().unwrap()),
            tcp_xhttp_url: None,
            tcp_mode: TransportMode::WsH1,
            udp_ws_url: Some("wss://main.example.com/udp".parse().unwrap()),
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
            endpoint_check: false,
            endpoint_check_timeout: Duration::from_millis(2000),
            ws: WsProbeConfig { enabled: probes_enabled },
            http: None,
            dns: None,
            tcp: None,
            tls: None,
        },
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
            tun_suppress_icmp_reply_when_down: suppress_when_down,
            // None → derived from the probe schedule (interval 30 s,
            // liveness 300 s ⇒ 360 s).
            tun_icmp_liveness_window: None,
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
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_some()
    );

    // Explicitly-down uplinks stay suppressed.
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_some()
    );

    let v6 = ipv6_echo_request_to(std::net::Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888));
    assert!(echo_reply_suppressed_for_down_group(&routing, &v6).await.is_some());
}

#[tokio::test]
async fn replies_while_any_transport_has_a_healthy_uplink() {
    let manager = icmp_gate_manager(true, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    manager.test_set_tcp_health(0, true, 50).await;
    manager.test_set_udp_health(0, false, 0).await;
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );

    // TCP down but UDP healthy still counts as a live group.
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, true, 50).await;
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn replies_when_group_did_not_opt_in() {
    let manager = icmp_gate_manager(false, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;

    let packet = ipv4_echo_request_to([8, 8, 8, 8]);
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn unparseable_destination_never_suppresses() {
    let manager = icmp_gate_manager(true, false);
    let routing = TunRouting::from_single_manager(manager);

    // Too short to carry a destination field — the gate steps aside and
    // leaves validation to the reply builder.
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &[0x45u8; 8])
            .await
            .is_none()
    );
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
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );
}

/// The failure this gate exists for after 2026-07-22: a daemon that still
/// runs its TUN read loop but has stopped doing anything else. `healthy` is
/// sticky, so the group keeps reporting a live uplink off a verdict nobody
/// has revisited, and an unconditional echo reply would tell a router's
/// ping-check that all is well while no traffic moves at all.
#[tokio::test(start_paused = true)]
async fn stale_health_verdict_suppresses_even_though_an_uplink_is_flagged_healthy() {
    let manager = icmp_gate_manager_with_probes(true, false, true);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    manager.test_set_tcp_health(0, true, 50).await;
    manager.test_mark_checked_now(0).await;
    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none(),
        "a freshly stamped verdict answers normally",
    );

    // Probe interval 30 s, liveness 300 s ⇒ derived window 360 s. Nothing
    // updates the status while the clock runs.
    tokio::time::advance(Duration::from_secs(361)).await;

    assert_eq!(
        echo_reply_suppressed_for_down_group(&routing, &packet).await,
        Some(super::EchoSuppression::StaleEvidence),
        "a health flag nobody refreshed must stop answering pings",
    );
}

/// A daemon that has just started has not had time to stamp anything, and
/// `selection_health` can already read healthy through the fallback-bootstrap
/// path — so without a startup grace the freshness rule would silence a
/// perfectly fine node for its first window. cloud3 withheld two echo replies
/// exactly this way right after a restart on 2026-07-22.
#[tokio::test(start_paused = true)]
async fn a_freshly_started_daemon_answers_before_its_first_probe_completes() {
    let manager = icmp_gate_manager_with_probes(true, false, true);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    // Healthy but never probed: no `last_checked`, no `last_active`.
    manager.test_set_tcp_health(0, true, 50).await;

    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none(),
        "a stamp cannot be stale before there was time to take one",
    );
}

/// Real traffic counts as evidence too — an uplink busy enough to skip probe
/// cycles must not be mistaken for a stalled daemon.
#[tokio::test(start_paused = true)]
async fn recent_traffic_keeps_the_reply_alive_without_a_probe_stamp() {
    let manager = icmp_gate_manager_with_probes(true, false, true);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    manager.test_set_tcp_health(0, true, 50).await;
    tokio::time::advance(Duration::from_secs(361)).await;
    manager
        .test_mark_active_now(0, outline_uplink::TransportKind::Tcp)
        .await;

    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );
}

/// Without probes there is no stamp to age, so the freshness half of the gate
/// must step aside entirely — otherwise a probe-less group would go silent
/// forever and strand every ping-check pointed at it.
#[tokio::test(start_paused = true)]
async fn freshness_gate_is_skipped_when_the_group_has_no_probes() {
    let manager = icmp_gate_manager_with_probes(true, false, false);
    let routing = TunRouting::from_single_manager(manager.clone());
    let packet = ipv4_echo_request_to([8, 8, 8, 8]);

    manager.test_set_tcp_health(0, true, 50).await;
    tokio::time::advance(Duration::from_secs(3600)).await;

    assert!(
        echo_reply_suppressed_for_down_group(&routing, &packet)
            .await
            .is_none()
    );
}

/// A reassembled packet carries the *sender's* L4 checksum (it rides in the
/// first fragment, and the read loop's recompute deliberately declines to fold a
/// fragment), so reassembly must always downgrade the provenance — otherwise the
/// parser would skip validating a checksum this process never produced.
#[test]
fn reassembly_downgrades_checksum_provenance_to_unverified() {
    assert_eq!(packet_l4_checksum(L4Checksum::Recomputed, false), L4Checksum::Recomputed);
    assert_eq!(packet_l4_checksum(L4Checksum::Recomputed, true), L4Checksum::Unverified);
    assert_eq!(packet_l4_checksum(L4Checksum::Unverified, false), L4Checksum::Unverified);
    assert_eq!(packet_l4_checksum(L4Checksum::Unverified, true), L4Checksum::Unverified);
}
