//! `tun_wire_dial`: a TUN TCP flow must survive a dead primary carrier by
//! falling back to a sibling wire *of the same uplink*, not by giving up on
//! the uplink and jumping to a different one.
//!
//! Two uplinks are configured so a regression that treats "primary wire dead"
//! as "uplink dead" is caught: `nuxt`'s primary points at a closed port and
//! its only fallback is a live Shadowsocks-over-WS endpoint, while `senko`'s
//! primary is live on its own. `nuxt` is declared first, so with no runtime
//! history yet it is tried first — if `connect_tcp_uplink_inner` still only
//! ever dials wire 0, `nuxt` fails outright and the flow lands on `senko`
//! instead; the test would then see `senko`'s upstream receive the target
//! rather than `nuxt`'s fallback.

use std::net::Ipv4Addr;
use std::time::Duration;

use outline_uplink::{
    CipherKind, FallbackTransport, LoadBalancingConfig, TransportMode, UplinkConfig, UplinkManager,
    UplinkTransport,
};
use socks5_proto::TargetAddr;
use url::Url;

use crate::wire::IpVersion;

use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_SYN, TcpFlowKey};
use super::super::TunTcpEngine;
use super::{TestTcpUpstream, TunCapture};

/// A URL nothing listens on: connection refused, deterministically and fast.
/// The same fixture the pre-existing `tun_tcp_flow_limit_uses_activity_eviction_index`
/// test uses for "dead" uplinks.
fn dead_url() -> Url {
    "ws://127.0.0.1:1/tcp".parse().unwrap()
}

fn ss_fallback(url: Url) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url),
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
        password: "Secret0".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn ss_uplink(name: &str, primary_url: Url, fallbacks: Vec<FallbackTransport>) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(primary_url),
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
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks,
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// `nuxt` (dead primary + one live fallback wire) declared before `senko` (a
/// fully healthy sibling uplink), with `tun_wire_dial` on. Everything else
/// mirrors `super::test_probe_config()` / `super::test_load_balancing_config()`
/// so this fixture differs from the rest of the module only in what the test
/// needs: two uplinks and the wire-dial gate.
async fn build_manager_with_dead_primary_wire(
    nuxt_fallback_url: Url,
    senko_primary_url: Url,
) -> UplinkManager {
    build_manager_with_dead_primary_wire_gated(nuxt_fallback_url, senko_primary_url, true).await
}

/// Same fixture as `build_manager_with_dead_primary_wire`, with the gate
/// exposed so the gate-off counterpart test can flip it off.
async fn build_manager_with_dead_primary_wire_gated(
    nuxt_fallback_url: Url,
    senko_primary_url: Url,
    tun_wire_dial: bool,
) -> UplinkManager {
    let nuxt = ss_uplink("nuxt", dead_url(), vec![ss_fallback(nuxt_fallback_url)]);
    let senko = ss_uplink("senko", senko_primary_url, Vec::new());
    UplinkManager::new_for_test(
        "test",
        vec![nuxt, senko],
        super::test_probe_config(),
        LoadBalancingConfig {
            tun_wire_dial,
            ..super::test_load_balancing_config()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn tun_tcp_falls_back_to_a_sibling_wire_before_leaving_the_uplink() {
    let nuxt_fallback = TestTcpUpstream::start().await;
    let senko_primary = TestTcpUpstream::start().await;
    let manager =
        build_manager_with_dead_primary_wire(nuxt_fallback.url(), senko_primary.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40500, 443);
    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            100,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // The handshake target must land on `nuxt`'s fallback wire: the dead
    // primary must not have cost the flow the whole uplink.
    let target = nuxt_fallback.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));

    // `senko` must never have been dialed: a dead carrier on one wire is not
    // a dead uplink, so failover must not have reached past `nuxt`.
    assert!(
        senko_primary.try_target().await.is_none(),
        "a dead primary wire must not fail the whole uplink over to a sibling"
    );

    assert!(engine.inner.flows.contains_key(&key));
}

/// The gate-off half of the fixture above: `tun_wire_dial` is the reason a
/// dead primary carrier costs the flow the whole uplink instead of falling
/// back within it. Same topology, same dead `nuxt` primary — but with the
/// gate off, `dial_over_wires` only ever tries wire 0, so `nuxt` must fail
/// outright and the flow must land on `senko`, never on `nuxt`'s fallback
/// wire. That is the observable difference between gated and ungated; without
/// this test the claim that a gate-off node never touches a fallback wire
/// rested only on the gate-on test still passing.
#[tokio::test]
async fn tun_tcp_gate_off_leaves_the_uplink_instead_of_using_a_sibling_wire() {
    let nuxt_fallback = TestTcpUpstream::start().await;
    let senko_primary = TestTcpUpstream::start().await;
    let manager =
        build_manager_with_dead_primary_wire_gated(nuxt_fallback.url(), senko_primary.url(), false)
            .await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40500, 443);
    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    };

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            100,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // With the gate off the flow must reach `senko` — the *second uplink* —
    // rather than `nuxt`'s fallback wire, because a gate-off node never dials
    // anything but wire 0.
    let target = senko_primary.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));

    assert!(
        nuxt_fallback.try_target().await.is_none(),
        "gate-off must never dial a fallback wire, even on a dead primary"
    );

    assert!(engine.inner.flows.contains_key(&key));
}

/// A wire with no TCP path configured must be *skipped*, not charged as a
/// broken wire — the plane-symmetric twin of
/// `crate::udp::tests::wire_fallback::tun_udp_skips_a_wire_with_no_udp_path_instead_of_dialing_and_failing_it`.
/// Charging it teaches the per-wire liveness weights that a healthy
/// UDP-only wire is failing, and (with `shuffle_wires`) burns a slot of the
/// chain-exhaustion round on a wire that never ran a dial.
///
/// Topology: wire 0 dead, wire 1 UDP-only (no TCP URL at all), wire 2 live.
/// `min_failures = 1` (`super::test_probe_config()`), so every recorded
/// failure on the active wire advances `active_wire` by exactly one — which
/// is what makes the final index a direct readout of how many wires were
/// charged.
#[tokio::test]
async fn tun_tcp_skips_a_wire_with_no_tcp_path_instead_of_charging_it() {
    let live_wire = TestTcpUpstream::start().await;
    let udp_only = FallbackTransport {
        tcp_ws_url: None,
        udp_ws_url: Some("ws://127.0.0.1:1/udp".parse().unwrap()),
        ..ss_fallback(dead_url())
    };
    let nuxt = ss_uplink("nuxt", dead_url(), vec![udp_only, ss_fallback(live_wire.url())]);
    let manager = UplinkManager::new_for_test(
        "test",
        vec![nuxt],
        super::test_probe_config(),
        LoadBalancingConfig {
            tun_wire_dial: true,
            ..super::test_load_balancing_config()
        },
    )
    .unwrap();
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager.clone()),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
    let (client_port, remote_port) = (40600, 443);

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            100,
            0,
            4096,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            4096,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // The flow reached wire 2 — proof the TCP-less wire 1 did not sink the
    // uplink on its way there.
    let target = live_wire.expect_target().await;
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));

    // The load-bearing assertion: exactly one advance (0 -> 1), off wire 0's
    // real dial failure. A second advance (1 -> 2) can only mean wire 1's
    // absent TCP path was recorded as a failure rather than skipped.
    assert_eq!(
        manager.active_wire(0, outline_uplink::TransportKind::Tcp),
        1,
        "wire 1 (no TCP path configured) must not have recorded an outcome",
    );
}
