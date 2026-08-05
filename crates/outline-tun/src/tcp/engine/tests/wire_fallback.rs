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
    let nuxt = ss_uplink("nuxt", dead_url(), vec![ss_fallback(nuxt_fallback_url)]);
    let senko = ss_uplink("senko", senko_primary_url, Vec::new());
    UplinkManager::new_for_test(
        "test",
        vec![nuxt, senko],
        super::test_probe_config(),
        LoadBalancingConfig {
            tun_wire_dial: true,
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
