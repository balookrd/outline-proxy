//! The TUN data path must be able to *restore* uplink health, not only tear it
//! down.
//!
//! With no `[probe]` section configured — the shape the generated Android
//! profile ships — `report_active_traffic` is the only thing left that flips
//! `healthy` back to `Some(true)`, and the SOCKS relay used to be its only
//! caller. On the TUN path that made `healthy` a one-way door: a network change
//! (the phone's active SIM switching, say) marks every uplink down through
//! `report_runtime_failure`, and nothing afterwards clears it. The group then
//! reads "no link" forever — while traffic flows perfectly well, because
//! candidate selection never filters on the flag.
//!
//! Downlink bytes are the signal, mirroring `pinned_relay`: data arriving *from*
//! the uplink proves the path delivers. Bytes written *into* the tunnel prove
//! nothing (a degraded server accepts them and then closes the data path), which
//! is why the uplink direction is deliberately not counted here either.

use std::net::Ipv4Addr;
use std::time::Duration;

use outline_uplink::TransportKind;

use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_SYN};
use super::super::TunTcpEngine;
use super::{TestTcpUpstream, TunCapture, build_test_manager};

#[tokio::test]
async fn tun_downlink_traffic_restores_uplink_health_without_probe() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    assert!(
        !manager.probe_config().enabled(),
        "this repro needs the probe-less shape the Android profile ships"
    );
    let health = manager.clone();

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
    let client_port = 40100;
    let remote_port = 80;

    // Open the flow: SYN → SYN/ACK → ACK, then one client chunk so the uplink
    // is dialled and carrying.
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
    let _ = upstream.expect_target().await;

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
            b"ABC",
        ))
        .await
        .unwrap();
    assert_eq!(upstream.recv_chunk().await, b"ABC");

    // The network changes underneath the flow: every in-flight connection dies
    // at once and the data path reports it. With no probe configured this flips
    // the uplink to unhealthy immediately.
    health
        .report_runtime_failure(0, TransportKind::Tcp, &anyhow::anyhow!("network changed"))
        .await;
    assert!(
        health.link_confirmed_down(TransportKind::Tcp).await,
        "the uplink should read as down right after the runtime failure"
    );

    // Connectivity is back and the uplink delivers again: downlink bytes reach
    // the TUN client.
    upstream.send_chunk(b"XYZ").await;
    let downlink = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(downlink.payload, b"XYZ"[..]);

    // Proven delivery has to clear the verdict, otherwise the group is stuck at
    // "no link" for the lifetime of the process.
    assert!(
        !health.link_confirmed_down(TransportKind::Tcp).await,
        "downlink traffic did not restore uplink health: `healthy` is a one-way \
         door on the TUN path, so the tunnel reads as down while it carries data"
    );

    // ...and only the verdict. One flow's downlink says this path still
    // delivers; it does not say fresh dials succeed, so the cooldown the
    // failure stamped has to stand until it expires on its own. Otherwise a
    // single busy flow would keep clearing the evidence that every *new*
    // connection is failing, and selection would never move off the uplink.
    assert!(
        !health.has_any_healthy(TransportKind::Tcp).await,
        "downlink delivery cleared the failure cooldown; one flow's bytes must \
         not vouch for new sessions"
    );
}
