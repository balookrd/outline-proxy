//! Upstream-dial admission gate (`[tun] max_concurrent_upstream_dials`).
//!
//! A flow burst used to launch one carrier handshake per SYN simultaneously —
//! the super-linear term in the 2026-07-18 1 GiB-host livelock. The gate makes
//! excess connect tasks queue for a semaphore permit before dialling. These
//! tests drive the gate deterministically by holding the only permit from the
//! test itself: no timing games against real dials.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig};
use outline_uplink::UplinkRegistry;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::TunRouting;
use crate::wire::IpVersion;

use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFlowKey};
use super::super::TunTcpEngine;
use super::{TunCapture, build_test_manager};

/// An origin that records whether anyone ever connected to it.
struct WatchedOrigin {
    addr: SocketAddr,
    accepted: Arc<AtomicBool>,
}

impl WatchedOrigin {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicBool::new(false));
        let task_accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            // Accept and hold: connection liveness is all the tests observe.
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                task_accepted.store(true, Ordering::SeqCst);
                held.push(stream);
            }
        });
        Self { addr, accepted }
    }

    async fn wait_for_accept(&self) {
        let accepted = tokio::time::timeout(Duration::from_secs(10), async {
            while !self.accepted.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(accepted.is_ok(), "origin never saw the dial after the permit freed up");
    }

    /// Assert no dial reaches the origin within a grace window (a positive
    /// wait, because "nothing happened" cannot be awaited).
    async fn assert_not_dialled(&self, why: &str) {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!self.accepted.load(Ordering::SeqCst), "{why}");
    }
}

async fn direct_routing() -> TunRouting {
    let manager = build_test_manager("ws://127.0.0.1:1/tcp".parse().unwrap()).await;
    let table = RoutingTable::compile(&RoutingTableConfig {
        rules: Vec::new(),
        default_target: RouteTarget::Direct,
        default_fallback: None,
    })
    .await
    .unwrap();
    TunRouting::new(
        UplinkRegistry::from_single_manager(manager),
        Some(Arc::new(table)),
        None,
        false,
    )
}

fn gated_engine(
    writer: crate::SharedTunWriter,
    routing: TunRouting,
) -> (TunTcpEngine, Arc<Semaphore>) {
    let engine = TunTcpEngine::new(
        writer,
        routing,
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );
    let semaphore = Arc::new(Semaphore::new(1));
    engine.set_dial_admission(Arc::clone(&semaphore));
    (engine, semaphore)
}

fn flow_key(client_port: u16, remote: SocketAddr) -> (Ipv4Addr, Ipv4Addr, TcpFlowKey) {
    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(127, 0, 0, 1);
    let key = TcpFlowKey {
        version: IpVersion::V4,
        client_ip: client_ip.into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port: remote.port(),
    };
    (client_ip, remote_ip, key)
}

#[tokio::test]
async fn queued_dial_waits_for_a_permit_and_proceeds_when_one_frees() {
    let origin = WatchedOrigin::start().await;
    let (writer, mut capture) = TunCapture::new().await;
    let (engine, semaphore) = gated_engine(writer, direct_routing().await);

    // Hold the only permit: every dial must now queue.
    let held = Arc::clone(&semaphore).try_acquire_owned().unwrap();

    let (client_ip, remote_ip, _key) = flow_key(40400, origin.addr);
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            40400,
            origin.addr.port(),
            100,
            0,
            u16::MAX,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    // The local handshake is not gated: the SYN-ACK arrives while the dial
    // queues, so the client can already push (window-bounded) upload data.
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);

    origin
        .assert_not_dialled("the dial must queue while the admission permit is held")
        .await;

    // Free the permit: the queued dial must go through.
    drop(held);
    origin.wait_for_accept().await;
}

#[tokio::test]
async fn flow_closed_while_queued_abandons_the_dial_and_takes_no_permit() {
    let origin = WatchedOrigin::start().await;
    let (writer, mut capture) = TunCapture::new().await;
    let (engine, semaphore) = gated_engine(writer, direct_routing().await);

    let held = Arc::clone(&semaphore).try_acquire_owned().unwrap();

    let (client_ip, remote_ip, key) = flow_key(40401, origin.addr);
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            40401,
            origin.addr.port(),
            100,
            0,
            u16::MAX,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    // The client aborts while the dial is still queued.
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            40401,
            origin.addr.port(),
            101,
            server_next_seq,
            u16::MAX,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while engine.inner.flows.contains_key(&key) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "RST must tear the queued flow down");
    // The teardown removes the flow from the table *before* it fires the close
    // signal the queued task watches. Give that signal a moment to land — if
    // the permit freed inside that micro-window the task would dial and then
    // discard the closed flow, which is safe in production but not what this
    // test is pinning.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Release the test's permit: the abandoned connect task must not consume
    // it, so it returns to the semaphore untouched and no dial ever lands.
    drop(held);
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        while semaphore.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(settled.is_ok(), "the queued task must not take a permit for a dead flow");
    origin
        .assert_not_dialled("a flow torn down while queued must never be dialled")
        .await;
}
