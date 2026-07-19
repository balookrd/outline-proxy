//! Uplink receive-window auto-tuning (`initial_receive_window_bytes`).
//!
//! A new flow used to advertise the full `max_buffered_client_bytes` (2 MiB)
//! from the SYN-ACK — before its upstream even connected — so a burst of new
//! flows could legally buffer `N × 2 MiB` while their dials were still in
//! flight (the 2026-07-18 livelock scale). With auto-tuning the flow starts at
//! the configured initial window and earns the rest only as its bytes actually
//! drain into the upstream. This test pins three properties on the direct
//! path: the SYN-ACK advertises the *initial* window (not the full cap), an
//! upload still gets through in full (the window ramps, it does not wedge),
//! and the capacity reaches the full cap once enough bytes have drained.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig};
use outline_uplink::UplinkRegistry;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::config::TunTcpConfig;
use crate::wire::IpVersion;
use crate::{TunRoute, TunRouting};

use super::super::super::TCP_SERVER_WINDOW_SCALE;
use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFlowKey};
use super::super::TunTcpEngine;
use super::{TunCapture, build_test_manager};

/// The window a brand-new flow starts with in this test.
const INITIAL_WINDOW: usize = 16 * 1024;
/// The full uplink buffer cap the window is allowed to grow to. Kept small so
/// the ramp completes within a modest upload.
const FULL_WINDOW: usize = 256 * 1024;
/// Total upload pushed through the flow — comfortably more than
/// `FULL_WINDOW − INITIAL_WINDOW`, so the capacity provably reaches the cap.
const UPLOAD_TOTAL: usize = FULL_WINDOW;
/// One client segment's payload. Kept under the initial window so the client
/// never sends past what the flow advertised.
const SEGMENT_BYTES: usize = 4 * 1024;
/// Segments sent per burst before waiting for the pump to drain them. A burst
/// never exceeds [`INITIAL_WINDOW`], the smallest window the flow ever has.
const SEGMENTS_PER_BURST: usize = INITIAL_WINDOW / SEGMENT_BYTES;

/// An origin that drains the flow's upload: accepts one connection, reads to
/// EOF, and publishes how many bytes it has received.
struct SinkOrigin {
    addr: SocketAddr,
    received: Arc<AtomicUsize>,
}

impl SinkOrigin {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let task_received = Arc::clone(&received);

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        task_received.fetch_add(n, Ordering::SeqCst);
                    },
                }
            }
        });

        Self { addr, received }
    }

    /// Poll until the origin has received at least `expected` bytes.
    async fn wait_for(&self, expected: usize) {
        let drained = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if self.received.load(Ordering::SeqCst) >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            drained.is_ok(),
            "origin received only {} of the {expected} bytes sent so far",
            self.received.load(Ordering::SeqCst)
        );
    }
}

/// Routing whose default target is `direct`, straight to the [`SinkOrigin`].
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

#[tokio::test]
async fn uplink_window_starts_small_and_grows_as_bytes_drain() {
    let origin = SinkOrigin::start().await;
    let (writer, mut capture) = TunCapture::new().await;
    let config = TunTcpConfig {
        initial_receive_window_bytes: INITIAL_WINDOW,
        max_buffered_client_bytes: FULL_WINDOW,
        ..test_tun_tcp_config()
    };
    let engine = TunTcpEngine::new(
        writer,
        direct_routing().await,
        128,
        Duration::from_secs(60),
        false,
        config,
        Arc::new(outline_transport::DnsCache::default()),
    );

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(127, 0, 0, 1);
    let client_port = 40300;
    let remote_port = origin.addr.port();
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
            u16::MAX,
            TCP_FLAG_SYN,
            &[],
        ))
        .await
        .unwrap();
    let syn_ack = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
    // The whole point: the SYN-ACK advertises the *initial* window, not the
    // full `max_buffered_client_bytes` — a still-dialling flow can only be
    // fed this much.
    assert_eq!(
        usize::from(syn_ack.window_size),
        INITIAL_WINDOW >> TCP_SERVER_WINDOW_SCALE,
        "SYN-ACK must advertise the initial auto-tuning window"
    );
    let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            101,
            server_next_seq,
            u16::MAX,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // Upload in window-respecting bursts: each burst fits the smallest window
    // the flow ever advertises, and the next one starts only after the pump
    // drained the previous into the origin (so nothing is ever sent past the
    // advertised window, even before it has grown).
    let payload = vec![b'U'; SEGMENT_BYTES];
    let mut client_seq: u32 = 101;
    let mut sent_total = 0usize;
    while sent_total < UPLOAD_TOTAL {
        for _ in 0..SEGMENTS_PER_BURST {
            engine
                .handle_packet_unverified(&build_client_packet(
                    client_ip,
                    remote_ip,
                    client_port,
                    remote_port,
                    client_seq,
                    server_next_seq,
                    u16::MAX,
                    TCP_FLAG_ACK,
                    &payload,
                ))
                .await
                .unwrap();
            client_seq = client_seq.wrapping_add(SEGMENT_BYTES as u32);
            sent_total += SEGMENT_BYTES;
        }
        origin.wait_for(sent_total).await;
    }

    assert_eq!(
        origin.received.load(Ordering::SeqCst),
        UPLOAD_TOTAL,
        "the upload must arrive in full — a small initial window may ramp, never wedge"
    );

    // Enough bytes have drained for the capacity to have earned the full cap.
    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|entry| Arc::clone(entry.value()))
        .expect("an uploading flow must still be alive");
    {
        let state = flow.lock().await;
        assert!(
            matches!(state.routing.route, TunRoute::Direct { .. }),
            "this test only proves anything on the direct path"
        );
        assert_eq!(
            state.receive_window_capacity, FULL_WINDOW,
            "the receive window must have grown to the full cap as bytes drained"
        );
    }

    // Auto-tuning throttles by advertising less; it must never reset a flow.
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        assert_eq!(parsed.flags & TCP_FLAG_RST, 0, "auto-tuned flow was reset");
    }
}
