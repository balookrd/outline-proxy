//! Downlink backpressure on the *direct* (`via = "direct"`) TUN TCP path.
//!
//! A direct flow has no carrier to throttle it: the reader talks to the origin
//! over a plain socket. Its only push-back is *not reading* — the kernel receive
//! buffer fills, the window we advertise to the origin collapses, and TCP flow
//! control stops the origin at the source. Without that park, a fast origin
//! feeding a slow (or non-ACKing) TUN client grew `pending_server_data` without
//! bound in RAM, which is the regression this test pins.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig};
use outline_uplink::UplinkRegistry;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::config::TunTcpConfig;
use crate::wire::IpVersion;
use crate::{TunRoute, TunRouting};

use super::super::super::state_machine::{TcpFlowStatus, pending_server_bytes};
use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFlowKey};
use super::super::TunTcpEngine;
use super::{TunCapture, build_test_manager};

/// Per-flow downlink soft limit for this test: small enough that the origin runs
/// into it within milliseconds on loopback.
const DOWNLINK_LIMIT: usize = 64 * 1024;
/// Size of one `try_read_buf` in the direct reader. The gate parks *before*
/// reading, so this bounds how far a single read may overshoot the soft limit.
const DIRECT_READ_BUF: usize = 16 * 1024;
/// What the origin tries to push. Two orders of magnitude over the soft limit,
/// so "the origin got through all of it" is unambiguously an unbounded queue.
const ORIGIN_TOTAL: usize = 16 * 1024 * 1024;
/// Client's advertised receive window. The client ACKs the handshake and then
/// goes silent, so the send window stays exhausted for the whole test.
const CLIENT_WINDOW: u16 = 4096;

/// A fast origin behind a direct flow: accepts one connection, pushes
/// [`ORIGIN_TOTAL`] bytes as fast as the socket takes them, and publishes how
/// many bytes it actually handed to the kernel. It never reads, so the only
/// thing that can stop it is TCP flow control from our side — which is exactly
/// what this test measures.
struct BlockedOrigin {
    addr: SocketAddr,
    written: Arc<AtomicUsize>,
    /// Set once the write loop leaves — either the payload went out in full (no
    /// backpressure) or the connection broke (the flow was reset).
    finished: Arc<AtomicBool>,
}

impl BlockedOrigin {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let written = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let task_written = Arc::clone(&written);
        let task_finished = Arc::clone(&finished);

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let payload = vec![b'D'; 64 * 1024];
            let mut sent = 0usize;
            while sent < ORIGIN_TOTAL {
                let take = payload.len().min(ORIGIN_TOTAL - sent);
                // Plain `write` (not `write_all`): a short write still counts,
                // so the published byte count is exact at the moment the origin
                // parks in the kernel's send path.
                match stream.write(&payload[..take]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        sent += n;
                        task_written.store(sent, Ordering::SeqCst);
                    },
                    Err(_) => break,
                }
            }
            task_finished.store(true, Ordering::SeqCst);
        });

        Self { addr, written, finished }
    }
}

/// Routing whose default target is `direct`, so the engine escapes the tunnel
/// over a plain socket to the literal `remote_ip:remote_port` of the flow key —
/// i.e. straight to the [`BlockedOrigin`] listener.
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

/// Poll until the origin stops making progress (parked in `write` because we
/// stopped reading) or gives up entirely. Polling rather than a fixed sleep, so
/// the test neither races a loaded CI box nor pays for a worst-case wait.
async fn wait_until_origin_settles(origin: &BlockedOrigin) {
    let settled = tokio::time::timeout(Duration::from_secs(20), async {
        let mut last = usize::MAX;
        let mut stable_samples = 0;
        loop {
            if origin.finished.load(Ordering::SeqCst) {
                return;
            }
            let written = origin.written.load(Ordering::SeqCst);
            if written > 0 && written == last {
                stable_samples += 1;
                // ~300 ms without a single byte moving: on loopback that is a
                // blocked sender, not a slow one.
                if stable_samples >= 6 {
                    return;
                }
            } else {
                stable_samples = 0;
            }
            last = written;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(settled.is_ok(), "origin neither finished nor stalled within 20s");
}

#[tokio::test]
async fn direct_tun_tcp_flow_backpressures_a_fast_origin() {
    let origin = BlockedOrigin::start().await;
    let (writer, mut capture) = TunCapture::new().await;
    let config = TunTcpConfig {
        max_pending_server_bytes: DOWNLINK_LIMIT,
        // The client here deliberately never ACKs, so its window stays shut for
        // the whole run. Push the stall reapers far past the test window: the
        // only teardown this test may observe is one it is actually about (a
        // backlog abort), never a timeout of the artificial stall.
        backlog_no_progress_abort: Duration::from_secs(60),
        max_retransmits: 1_000,
        ..test_tun_tcp_config()
    };
    let hard_limit = config.max_pending_server_bytes * config.backlog_hard_limit_multiplier;
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
    let client_port = 40100;
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
            CLIENT_WINDOW,
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
            CLIENT_WINDOW,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();

    // From here the client is a healthy-but-slow reader: it never ACKs the
    // downlink, so the send window empties and the queue starts to fill.
    wait_until_origin_settles(&origin).await;

    let written = origin.written.load(Ordering::SeqCst);
    assert!(
        !origin.finished.load(Ordering::SeqCst),
        "origin was never throttled: it drained its whole payload into our queue \
         (or lost the connection) after writing {written} of {ORIGIN_TOTAL} bytes"
    );
    assert!(written > 0, "origin was never dialled: the flow did not take the direct path");
    assert!(
        written < ORIGIN_TOTAL / 2,
        "origin was not pushed back at the source: it wrote {written} of {ORIGIN_TOTAL} bytes"
    );

    let flow = engine
        .inner
        .flows
        .get(&key)
        .map(|entry| Arc::clone(entry.value()))
        .expect("a slow-but-live client must be throttled, not reset");
    let state = flow.lock().await;
    assert_eq!(state.status, TcpFlowStatus::Established);
    assert!(
        matches!(state.routing.route, TunRoute::Direct { .. }),
        "this test only proves anything on the direct path"
    );

    let pending = pending_server_bytes(&state);
    assert!(
        pending <= hard_limit,
        "downlink queue blew past the hard limit: {pending} > {hard_limit} bytes"
    );
    // The gate parks before reading, so the queue can only overshoot the soft
    // limit by the one read that crossed it.
    assert!(
        pending <= DOWNLINK_LIMIT + DIRECT_READ_BUF,
        "downlink queue is not held at the soft limit: {pending} bytes"
    );
    drop(state);

    // A throttled flow is not a dead flow: nothing may have been reset.
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        assert_eq!(
            parsed.flags & TCP_FLAG_RST,
            0,
            "backpressured flow was reset instead of throttled"
        );
    }
}
