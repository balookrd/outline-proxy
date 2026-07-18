//! Engine-wide pending-downlink budget (`pending_server_budget_bytes`).
//!
//! The per-flow soft limit bounds one download, but N concurrent bulk
//! downloads legally hold `N ×` that — the 2026-07-18 incident: a burst of
//! ~141 CDN flows on a 1 GiB host outran kernel reclaim and livelocked the
//! box. The global budget parks *every* upstream reader once the engine-wide
//! pending sum crosses it, with no abort escalation, releasing them as client
//! ACKs drain the queues. This test pins three properties on the direct path:
//! the origin is throttled by the *budget* (well under the per-flow limit),
//! the engine-wide counter tracks the flow's queue, and tearing the flow down
//! returns its share to the counter.

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

/// Engine-wide budget for this test: small enough that the origin runs into it
/// within milliseconds on loopback, and far under the per-flow soft limit so
/// the *global* gate is unambiguously what parked the reader.
const BUDGET: usize = 48 * 1024;
/// Per-flow soft limit — deliberately far above [`BUDGET`] so the per-flow arm
/// of the gate never engages in this test.
const PER_FLOW_LIMIT: usize = 1024 * 1024;
/// Size of one `try_read_buf` in the direct reader. The gate parks *before*
/// reading, so this bounds how far a single read may overshoot the budget.
const DIRECT_READ_BUF: usize = 16 * 1024;
/// What the origin tries to push — orders of magnitude over the budget, so
/// "the origin got through all of it" is unambiguously an unenforced budget.
const ORIGIN_TOTAL: usize = 16 * 1024 * 1024;
/// Client's advertised receive window. The client ACKs the handshake and then
/// goes silent, so nothing ever drains and the pending sum stays parked.
const CLIENT_WINDOW: u16 = 4096;

/// A fast origin behind a direct flow: accepts one connection, pushes
/// [`ORIGIN_TOTAL`] bytes as fast as the socket takes them, and publishes how
/// many bytes it actually handed to the kernel.
struct BlockedOrigin {
    addr: SocketAddr,
    written: Arc<AtomicUsize>,
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
            let payload = vec![b'B'; 64 * 1024];
            let mut sent = 0usize;
            while sent < ORIGIN_TOTAL {
                let take = payload.len().min(ORIGIN_TOTAL - sent);
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
/// stopped reading) or gives up entirely.
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
async fn global_pending_budget_parks_readers_and_settles_on_teardown() {
    let origin = BlockedOrigin::start().await;
    let (writer, mut capture) = TunCapture::new().await;
    let config = TunTcpConfig {
        max_pending_server_bytes: PER_FLOW_LIMIT,
        pending_server_budget_bytes: BUDGET,
        // The client never ACKs past the handshake; keep every reaper far past
        // the test window so the only observable throttling is the budget's.
        backlog_no_progress_abort: Duration::from_secs(60),
        max_retransmits: 1_000,
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
    let client_port = 40200;
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

    wait_until_origin_settles(&origin).await;

    let written = origin.written.load(Ordering::SeqCst);
    assert!(
        !origin.finished.load(Ordering::SeqCst),
        "origin was never throttled: it drained its whole payload \
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
        .expect("a budget-parked flow must be throttled, not reset");
    let (pending, global) = {
        let state = flow.lock().await;
        assert_eq!(state.status, TcpFlowStatus::Established);
        assert!(
            matches!(state.routing.route, TunRoute::Direct { .. }),
            "this test only proves anything on the direct path"
        );
        (
            pending_server_bytes(&state),
            engine.inner.pending_server_bytes_global.load(Ordering::SeqCst),
        )
    };
    drop(flow);
    // The gate parks before reading, so the queue may overshoot the budget by
    // at most the one read that crossed it — far under the per-flow limit,
    // proving the *global* arm is what parked the reader.
    assert!(
        pending <= BUDGET + DIRECT_READ_BUF,
        "downlink queue is not held at the global budget: {pending} bytes"
    );
    assert_eq!(
        global, pending,
        "engine-wide pending counter drifted from the single flow's queue"
    );

    // A throttled flow is not a dead flow: nothing may have been reset so far.
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        assert_eq!(
            parsed.flags & TCP_FLAG_RST,
            0,
            "budget-parked flow was reset instead of throttled"
        );
    }

    // Tear the flow down and require its share back: `TcpFlowState::drop`
    // must settle the engine-wide counter no matter which path removed it.
    engine.abort_flow_with_rst(&key, "test_teardown").await;
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if engine.inner.pending_server_bytes_global.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "engine-wide pending counter was not returned on flow teardown: {} bytes left",
        engine.inner.pending_server_bytes_global.load(Ordering::SeqCst)
    );
}
