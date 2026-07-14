//! Per-flow resume accounting on the TUN TCP engine.
//!
//! A flow records what a future carrier migration would need — its own Session
//! ID, the tail of what it sent upstream, and how many downstream bytes it has
//! taken from the server. These tests pin that the recording tracks the real
//! data path (and, above all, that a flow whose ring cannot keep up is
//! *downgraded*, never killed).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
};
use url::Url;

use crate::wire::IpVersion;
use futures_util::StreamExt;

use super::super::super::state_machine::{FlowResume, TcpFlowStatus};
use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFlowKey};
use super::super::TunTcpEngine;
use super::{TestTcpUpstream, TunCapture, build_test_manager};

const CLIENT_WINDOW: u16 = 65535;

/// Ring cap small enough that a single ordinary client segment cannot fit — the
/// only practical way to drive the overflow path, since a real TUN segment
/// never approaches the production 64 KiB cap.
const TINY_RING_BYTES: usize = 8;

fn flow_key(client_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> TcpFlowKey {
    TcpFlowKey {
        version: IpVersion::V4,
        client_ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        client_port,
        remote_ip: remote_ip.into(),
        remote_port,
    }
}

/// Drives SYN → SYN-ACK → ACK for one flow and returns the server's next
/// sequence number. Leaves the flow Established with its upstream connecting.
async fn open_flow(
    engine: &TunTcpEngine,
    capture: &mut TunCapture,
    key: &TcpFlowKey,
    client_seq: u32,
) -> u32 {
    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = match key.remote_ip {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("tests use IPv4 flows"),
    };
    engine
        .handle_packet_unverified(&build_client_packet(
            client_ip,
            remote_ip,
            key.client_port,
            key.remote_port,
            client_seq,
            0,
            CLIENT_WINDOW,
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
            key.client_port,
            key.remote_port,
            client_seq.wrapping_add(1),
            server_next_seq,
            CLIENT_WINDOW,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();
    server_next_seq
}

/// Waits until the connect task has armed the flow's resume state (the upstream
/// is up and the pump is running). Polling, because the connect completes on its
/// own task after the handshake bytes are on the wire.
async fn wait_until_armed(engine: &TunTcpEngine, key: &TcpFlowKey) {
    for _ in 0..200 {
        if let Some(flow) = engine.inner.flows.get(key).map(|e| Arc::clone(e.value()))
            && flow.lock().await.resume.is_resumable()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("flow's resume state was never armed");
}

#[tokio::test]
async fn uplink_payload_is_mirrored_into_the_flows_replay_ring() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );

    let key = flow_key(40200, Ipv4Addr::new(8, 8, 8, 8), 443);
    let server_next_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.expect_target().await;
    wait_until_armed(&engine, &key).await;

    // Two segments, so the ring has to preserve *order*, not just bytes.
    for (offset, payload) in [(0u32, &b"GET / "[..]), (6, &b"HTTP/1.1\r\n"[..])] {
        engine
            .handle_packet_unverified(&build_client_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(8, 8, 8, 8),
                key.client_port,
                key.remote_port,
                1001u32.wrapping_add(offset),
                server_next_seq,
                CLIENT_WINDOW,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                payload,
            ))
            .await
            .unwrap();
    }

    // The upstream having received the bytes is what makes the ring assertions
    // race-free: the pump pushes into the ring *before* it writes to the writer.
    let mut received = upstream.recv_chunk().await;
    while received.len() < 16 {
        received.extend_from_slice(&upstream.recv_chunk().await);
    }
    assert_eq!(received, b"GET / HTTP/1.1\r\n".to_vec());

    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    let state = flow.lock().await;
    let ring = state.resume.replay().expect("a tunneled flow keeps a replay ring");
    assert_eq!(ring.total_sent(), 16, "the ring must track the bytes actually sent");
    assert_eq!(
        ring.replay_from(0).unwrap(),
        b"GET / HTTP/1.1\r\n".to_vec(),
        "the ring must reproduce the uplink byte stream in send order"
    );
    // Nothing downstream arrived yet.
    assert_eq!(state.resume.client_acked_offset(), 0);
}

#[tokio::test]
async fn downstream_payload_advances_the_client_acked_offset() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );

    let key = flow_key(40201, Ipv4Addr::new(8, 8, 8, 8), 443);
    let server_next_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.expect_target().await;
    wait_until_armed(&engine, &key).await;

    upstream.send_chunk(b"ABCDEFGH").await;
    let downlink = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(downlink.payload, b"ABCDEFGH"[..]);
    assert_eq!(downlink.sequence_number, server_next_seq);

    upstream.send_chunk(b"IJ").await;
    let downlink = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(downlink.payload, b"IJ"[..]);

    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    let state = flow.lock().await;
    // Counted when the bytes are accepted into the flow's downlink buffer — the
    // point past which this flow, not the server, owns delivering them.
    assert_eq!(state.resume.client_acked_offset(), 10);
    // The downstream direction never touches the uplink ring.
    assert_eq!(state.resume.replay().unwrap().total_sent(), 0);
}

/// The one that matters: a chunk the ring cannot hold costs the flow its
/// *resumability*, nothing else. No FIN, no RST, and the bytes still go
/// upstream.
#[tokio::test]
async fn an_oversized_uplink_chunk_downgrades_the_flow_but_never_kills_it() {
    let upstream = TestTcpUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );

    let key = flow_key(40202, Ipv4Addr::new(8, 8, 8, 8), 443);
    let server_next_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.expect_target().await;
    wait_until_armed(&engine, &key).await;

    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    // Shrink this flow's ring so an ordinary segment overflows it. Same effect a
    // 64 KiB+ chunk would have in production, without pushing 64 KiB through a
    // test.
    {
        let mut state = flow.lock().await;
        let session_id = state.resume.session_id;
        state.resume = FlowResume::armed_with_capacity(session_id, TINY_RING_BYTES);
    }

    let payload = b"a segment far larger than the ring";
    engine
        .handle_packet_unverified(&build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            key.client_port,
            key.remote_port,
            1001,
            server_next_seq,
            CLIENT_WINDOW,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
        ))
        .await
        .unwrap();

    // The payload still reaches the upstream, byte for byte.
    let mut received = upstream.recv_chunk().await;
    while received.len() < payload.len() {
        received.extend_from_slice(&upstream.recv_chunk().await);
    }
    assert_eq!(
        received,
        payload.to_vec(),
        "an overflowing ring must not cost the flow its data"
    );

    // The flow is still alive and serving: the server's reply flows through.
    upstream.send_chunk(b"OK").await;
    let downlink = parse_tcp_packet_unverified(&capture.next_packet().await).unwrap();
    assert_eq!(downlink.payload, b"OK"[..]);

    {
        let state = flow.lock().await;
        assert_eq!(state.status, TcpFlowStatus::Established, "the flow must not have been closed");
        assert!(
            !state.resume.is_resumable(),
            "a ring that cannot hold a chunk whole can never replay it — the flow must be \
             marked non-resumable"
        );
        assert!(state.resume.replay().is_none(), "the unusable ring is dropped, not kept torn");
        // Downstream accounting keeps working on a downgraded flow.
        assert_eq!(state.resume.client_acked_offset(), 2);
    }

    // And nothing reset the client.
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        assert_eq!(parsed.flags & TCP_FLAG_RST, 0, "a ring overflow must never turn into a reset");
    }
}

/// A WebSocket upstream that mints a distinct `X-Outline-Session` per accepted
/// connection — the server behaviour the client's resume plumbing keys off.
/// Speaks no Shadowsocks: these tests only care about what the handshake hands
/// back, and the client's setup is write-only.
struct SessionIssuingUpstream {
    addr: std::net::SocketAddr,
}

impl SessionIssuingUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issued = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let nth = issued.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let session_hex = format!("{nth:032x}");
                    // `ErrorResponse` is tungstenite's `Callback` signature, not
                    // ours — the large-Err shape is imposed by the trait.
                    #[allow(clippy::result_large_err)]
                    let inject =
                        move |_req: &HandshakeRequest,
                              mut response: HandshakeResponse|
                              -> Result<HandshakeResponse, ErrorResponse> {
                            response.headers_mut().insert(
                                "x-outline-session",
                                session_hex.parse().expect("hex is a valid header value"),
                            );
                            Ok(response)
                        };
                    let Ok(mut ws) = accept_hdr_async(stream, inject).await else {
                        return;
                    };
                    // Drain whatever the client writes; never close first.
                    while ws.next().await.is_some() {}
                });
            }
        });
        Self { addr }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/tcp", self.addr)).unwrap()
    }
}

#[tokio::test]
async fn each_flow_records_its_own_session_id() {
    let upstream = SessionIssuingUpstream::start().await;
    let manager = build_test_manager(upstream.url()).await;
    let (writer, mut capture) = TunCapture::new().await;
    let engine = TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager),
        128,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );

    let first_key = flow_key(40203, Ipv4Addr::new(8, 8, 8, 8), 443);
    let second_key = flow_key(40204, Ipv4Addr::new(8, 8, 8, 8), 443);
    open_flow(&engine, &mut capture, &first_key, 1000).await;
    open_flow(&engine, &mut capture, &second_key, 2000).await;
    wait_until_armed(&engine, &first_key).await;
    wait_until_armed(&engine, &second_key).await;

    let first = engine
        .inner
        .flows
        .get(&first_key)
        .map(|e| Arc::clone(e.value()))
        .unwrap();
    let second = engine
        .inner
        .flows
        .get(&second_key)
        .map(|e| Arc::clone(e.value()))
        .unwrap();
    let first_id = first.lock().await.resume.session_id;
    let second_id = second.lock().await.resume.session_id;

    assert!(first_id.is_some(), "a resume-capable server issues an id on every stream");
    assert!(second_id.is_some());
    // Two flows, two carrier streams, two ids. Sharing one would let a resume
    // splice one flow onto the other's upstream.
    assert_ne!(first_id, second_id, "flows must never share a Session ID");
}
