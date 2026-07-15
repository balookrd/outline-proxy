//! Carrier migration: a TUN TCP flow surviving the death of its carrier.
//!
//! These tests drive the real engine against a mock upstream that speaks the
//! real resume protocol — it mints `X-Outline-Session` ids, echoes the v1/v2
//! capability headers, and (when told to) emits the `ORSM` / `ORDR` control
//! frames. What they pin down is the one thing that matters: the flow migrates
//! **only** when the server confirms it re-attached the parked upstream, and
//! when it does, the byte stream comes out exact — no duplicates, no gaps, no
//! FIN, no RST.
//!
//! The carrier is killed with a TCP RST (`SO_LINGER = 0`), not a FIN: a FIN is a
//! *clean* close, which the client correctly reads as "the upstream reached EOF"
//! and turns into an honest FIN for the application. Only a dirty death is a
//! carrier death.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use parking_lot::Mutex as SyncMutex;
use socks5_proto::TargetAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
};
use tokio_tungstenite::{MaybeTlsStream, accept_hdr_async};
use url::Url;

use outline_transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, TransportStream, UpstreamTransportGuard,
};
use outline_wire::resume::{build_v1_payload, downlink_replay};
use shadowsocks_crypto::CipherKind;

use crate::wire::IpVersion;

use super::super::super::TcpFlowKey;
use super::super::super::state_machine::{FlowResume, TcpFlowStatus};
use super::super::super::tests::{build_client_packet, test_tun_tcp_config};
use super::super::super::wire::parse_tcp_packet_unverified;
use super::super::super::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN};
use super::super::TunTcpEngine;
use super::{TunCapture, build_test_manager};

const CLIENT_WINDOW: u16 = 65535;
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

// ---------------------------------------------------------------------------
// Mock upstream
// ---------------------------------------------------------------------------

/// How the mock answers the *next* connection that presents a resume id.
#[derive(Clone)]
struct ResumePolicy {
    /// Echo `X-Outline-Resume-Ack-Prefix: 1`. A server with resumption disabled
    /// does not, and the client must then treat the redial as a miss without
    /// waiting for a frame that is never coming.
    echo_capabilities: bool,
    /// Emit the v1 `ORSM` frame — the server's *only* statement that it really
    /// re-attached the parked upstream. Off models every kind of miss.
    confirm_hit: bool,
    /// `up_acked`: how many uplink bytes the server claims it forwarded upstream
    /// before the carrier died. The client must replay from exactly here.
    up_acked: u64,
    /// v2 `ORDR` payload: the downstream bytes the dead carrier never delivered.
    downlink_replay: Option<Vec<u8>>,
    /// v2 `ORDR` with `REPLAY_TRUNCATED`: the server's ring rolled past our
    /// offset, so the downstream gap is unrecoverable.
    downlink_truncated: bool,
    /// Speak first with these bytes instead of the control frames — what a
    /// *fresh* upstream (i.e. a miss) looks like when the destination is
    /// server-speaks-first.
    speak_instead: Option<Vec<u8>>,
}

impl Default for ResumePolicy {
    fn default() -> Self {
        Self {
            echo_capabilities: true,
            confirm_hit: true,
            up_acked: 0,
            downlink_replay: None,
            downlink_truncated: false,
            speak_instead: None,
        }
    }
}

/// What one connection asked for, for the assertions that the client presented
/// its own id and its own downstream offset.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedRequest {
    resume_id: Option<String>,
    down_acked: Option<u64>,
}

struct MockState {
    policy: SyncMutex<ResumePolicy>,
    requests: SyncMutex<Vec<ObservedRequest>>,
    accepted: AtomicUsize,
    /// Every plaintext chunk the mock decrypted, tagged with the 1-based ordinal
    /// of the connection it arrived on — so a test can say "connection 2 saw
    /// exactly these bytes, in this order".
    uplink_tx: mpsc::UnboundedSender<(usize, Vec<u8>)>,
    /// Downstream sender and killer for the newest connection.
    live: Mutex<Option<LiveConnection>>,
}

struct LiveConnection {
    downstream: mpsc::UnboundedSender<Vec<u8>>,
    /// Dropping this end makes the handler return, which drops the socket — and
    /// with `SO_LINGER = 0` that is a RST on the wire.
    kill: tokio::sync::oneshot::Sender<()>,
}

/// A Shadowsocks-over-WebSocket upstream that speaks session resumption.
struct ResumableUpstream {
    addr: SocketAddr,
    state: Arc<MockState>,
    uplink_rx: Mutex<mpsc::UnboundedReceiver<(usize, Vec<u8>)>>,
}

impl ResumableUpstream {
    async fn start() -> Arc<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (uplink_tx, uplink_rx) = mpsc::unbounded_channel();
        let state = Arc::new(MockState {
            policy: SyncMutex::new(ResumePolicy::default()),
            requests: SyncMutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
            uplink_tx,
            live: Mutex::new(None),
        });
        let accept_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                // Arm the RST *now*: once the socket is inside the WebSocket we
                // no longer have a handle to set it on.
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                let ordinal = accept_state.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                let conn_state = Arc::clone(&accept_state);
                tokio::spawn(async move {
                    let _ = serve_connection(stream, ordinal, conn_state).await;
                });
            }
        });
        Arc::new(Self {
            addr,
            state,
            uplink_rx: Mutex::new(uplink_rx),
        })
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/tcp", self.addr)).unwrap()
    }

    fn set_policy(&self, policy: ResumePolicy) {
        *self.state.policy.lock() = policy;
    }

    fn connections(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<ObservedRequest> {
        self.state.requests.lock().clone()
    }

    /// Next plaintext chunk the mock decrypted, with its connection ordinal.
    async fn recv(&self) -> (usize, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            self.uplink_rx.lock().await.recv().await
        })
        .await
        .expect("timed out waiting for an upstream chunk")
        .expect("mock upstream channel closed")
    }

    /// Accumulate chunks from `connection` until `len` bytes have arrived, then
    /// return them concatenated. Chunk boundaries are a transport detail; the
    /// byte stream is what must be exact.
    async fn recv_exactly(&self, connection: usize, len: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < len {
            let (ordinal, chunk) = self.recv().await;
            assert_eq!(ordinal, connection, "chunk arrived on an unexpected connection");
            got.extend_from_slice(&chunk);
        }
        got
    }

    /// Assert nothing more arrives upstream for a beat — used to prove a byte
    /// range was *not* re-sent.
    async fn expect_quiet(&self) {
        let quiet = tokio::time::timeout(Duration::from_millis(300), async {
            self.uplink_rx.lock().await.recv().await
        })
        .await;
        assert!(quiet.is_err(), "upstream received bytes it should never have seen: {quiet:?}");
    }

    /// Assert that an abandoned redial replayed **nothing**: whatever reached the
    /// upstream on `connection` is at most the Shadowsocks target header the
    /// handshake always carries, never a payload byte.
    ///
    /// Whether the server got even that far is a race — the client closes the
    /// stream the moment it learns the resume missed — so this tolerates the
    /// header being absent, and refuses anything past it.
    async fn expect_no_payload(&self, connection: usize) {
        let mut bytes = Vec::new();
        while let Ok(Some((ordinal, chunk))) =
            tokio::time::timeout(Duration::from_millis(300), async {
                self.uplink_rx.lock().await.recv().await
            })
            .await
        {
            assert_eq!(ordinal, connection, "chunk arrived on an unexpected connection");
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return;
        }
        let (_, consumed) = TargetAddr::from_wire_bytes(&bytes)
            .expect("only a target header may ever reach an abandoned redial");
        assert_eq!(
            consumed,
            bytes.len(),
            "an abandoned redial must not replay a single payload byte"
        );
    }

    async fn send_downstream(&self, bytes: &[u8]) {
        let live = self.state.live.lock().await;
        live.as_ref()
            .expect("no live connection")
            .downstream
            .send(bytes.to_vec())
            .expect("downstream channel closed");
    }

    /// Kill the newest carrier the way a collapsing H3 connection does: RST.
    async fn kill_carrier(&self) {
        let live = self.state.live.lock().await.take();
        drop(live.expect("no live connection to kill").kill);
    }
}

async fn serve_connection(
    stream: TcpStream,
    ordinal: usize,
    state: Arc<MockState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let observed = Arc::new(SyncMutex::new(ObservedRequest { resume_id: None, down_acked: None }));
    let echo_capabilities = state.policy.lock().echo_capabilities;

    let capture = Arc::clone(&observed);
    // `ErrorResponse` is tungstenite's `Callback` signature, not ours.
    #[allow(clippy::result_large_err)]
    let handshake = move |request: &HandshakeRequest,
                          mut response: HandshakeResponse|
          -> Result<HandshakeResponse, ErrorResponse> {
        let header = |name: &str| {
            request
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        {
            let mut capture = capture.lock();
            capture.resume_id = header("x-outline-resume");
            capture.down_acked = header("x-outline-resume-down-acked").and_then(|v| v.parse().ok());
        }
        // Every session gets an id, exactly like a resumption-enabled server.
        let session = format!("{ordinal:032x}");
        response
            .headers_mut()
            .insert("x-outline-session", session.parse().unwrap());
        if echo_capabilities {
            // NB: the real server echoes these whenever it *understands* the
            // protocol — hit or miss. They are a capability statement, never a
            // confirmation, which is the whole reason the client must wait for
            // the control frame instead.
            if request.headers().contains_key("x-outline-resume-ack-prefix") {
                response
                    .headers_mut()
                    .insert("x-outline-resume-ack-prefix", "1".parse().unwrap());
            }
            if request.headers().contains_key("x-outline-resume-symmetric-replay") {
                response
                    .headers_mut()
                    .insert("x-outline-resume-symmetric-replay", "1".parse().unwrap());
            }
        }
        Ok(response)
    };

    let ws = accept_hdr_async(MaybeTlsStream::Plain(stream), handshake).await?;
    state.requests.lock().push(observed.lock().clone());
    let is_resume = observed.lock().resume_id.is_some();

    let ws = TransportStream::new_http1(ws);
    let (sink, source) = ws.split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("Secret0").unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(sink, cipher, &master_key, Arc::clone(&lifetime)).await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(source, cipher, &master_key, lifetime, ctrl_tx)
        .with_request_salt(request_salt);

    // The target header. The real server parses it off every stream — including
    // a resumed one, where it then throws it away and keeps the parked target.
    let target = reader.read_chunk().await?;
    state.uplink_tx.send((ordinal, target.to_vec()))?;

    // Control frames, in the order the spec fixes: v1 then v2, both before any
    // upstream byte.
    if is_resume {
        let policy = state.policy.lock().clone();
        if let Some(bytes) = policy.speak_instead {
            writer.send_chunk(&bytes).await?;
        } else if policy.confirm_hit && policy.echo_capabilities {
            writer.send_chunk(&build_v1_payload(policy.up_acked)).await?;
            // v2, once echoed, is emitted on EVERY hit — with `replay_len = 0`
            // when there is nothing to replay. A server that echoed the
            // capability and then stayed silent would hang the client, so a mock
            // that only speaks when it has something to say would be testing a
            // protocol nobody implements.
            if policy.downlink_truncated {
                let header =
                    downlink_replay::build_v1_header(downlink_replay::FLAG_REPLAY_TRUNCATED, 0);
                writer.send_chunk(&header).await?;
            } else {
                let replay = policy.downlink_replay.unwrap_or_default();
                let mut frame = downlink_replay::build_v1_header(
                    downlink_replay::FLAGS_NONE,
                    replay.len() as u64,
                )
                .to_vec();
                frame.extend_from_slice(&replay);
                writer.send_chunk(&frame).await?;
            }
        }
    }

    let (downstream_tx, mut downstream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (kill_tx, mut kill_rx) = tokio::sync::oneshot::channel::<()>();
    *state.live.lock().await = Some(LiveConnection { downstream: downstream_tx, kill: kill_tx });

    loop {
        tokio::select! {
            // The killer end was dropped: return, which drops the socket. With
            // `SO_LINGER = 0` the kernel sends a RST.
            _ = &mut kill_rx => return Ok(()),
            inbound = reader.read_chunk() => match inbound {
                Ok(chunk) => state.uplink_tx.send((ordinal, chunk.to_vec()))?,
                Err(_) => return Ok(()),
            },
            outbound = downstream_rx.recv() => match outbound {
                Some(chunk) => writer.send_chunk(&chunk).await?,
                None => return Ok(()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Engine harness
// ---------------------------------------------------------------------------

fn flow_key(client_port: u16) -> TcpFlowKey {
    TcpFlowKey {
        version: IpVersion::V4,
        client_ip: CLIENT_IP.into(),
        client_port,
        remote_ip: REMOTE_IP.into(),
        remote_port: 443,
    }
}

/// SYN → SYN-ACK → ACK. Returns the server's next sequence number.
async fn open_flow(
    engine: &TunTcpEngine,
    capture: &mut TunCapture,
    key: &TcpFlowKey,
    client_seq: u32,
) -> u32 {
    engine
        .handle_packet_unverified(&build_client_packet(
            CLIENT_IP,
            REMOTE_IP,
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
            CLIENT_IP,
            REMOTE_IP,
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

/// Feed one client data segment.
async fn client_sends(engine: &TunTcpEngine, key: &TcpFlowKey, seq: u32, ack: u32, payload: &[u8]) {
    engine
        .handle_packet_unverified(&build_client_packet(
            CLIENT_IP,
            REMOTE_IP,
            key.client_port,
            key.remote_port,
            seq,
            ack,
            CLIENT_WINDOW,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
        ))
        .await
        .unwrap();
}

/// Pure ACK from the client, acknowledging downstream bytes. Without it the
/// stack keeps them on the retransmit queue and holds any FIN behind them — so a
/// test that wants to observe a teardown must ACK what it was sent.
async fn client_acks(engine: &TunTcpEngine, key: &TcpFlowKey, seq: u32, ack: u32) {
    engine
        .handle_packet_unverified(&build_client_packet(
            CLIENT_IP,
            REMOTE_IP,
            key.client_port,
            key.remote_port,
            seq,
            ack,
            CLIENT_WINDOW,
            TCP_FLAG_ACK,
            &[],
        ))
        .await
        .unwrap();
}

async fn wait_until_armed(engine: &TunTcpEngine, key: &TcpFlowKey) {
    for _ in 0..300 {
        if let Some(flow) = engine.inner.flows.get(key).map(|e| Arc::clone(e.value()))
            && flow.lock().await.resume.is_resumable()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("flow's resume state was never armed");
}

/// Wait until the flow has migrated (its carrier epoch advanced) or the reader
/// gave up. `true` = migrated.
async fn wait_for_migration(engine: &TunTcpEngine, key: &TcpFlowKey) -> bool {
    for _ in 0..600 {
        match engine.inner.flows.get(key).map(|e| Arc::clone(e.value())) {
            Some(flow) => {
                if flow.lock().await.resume.carrier_epoch() > 0 {
                    return true;
                }
            },
            // The flow is gone: it was torn down, so it certainly did not
            // migrate.
            None => return false,
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Drain whatever the TUN has queued and report whether any of it was a FIN or a
/// RST — the two things the application must never see on a migration.
async fn saw_fin_or_rst(capture: &mut TunCapture) -> bool {
    let mut saw = false;
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        if parsed.flags & (TCP_FLAG_FIN | TCP_FLAG_RST) != 0 {
            saw = true;
        }
    }
    saw
}

/// Next TUN packet carrying payload (skipping pure ACKs).
async fn next_data_packet(capture: &mut TunCapture) -> (u32, Vec<u8>) {
    for _ in 0..200 {
        let packet = capture.next_packet().await;
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        if !parsed.payload.is_empty() {
            return (parsed.sequence_number, parsed.payload.to_vec());
        }
    }
    panic!("no data packet reached the TUN");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The money test. The carrier dies mid-flow; the server confirms the resume and
/// reports it forwarded only part of what we sent; the flow migrates; the
/// upstream receives EXACTLY the missing tail — no duplicate byte, no missing
/// byte — and the application never sees a FIN or a RST.
#[tokio::test]
async fn a_flow_survives_its_carrier_dying_and_replays_only_the_missing_tail() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41000);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let (conn, target) = upstream.recv().await;
    assert_eq!(conn, 1);
    let (target, _) = TargetAddr::from_wire_bytes(&target).unwrap();
    assert_eq!(target, TargetAddr::IpV4(REMOTE_IP, 443));
    wait_until_armed(&engine, &key).await;

    // 16 bytes upstream, all of which reach the mock.
    client_sends(&engine, &key, 1001, server_seq, b"GET / HTTP/1.1\r\n").await;
    assert_eq!(upstream.recv_exactly(1, 16).await, b"GET / HTTP/1.1\r\n".to_vec());

    // The server will claim it forwarded only the first 6 of them ("GET / ") —
    // the rest died in flight with the carrier.
    upstream.set_policy(ResumePolicy { up_acked: 6, ..ResumePolicy::default() });
    upstream.kill_carrier().await;

    assert!(wait_for_migration(&engine, &key).await, "the flow must have migrated");
    assert_eq!(upstream.connections(), 2, "the migration re-dialled exactly once");

    // The redial presented this flow's own id — the one connection 1 minted.
    let requests = upstream.requests();
    assert_eq!(requests[0].resume_id, None, "the first dial resumes nothing");
    assert_eq!(
        requests[1].resume_id.as_deref(),
        Some(format!("{:032x}", 1).as_str()),
        "the redial must present the id the server issued to THIS flow"
    );
    assert_eq!(requests[1].down_acked, None, "nothing downstream was accepted, so no offset");

    // The new upstream sees the target header, then the tail from offset 6 —
    // and nothing else. Not one byte of "GET / " again.
    let (conn, target) = upstream.recv().await;
    assert_eq!(conn, 2);
    assert_eq!(
        TargetAddr::from_wire_bytes(&target).unwrap().0,
        TargetAddr::IpV4(REMOTE_IP, 443)
    );
    assert_eq!(
        upstream.recv_exactly(2, 10).await,
        b"HTTP/1.1\r\n".to_vec(),
        "the replay must be exactly the tail the server said it never forwarded"
    );
    upstream.expect_quiet().await;

    // The flow is alive and still works, in both directions.
    client_sends(&engine, &key, 1017, server_seq, b"MORE").await;
    assert_eq!(upstream.recv_exactly(2, 4).await, b"MORE".to_vec());
    upstream.send_downstream(b"REPLY").await;
    let (seq, payload) = next_data_packet(&mut capture).await;
    assert_eq!(payload, b"REPLY".to_vec());
    assert_eq!(seq, server_seq, "the downstream sequence continues where it left off");

    // And the application never learned any of this happened.
    assert!(
        !saw_fin_or_rst(&mut capture).await,
        "a migrated flow must not send the application a FIN or a RST"
    );
    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    assert_eq!(flow.lock().await.status, TcpFlowStatus::Established);
}

/// The downstream gap: the v2 replay slice reaches the application BEFORE any
/// fresh byte from the new carrier, and in order.
#[tokio::test]
async fn the_downstream_replay_slice_is_delivered_before_any_fresh_byte() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41001);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;

    // The application takes 4 bytes downstream before the carrier dies, so the
    // redial must report `down_acked = 4` and the server replays from there.
    upstream.send_downstream(b"HEAD").await;
    let (seq, payload) = next_data_packet(&mut capture).await;
    assert_eq!(payload, b"HEAD".to_vec());
    assert_eq!(seq, server_seq);

    upstream.set_policy(ResumePolicy {
        downlink_replay: Some(b"GAP!".to_vec()),
        ..ResumePolicy::default()
    });
    upstream.kill_carrier().await;
    assert!(wait_for_migration(&engine, &key).await, "the flow must have migrated");

    let requests = upstream.requests();
    assert_eq!(
        requests[1].down_acked,
        Some(4),
        "the redial must tell the server how much downstream this flow already accepted"
    );

    // The gap the dead carrier never delivered comes first...
    let (gap_seq, gap) = next_data_packet(&mut capture).await;
    assert_eq!(gap, b"GAP!".to_vec());
    assert_eq!(gap_seq, server_seq.wrapping_add(4), "the gap continues the byte stream");

    // ...and only then whatever the new carrier produces.
    upstream.send_downstream(b"NEW").await;
    let (fresh_seq, fresh) = next_data_packet(&mut capture).await;
    assert_eq!(fresh, b"NEW".to_vec());
    assert_eq!(fresh_seq, server_seq.wrapping_add(8), "fresh bytes follow the replayed gap");
}

/// A miss is never papered over — shape 1: the server has resumption disabled,
/// so it never engages the protocol. The flow tears down exactly as it did
/// before migration existed, and the stream the redial opened is closed rather
/// than leaked.
#[tokio::test]
async fn a_server_that_does_not_confirm_the_resume_gets_no_migration() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41002);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;
    client_sends(&engine, &key, 1001, server_seq, b"SENT").await;
    assert_eq!(upstream.recv_exactly(1, 4).await, b"SENT".to_vec());

    // The redial will be answered, but with no capability echo and no control
    // frame — the server minted a brand-new session and opened a brand-new
    // upstream. Continuing the flow on it would splice two byte streams.
    upstream.set_policy(ResumePolicy {
        echo_capabilities: false,
        confirm_hit: false,
        ..ResumePolicy::default()
    });
    upstream.kill_carrier().await;

    // The application gets the disconnect it would have got before.
    let fin = wait_for_fin(&mut capture).await;
    assert!(fin, "an unconfirmed resume must tear the flow down, not continue it");
    assert!(!wait_for_migration(&engine, &key).await, "the flow must not have migrated");

    // The redial happened — that is how we learned it was a miss — and the
    // upstream it opened was handed nothing: not one byte of "SENT" was replayed
    // onto a stream we had no proof about.
    assert_eq!(upstream.connections(), 2);
    upstream.expect_no_payload(2).await;
}

/// A miss is never papered over — shape 2: the server echoes the capability (so
/// it *understands* resumption) but the upstream it attached is fresh and speaks
/// first. Those bytes are not a control frame, and must never be mistaken for
/// one.
#[tokio::test]
async fn a_fresh_upstream_speaking_first_is_not_mistaken_for_a_resume_hit() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41003);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;
    client_sends(&engine, &key, 1001, server_seq, b"SENT").await;
    assert_eq!(upstream.recv_exactly(1, 4).await, b"SENT".to_vec());

    upstream.set_policy(ResumePolicy {
        confirm_hit: false,
        speak_instead: Some(b"220 fresh-smtp-banner\r\n".to_vec()),
        ..ResumePolicy::default()
    });
    upstream.kill_carrier().await;

    assert!(
        wait_for_fin(&mut capture).await,
        "bytes that are not an Ack-Prefix frame are not a hit; the flow must tear down"
    );
    assert!(!wait_for_migration(&engine, &key).await, "the flow must not have migrated");
    // And the banner from that fresh upstream never reached the application.
    while let Some(packet) = capture.try_next_packet().await {
        let parsed = parse_tcp_packet_unverified(&packet).unwrap();
        assert!(
            !parsed.payload.windows(3).any(|w| w == b"220"),
            "a fresh upstream's bytes must never be spliced into the application's stream"
        );
    }
}

/// A flow whose replay ring was dropped (an oversized chunk in Phase 1) cannot
/// prove byte-exactness, so it must not migrate at all — not even try.
#[tokio::test]
async fn a_flow_with_no_replay_ring_never_attempts_a_migration() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41004);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;

    // Shrink the ring so an ordinary segment overflows it, exactly as a >64 KiB
    // chunk would in production — the flow keeps serving but loses its ring.
    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    {
        let mut state = flow.lock().await;
        let session_id = state.resume.session_id;
        state.resume = FlowResume::armed_with_capacity(session_id, 8);
    }
    client_sends(&engine, &key, 1001, server_seq, b"a segment larger than the ring").await;
    assert_eq!(upstream.recv_exactly(1, 30).await, b"a segment larger than the ring".to_vec());
    assert!(!flow.lock().await.resume.is_resumable());

    upstream.kill_carrier().await;

    assert!(wait_for_fin(&mut capture).await, "a non-resumable flow tears down as before");
    assert_eq!(
        upstream.connections(),
        1,
        "a flow that cannot replay its tail must not even dial: the redial could only \
         produce a stream we would have to throw away"
    );
}

/// The server asks us to replay from an offset our ring has already evicted. We
/// cannot reproduce those bytes, so the honest answer is a teardown — never a
/// stream with a hole in it.
#[tokio::test]
async fn an_evicted_replay_offset_tears_the_flow_down_instead_of_tearing_the_stream() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41005);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;

    // An 8-byte ring: three 4-byte segments roll the oldest one out, so offset 0
    // is no longer reproducible.
    let flow = engine.inner.flows.get(&key).map(|e| Arc::clone(e.value())).unwrap();
    {
        let mut state = flow.lock().await;
        let session_id = state.resume.session_id;
        state.resume = FlowResume::armed_with_capacity(session_id, 8);
    }
    for (i, chunk) in [&b"AAAA"[..], b"BBBB", b"CCCC"].iter().enumerate() {
        client_sends(&engine, &key, 1001 + (i as u32 * 4), server_seq, chunk).await;
        assert_eq!(upstream.recv_exactly(1, 4).await, chunk.to_vec());
    }
    {
        let state = flow.lock().await;
        let ring = state
            .resume
            .replay()
            .expect("the ring survives eviction; it only rolls");
        assert_eq!(ring.oldest_offset(), 4, "the first chunk has been evicted");
    }

    // The server claims it forwarded nothing — so it wants a replay from 0,
    // which we can no longer produce.
    upstream.set_policy(ResumePolicy { up_acked: 0, ..ResumePolicy::default() });
    upstream.kill_carrier().await;

    assert!(
        wait_for_fin(&mut capture).await,
        "a replay we cannot reproduce must end the flow, not resume it with a gap"
    );
    assert!(!wait_for_migration(&engine, &key).await);
    // The redial happened, but nothing was replayed onto it — a partial replay
    // is exactly the torn stream this branch exists to prevent.
    assert_eq!(upstream.connections(), 2);
    upstream.expect_no_payload(2).await;
}

/// The server confirms the resume but admits its downlink ring rolled past our
/// offset (`REPLAY_TRUNCATED`): the bytes the dead carrier never delivered are
/// gone for good. Resuming would hand the application a stream with a hole in
/// the middle of it, which it has no way to notice — so we refuse.
#[tokio::test]
async fn a_truncated_downstream_replay_is_refused_rather_than_delivered_with_a_hole() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41007);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;
    upstream.send_downstream(b"HEAD").await;
    let (_, payload) = next_data_packet(&mut capture).await;
    assert_eq!(payload, b"HEAD".to_vec());
    // ACK it, so the teardown's FIN is not held behind unacked downstream data.
    client_acks(&engine, &key, 1001, server_seq.wrapping_add(4)).await;

    upstream.set_policy(ResumePolicy {
        downlink_truncated: true,
        ..ResumePolicy::default()
    });
    upstream.kill_carrier().await;

    assert!(
        wait_for_fin(&mut capture).await,
        "an unrecoverable downstream gap must end the flow, not resume it around the hole"
    );
    assert!(!wait_for_migration(&engine, &key).await, "the flow must not have migrated");
    upstream.expect_no_payload(2).await;
}

/// The pump does not reset a flow that is migrating, and does not re-send the
/// batch that died with the old carrier. The bytes the application wrote while
/// the carrier was dead reach the upstream exactly once — whether the pump had
/// already mirrored them into the ring (so the replay carries them) or takes
/// them afterwards (so the pump carries them).
#[tokio::test]
async fn the_pump_neither_resets_a_migrating_flow_nor_double_sends_its_batch() {
    let upstream = ResumableUpstream::start().await;
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

    let key = flow_key(41006);
    let server_seq = open_flow(&engine, &mut capture, &key, 1000).await;
    let _ = upstream.recv().await;
    wait_until_armed(&engine, &key).await;

    client_sends(&engine, &key, 1001, server_seq, b"HELLO").await;
    assert_eq!(upstream.recv_exactly(1, 5).await, b"HELLO".to_vec());

    // The server forwarded "HELLO" and nothing else.
    upstream.set_policy(ResumePolicy { up_acked: 5, ..ResumePolicy::default() });
    upstream.kill_carrier().await;
    // ...and the application keeps writing into the dead carrier. The pump will
    // fail to send this — it must park on the migration rather than reset the
    // flow, and it must not send these bytes twice (they are in the replay ring).
    client_sends(&engine, &key, 1006, server_seq, b"WORLD").await;

    assert!(
        wait_for_migration(&engine, &key).await,
        "the pump must not kill a migrating flow"
    );

    let (conn, _target) = upstream.recv().await;
    assert_eq!(conn, 2);
    assert_eq!(
        upstream.recv_exactly(2, 5).await,
        b"WORLD".to_vec(),
        "the bytes written while the carrier was dead must arrive exactly once"
    );
    upstream.expect_quiet().await;
    assert!(
        !saw_fin_or_rst(&mut capture).await,
        "the pump must not reset a flow the reader is rescuing"
    );
}

/// Wait for a FIN or RST to reach the application.
async fn wait_for_fin(capture: &mut TunCapture) -> bool {
    for _ in 0..600 {
        while let Some(packet) = capture.try_next_packet().await {
            let parsed = parse_tcp_packet_unverified(&packet).unwrap();
            if parsed.flags & (TCP_FLAG_FIN | TCP_FLAG_RST) != 0 {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}
