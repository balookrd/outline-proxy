//! Resource-bound invariants for the SS-over-WebSocket TCP relay.
//!
//! Both tests target the leak vector `AbortOnDrop` exists to close (see
//! [`crate::server::abort`]): the spawned upstream→client relay task must
//! never outlive the session that owns it. The upstream fixture accepts a
//! connection and then stays silent — an idle database, SSH session or
//! long-poll — because that is the only shape where an orphaned reader
//! waits forever instead of exiting on the next upstream EOF.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use axum::http::HeaderMap;
use bytes::BytesMut;
use outline_wire::cluster::{ObfuscationKey, ShardId};
use quinn::VarInt;
use ring::rand::SystemRandom;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};

use super::super::mesh_relay::{EdgeUpstream, edge_upstream, open_edge_relay_v5, ss_edge_echo};
use super::super::resume_headers::{
    ACK_PREFIX_HEADER, EdgeResumeAdvert, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER,
    SYMMETRIC_REPLAY_HEADER,
};
use super::super::ws_socket::{WsFrame, WsSocket};
use super::super::xhttp::handlers::XhttpEdge;
use super::*;
use crate::config::CipherKind;
use crate::protocol::TargetAddr;
use crate::server::abort::AbortOnDrop;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CloseReason, MeshEndpoint, MeshFraming, MeshIdentity, MeshPeerPool, OPEN_ACK_ACCEPTED,
    RelayOpen, ThrottleRegistry, UpstreamAckFrame, UserFrame,
};
use crate::server::nat::UdpResponseSender;
use crate::server::peer_user_cache::PeerUserCache;
use crate::server::resumption::ResumptionConfig;
use crate::server::tests::sample_config;

/// One scripted inbound event on the client side of the carrier.
enum Step {
    /// A WS Binary frame from the client.
    Binary(Bytes),
    /// `recv` fails: the client vanished without a closing handshake
    /// (TCP RST, QUIC reset, tungstenite `ResetWithoutClosingHandshake`).
    Reset,
    /// The client stays connected and silent until the test releases it.
    /// Without this a script's last frame would immediately EOF the carrier,
    /// tearing the session down before any downlink could arrive.
    Idle(oneshot::Receiver<()>),
}

enum MockMsg {
    Binary(Bytes),
    Ctrl,
}

/// Every Binary message the relay sent to the client, in order. Shared with the
/// test so it can decrypt the downlink under the key it expects.
type SentFrames = Arc<parking_lot::Mutex<Vec<Bytes>>>;

struct MockWs {
    steps: VecDeque<Step>,
    writer_alive: oneshot::Sender<()>,
    sent: SentFrames,
}

impl MockWs {
    /// A carrier driven by `steps`, discarding whatever is sent back.
    fn new(steps: VecDeque<Step>, writer_alive: oneshot::Sender<()>) -> Self {
        Self {
            steps,
            writer_alive,
            sent: SentFrames::default(),
        }
    }
}

struct MockReader(VecDeque<Step>);

struct MockWriter {
    /// Never read. The test observes when `run_ws_writer` returned by
    /// awaiting the paired receiver: it resolves the moment this writer
    /// half is dropped, which can only happen once every clone of the
    /// outbound data sender — including the one the relay task holds in
    /// its `ChannelSink` — is gone.
    _writer_alive: oneshot::Sender<()>,
    sent: SentFrames,
}

impl WsSocket for MockWs {
    type Msg = MockMsg;
    type Reader = MockReader;
    type Writer = MockWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (
            MockReader(self.steps),
            MockWriter {
                _writer_alive: self.writer_alive,
                sent: self.sent,
            },
        )
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Self::Msg>> {
        loop {
            match reader.0.pop_front() {
                Some(Step::Binary(data)) => return Ok(Some(MockMsg::Binary(data))),
                Some(Step::Reset) => {
                    return Err(anyhow!("connection reset without closing handshake"));
                },
                Some(Step::Idle(release)) => {
                    let _ = release.await;
                },
                // Script exhausted: the client stream ended without a Close
                // frame, which the relay reads as end-of-stream.
                None => return Ok(None),
            }
        }
    }

    async fn send(writer: &mut Self::Writer, msg: Self::Msg) -> Result<()> {
        if let MockMsg::Binary(data) = msg {
            writer.sent.lock().push(data);
        }
        Ok(())
    }

    async fn finish(_writer: &mut Self::Writer) {}

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        Ok(())
    }

    fn is_h3() -> bool {
        false
    }

    fn classify(msg: Self::Msg) -> WsFrame {
        match msg {
            MockMsg::Binary(data) => WsFrame::Binary(data),
            // The script never feeds control frames inbound.
            MockMsg::Ctrl => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> Self::Msg {
        MockMsg::Binary(data)
    }
    fn close_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn close_try_again_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn ping_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn pong_msg(_payload: Bytes) -> Self::Msg {
        MockMsg::Ctrl
    }
    fn binary_len(msg: &Self::Msg) -> Option<usize> {
        match msg {
            MockMsg::Binary(data) => Some(data.len()),
            MockMsg::Ctrl => None,
        }
    }
    fn msg_len(msg: &Self::Msg) -> usize {
        match msg {
            MockMsg::Binary(data) => data.len(),
            MockMsg::Ctrl => 0,
        }
    }
    fn make_udp_response_sender(
        _tx: mpsc::Sender<Self::Msg>,
        _protocol: Protocol,
        _app_protocol: AppProtocol,
        _scheme: PaddingScheme,
        _monitor: Option<Arc<super::super::throughput_monitor::ThroughputMonitor>>,
    ) -> UdpResponseSender {
        unimplemented!("the tcp relay never builds a udp response sender")
    }
}

/// Upstream that accepts connections and then goes silent forever: it never
/// writes, never reads and never closes. Models the idle-but-open targets
/// (database, SSH, long-poll, idle gRPC) against which an orphaned
/// upstream→client reader can wait indefinitely.
async fn spawn_silent_upstream() -> Result<(SocketAddr, AbortOnDrop<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            accepted.push(stream);
        }
    });
    Ok((addr, AbortOnDrop::new(task)))
}

fn test_user() -> Result<UserKey> {
    Ok(UserKey::new("bob", "secret-b", None, CipherKind::Chacha20IetfPoly1305, None)?)
}

/// Session-resumption is left disabled so `try_park_on_drop` bails out
/// immediately and the teardown takes the non-park branch.
fn test_contexts(user: &UserKey) -> (WsTcpServerCtx, WsTcpRouteCtx) {
    let metrics = Metrics::new(&sample_config((Ipv4Addr::LOCALHOST, 3000).into()));
    let server = WsTcpServerCtx {
        metrics: Arc::clone(&metrics),
        dns_cache: DnsCache::new(Duration::from_secs(60)),
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        orphan_registry: Arc::new(OrphanRegistry::new_disabled(metrics)),
        ws_data_channel_capacity: 8,
    };
    let route = WsTcpRouteCtx {
        users: Arc::from(vec![user.clone()]),
        protocol: Protocol::Http1,
        path: Arc::from("/tcp"),
        candidate_users: Arc::from(vec![user.id_arc()]),
        peer_user_cache: Arc::new(PeerUserCache::new(
            NonZeroUsize::new(16).expect("non-zero capacity"),
        )),
        padding: PaddingScheme::disabled(),
    };
    (server, route)
}

/// One SS-AEAD chunk carrying just the target address — the handshake that
/// makes the relay dial upstream and spawn the upstream→client task.
fn ss_handshake_frame(user: &UserKey, target: SocketAddr) -> Result<Bytes> {
    let plaintext = TargetAddr::from(target).to_wire_bytes()?;
    let mut encryptor = AeadStreamEncryptor::new(user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    Ok(buf.freeze())
}

// ── Cluster edge: SS-TCP with the upstream on the home (v5) ───────────────────

/// A stand-in home: it speaks the home half of the v5 mesh protocol over a real
/// mesh QUIC connection, but owns no park and no upstream socket — the test
/// plays the target itself. Everything the edge is *supposed* to do is therefore
/// observable here: the OPEN version, the attested user, and whether what
/// crosses the mesh is plaintext or ciphertext.
struct FakeHome {
    /// The USER frame the edge sent after authenticating its client.
    user: Option<oneshot::Receiver<UserFrame>>,
    /// Plaintext chunks the edge relayed toward the target.
    uplink: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Plaintext the test wants the "target" to answer with.
    downlink: mpsc::UnboundedSender<Vec<u8>>,
    _task: AbortOnDrop<()>,
}

impl FakeHome {
    /// The user name the edge attested, waiting for it if it has not arrived.
    async fn user_frame(&mut self) -> UserFrame {
        let rx = self.user.take().expect("the USER frame is read once");
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("the edge must send a USER frame after authenticating")
            .expect("the home task must not drop before the USER frame")
    }

    /// Reads until at least `want` bytes of uplink have arrived, then returns
    /// them.
    async fn upstream_received(&mut self, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        let collect = async {
            while got.len() < want {
                match self.uplink.recv().await {
                    Some(chunk) => got.extend_from_slice(&chunk),
                    None => break,
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), collect)
            .await
            .expect("the edge must relay the client's plaintext to the home");
        got
    }

    fn send_plaintext_downlink(&self, data: &[u8]) {
        self.downlink
            .send(data.to_vec())
            .expect("the home task must still be running");
    }
}

/// How the fake home answers the edge's OPEN.
enum HomeAnswer {
    /// A park exists: ack, take the USER frame, then splice.
    Park { acked_uplink: u64 },
    /// No park under this id: refuse before the edge upgrades its client.
    NoSession,
}

/// The edge's own cluster runtime plus the fake home it relays to. The edge's
/// credentials are its own: the home in these tests holds no key at all, which
/// is the property the whole change exists to allow.
struct EdgeHarness {
    cluster: ClusterCtx,
    shard: ShardId,
    server: WsTcpServerCtx,
    route: WsTcpRouteCtx,
    registry: Arc<OrphanRegistry>,
    user: UserKey,
    session_id: SessionId,
    _home_endpoint: MeshEndpoint,
}

impl EdgeHarness {
    /// An edge serving `user`/`secret`, wired to a home answering `answer`.
    async fn with_credentials(user: &str, secret: &str, answer: HomeAnswer) -> (Self, FakeHome) {
        let psk = b"edge-v5-tcp-psk";
        let home_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let home_addr = home_endpoint.local_addr().unwrap();
        let home = spawn_fake_home(home_endpoint.clone(), answer);

        let shard = ShardId::new(1).unwrap();
        let edge_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let cluster = ClusterCtx {
            pool: Arc::new(MeshPeerPool::new(
                edge_endpoint.clone(),
                HashMap::from([(shard, home_addr)]),
                8,
            )),
            endpoint: edge_endpoint,
            relay_budget: Duration::from_secs(5),
            throttle_registry: ThrottleRegistry::new(),
            relay_permits: Arc::new(Semaphore::new(8)),
            metrics: test_metrics(),
        };

        let user =
            UserKey::new(user, secret, None, CipherKind::Chacha20IetfPoly1305, None).unwrap();
        // Resumption is *on* here: a disabled registry could never park, so it
        // would prove nothing about an edge declining to. A non-zero downlink
        // ring is on too, so a client advertising v2 is actually negotiating it
        // locally — otherwise "the relayed echo withholds v2" would be vacuous.
        let obfuscation = ObfuscationKey::derive_from_psk(psk);
        let registry = Arc::new(
            OrphanRegistry::new(
                ResumptionConfig {
                    enabled: true,
                    downlink_buffer_bytes: 64 * 1024,
                    ..ResumptionConfig::defaults_disabled()
                },
                test_metrics(),
            )
            // This edge owns a *different* shard from the home below, which is
            // what makes the client's resume id a foreign one to route away.
            .with_cluster(obfuscation.clone(), ShardId::new(2).unwrap()),
        );
        let server = WsTcpServerCtx {
            metrics: test_metrics(),
            dns_cache: DnsCache::new(Duration::from_secs(60)),
            prefer_ipv4_upstream: false,
            outbound_ipv6: None,
            orphan_registry: Arc::clone(&registry),
            ws_data_channel_capacity: 8,
        };
        let route = WsTcpRouteCtx {
            users: Arc::from(vec![user.clone()]),
            protocol: Protocol::Http1,
            path: Arc::from("/tcp"),
            candidate_users: Arc::from(vec![user.id_arc()]),
            peer_user_cache: Arc::new(PeerUserCache::with_capacity(8)),
            padding: PaddingScheme::disabled(),
        };
        (
            Self {
                cluster,
                shard,
                server,
                route,
                registry,
                user,
                // A resume id the *home* shard minted, as if on a prior connect.
                session_id: SessionId::random_with_shard(&SystemRandom::new(), &obfuscation, shard)
                    .unwrap(),
                _home_endpoint: home_endpoint,
            },
            home,
        )
    }

    fn advert(&self) -> EdgeResumeAdvert {
        EdgeResumeAdvert {
            session_id: self.session_id,
            resume_capable: true,
            ack_prefix: true,
            symmetric_replay: true,
            down_acked: 0,
        }
    }

    /// The request headers the client behind [`Self::advert`] presents: a
    /// resume-capable v1+v2 client offering the foreign-shard id.
    fn resume_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RESUME_CAPABLE_HEADER, "1".parse().unwrap());
        headers.insert(ACK_PREFIX_HEADER, "1".parse().unwrap());
        headers.insert(SYMMETRIC_REPLAY_HEADER, "1".parse().unwrap());
        headers.insert(RESUME_REQUEST_HEADER, self.session_id.to_hex().parse().unwrap());
        headers
    }

    /// The resume negotiation this node would run on its own, i.e. what every
    /// entry point falls back to when no relay is in play.
    fn local_resume(&self) -> ResumeContext {
        ResumeContext::from_request_headers(&self.resume_headers(), &self.registry)
    }

    /// Runs phase 1 of the relay: `None` means the home refused and the caller
    /// serves the client locally instead.
    async fn open_relay(&self) -> Option<EdgeUpstream> {
        let advert = self.advert();
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40404));
        let pooled = tokio::time::timeout(
            Duration::from_secs(5),
            open_edge_relay_v5(&self.cluster, self.shard, &advert, MeshFraming::Tcp, peer),
        )
        .await
        .expect("the home must answer the OPEN, not hang the upgrade")?;
        Some(edge_upstream(
            pooled,
            &advert,
            &self.cluster,
            &self.server.metrics,
            &self.registry,
        ))
    }

    fn local_registry_size(&self) -> usize {
        self.registry.len()
    }
}

/// Drives the home half of one v5 relay stream: version-checks the OPEN,
/// answers it, and — when it admitted the relay — pumps plaintext both ways.
fn spawn_fake_home(endpoint: MeshEndpoint, answer: HomeAnswer) -> FakeHome {
    let (user_tx, user_rx) = oneshot::channel();
    let (uplink_tx, uplink_rx) = mpsc::unbounded_channel();
    let (downlink_tx, mut downlink_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let task = tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("the edge must dial the home")
            .expect("mesh handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("the edge must open a relay");
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await.expect("reading the OPEN length");
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        recv.read_exact(&mut buf).await.expect("reading the OPEN header");
        let header = match RelayOpen::parse(&buf).expect("parsing the OPEN header") {
            RelayOpen::V5(header) => header,
            RelayOpen::V4(_) => panic!("an SS-TCP edge must open v5, not v4"),
        };
        assert_eq!(
            header.framing,
            MeshFraming::Tcp,
            "an SS byte-stream carrier is TCP-framed on the mesh",
        );
        let acked_uplink = match answer {
            HomeAnswer::Park { acked_uplink } => acked_uplink,
            HomeAnswer::NoSession => {
                let code = VarInt::from_u32(CloseReason::NoSession.code());
                let _ = send.reset(code);
                let _ = recv.stop(code);
                return;
            },
        };
        send.write_all(&[OPEN_ACK_ACCEPTED])
            .await
            .expect("writing the OPEN ack");

        let mut prefix = [0u8; 1];
        recv.read_exact(&mut prefix).await.expect("reading the USER length");
        let mut frame = vec![0u8; 1 + prefix[0] as usize];
        frame[0] = prefix[0];
        recv.read_exact(&mut frame[1..])
            .await
            .expect("reading the USER frame");
        let _ = user_tx.send(UserFrame::parse(&frame).expect("parsing the USER frame"));

        if header.ack_prefix {
            send.write_all(&UpstreamAckFrame { upstream_acked: acked_uplink }.encode())
                .await
                .expect("writing the upstream-ack frame");
        }

        tokio::join!(
            async {
                while let Ok(Some(chunk)) = recv.read_chunk(64 * 1024, true).await {
                    if uplink_tx.send(chunk.bytes.to_vec()).is_err() {
                        break;
                    }
                }
            },
            async {
                while let Some(data) = downlink_rx.recv().await {
                    if send.write_all(&data).await.is_err() {
                        break;
                    }
                }
            },
        );
    });
    FakeHome {
        user: Some(user_rx),
        uplink: uplink_rx,
        downlink: downlink_tx,
        _task: AbortOnDrop::new(task),
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&sample_config((Ipv4Addr::LOCALHOST, 3000).into()))
}

/// One SS-AEAD chunk carrying the target address plus `payload`.
fn ss_frame_with_payload(user: &UserKey, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut plaintext = TargetAddr::from(target).to_wire_bytes()?;
    plaintext.extend_from_slice(payload);
    let mut encryptor = AeadStreamEncryptor::new(user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    Ok(buf.freeze())
}

/// A target address nothing listens on: a relayed session must never dial it,
/// so a regression that connects out fails the test rather than silently
/// working.
fn unreachable_target() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 1))
}

/// Decrypts everything the relay sent the client under `user`'s key.
fn decrypt_downlink(user: &UserKey, frames: &[Bytes]) -> Result<Vec<u8>> {
    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user.clone()]));
    let mut plaintext = Vec::new();
    for frame in frames {
        decryptor.feed_ciphertext(frame);
        let mut chunk = Vec::new();
        decryptor.drain_plaintext(&mut chunk)?;
        plaintext.extend_from_slice(&chunk);
    }
    Ok(plaintext)
}

/// The whole point: the edge's key is one the home does not hold, and the relay
/// still works because the edge — not the home — decrypts the client. The user
/// it authenticated is attested over the mesh, and what crosses the mesh is
/// plaintext.
#[tokio::test]
async fn edge_authenticates_with_its_own_credentials_then_sends_the_user_frame() -> Result<()> {
    let (harness, mut home) = EdgeHarness::with_credentials(
        "beerloga",
        "edge-secret",
        HomeAnswer::Park { acked_uplink: 0 },
    )
    .await;
    let edge = harness.open_relay().await.expect("the home holds a park");

    let (writer_alive, _writer_gone) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let socket = MockWs::new(
        VecDeque::from_iter([
            Step::Binary(ss_frame_with_payload(
                &harness.user,
                unreachable_target(),
                b"hello upstream",
            )?),
            Step::Idle(released),
        ]),
        writer_alive,
    );
    let relay = tokio::spawn(async move {
        let _ = run_tcp_relay::<MockWs>(
            socket,
            &harness.server,
            &harness.route,
            edge.resume,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 40404))),
            None,
            edge.source,
        )
        .await;
    });

    assert_eq!(
        home.user_frame().await.user,
        "beerloga",
        "the edge must attest the user it authenticated"
    );
    assert_eq!(
        home.upstream_received(b"hello upstream".len()).await,
        b"hello upstream",
        "the mesh must carry plaintext, not ciphertext"
    );
    let _ = release.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    Ok(())
}

/// The downlink is sealed under the edge's own key: the home hands over
/// plaintext and the client, which only ever knew the edge's credentials, reads
/// it back. This is the half that makes per-node credentials possible.
#[tokio::test]
async fn edge_seals_the_downlink_under_its_own_key() -> Result<()> {
    let (harness, mut home) = EdgeHarness::with_credentials(
        "beerloga",
        "edge-secret",
        HomeAnswer::Park { acked_uplink: 0 },
    )
    .await;
    let edge = harness.open_relay().await.expect("the home holds a park");

    let (writer_alive, _writer_gone) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let socket = MockWs::new(
        VecDeque::from_iter([
            Step::Binary(ss_frame_with_payload(&harness.user, unreachable_target(), b"go")?),
            Step::Idle(released),
        ]),
        writer_alive,
    );
    let sent = Arc::clone(&socket.sent);
    let user = harness.user.clone();
    let relay = tokio::spawn(async move {
        let _ = run_tcp_relay::<MockWs>(
            socket,
            &harness.server,
            &harness.route,
            edge.resume,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 40404))),
            None,
            edge.source,
        )
        .await;
    });
    // Ordering: the home only splices once it has the USER frame.
    let _ = home.user_frame().await;
    home.send_plaintext_downlink(b"payload from upstream");

    // The client decrypts with the edge's key and gets the plaintext back. The
    // Ack-Prefix control frame the home's offset produces comes first on the
    // same stream, exactly as on a direct resume.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let want = build_v1_payload(0).len() + b"payload from upstream".len();
    loop {
        let frames = sent.lock().clone();
        let plaintext = decrypt_downlink(&user, &frames)?;
        if plaintext.len() >= want {
            assert_eq!(
                &plaintext[build_v1_payload(0).len()..],
                b"payload from upstream",
                "the client must read the home's plaintext under the edge's key",
            );
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "the downlink never reached the client");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = release.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    Ok(())
}

/// A home that holds no park refuses **before** the client carrier is upgraded,
/// so the edge still has the choice to serve the client itself. That refusal is
/// now the ordinary case: fresh sessions are never created over the mesh.
#[tokio::test]
async fn edge_serves_locally_when_the_home_reports_no_session() -> Result<()> {
    let (harness, _home) =
        EdgeHarness::with_credentials("beerloga", "edge-secret", HomeAnswer::NoSession).await;

    assert!(
        harness.open_relay().await.is_none(),
        "a NoSession refusal must leave the edge free to serve a fresh local session",
    );
    let rendered = harness.cluster.metrics.render_prometheus();
    assert!(
        rendered.lines().any(|line| {
            line.starts_with("outline_ss_mesh_relay_opened_total{outcome=\"refused\"}")
                && line.ends_with(" 1")
        }),
        "an explicit refusal must be counted apart from an unreachable home:\n{rendered}",
    );
    Ok(())
}

/// A refused relay must never echo the id the client presented.
///
/// The session is served here now, and this node parks under its *own* freshly
/// minted id. Echoing the foreign one back would send every reconnect to the
/// home that just refused it, be refused again, and be served locally again —
/// an XHTTP or WS session that can never resume, forever.
///
/// Covers the axum WS upgrade and the h3 extended-CONNECT upgrade, which both
/// resolve their response echo through [`ss_edge_echo`].
#[tokio::test]
async fn a_refused_relay_echoes_a_local_id_on_the_ws_and_h3_edges() -> Result<()> {
    let (harness, _home) =
        EdgeHarness::with_credentials("beerloga", "edge-secret", HomeAnswer::NoSession).await;
    let edge = harness.open_relay().await;
    assert!(edge.is_none(), "the fixture must actually refuse, or this proves nothing");

    let local = harness.local_resume();
    let echo = ss_edge_echo(edge.as_ref(), &local);
    let echoed = echo
        .session_id
        .expect("a resume-capable client must be told an id it can come back with");
    assert_ne!(
        echoed, harness.session_id,
        "a refused relay must not echo the foreign id the client presented",
    );
    assert_eq!(
        Some(echoed),
        local.issued_session_id,
        "the echoed id must be the one this node will park under",
    );
    Ok(())
}

/// The XHTTP twin of the test above: both XHTTP entry points (axum h1/h2 and h3)
/// record and echo whatever [`XhttpEdge::issued_id`] returns, so a refused relay
/// must put the locally minted id into the registry slot as well as on the wire.
#[tokio::test]
async fn a_refused_relay_echoes_a_local_id_on_the_xhttp_edges() -> Result<()> {
    let (harness, _home) =
        EdgeHarness::with_credentials("beerloga", "edge-secret", HomeAnswer::NoSession).await;
    let edge = XhttpEdge { ss: harness.open_relay().await, v4: None };
    assert!(edge.ss.is_none(), "the fixture must actually refuse, or this proves nothing");

    let local = harness.local_resume();
    assert!(
        edge.relayed_echo().is_none(),
        "a refused relay leaves the handler's own echo in force",
    );
    let issued = edge.issued_id(&local);
    assert_ne!(
        issued,
        Some(harness.session_id),
        "a refused relay must not record the foreign id the client presented",
    );
    assert_eq!(
        issued, local.issued_session_id,
        "the recorded id must be the one this node will park under",
    );
    Ok(())
}

/// An admitted relay echoes the presented id — and never confirms v2.
///
/// The home replays its unacked downlink suffix as undelimited plaintext at the
/// head of the mesh body, which the edge cannot wrap in the framed `ORDR` reply
/// a v2 client expects. Confirming v2 anyway would make the client parse those
/// payload bytes as a frame header and kill the session. v1 still rides through:
/// the edge re-emits the home's acked uplink offset itself.
#[tokio::test]
async fn an_admitted_relay_echoes_continuity_but_never_confirms_symmetric_replay() -> Result<()> {
    let (harness, _home) = EdgeHarness::with_credentials(
        "beerloga",
        "edge-secret",
        HomeAnswer::Park { acked_uplink: 0 },
    )
    .await;
    let edge = harness.open_relay().await.expect("the home holds a park");

    let local = harness.local_resume();
    assert!(
        local.symmetric_replay_requested,
        "the fixture must locally negotiate v2, or the assertions below are vacuous",
    );

    // WS / h3.
    let echo = ss_edge_echo(Some(&edge), &local);
    assert_eq!(
        echo.session_id,
        Some(harness.session_id),
        "continuity: the home parks under the id the client presented",
    );
    assert!(echo.ack_prefix, "v1 rides through — the edge re-emits the home's acked offset");
    assert!(
        !echo.symmetric_replay,
        "v2 cannot be honoured over the mesh, so it is not confirmed"
    );

    // Both XHTTP entry points, which answer with the same echo.
    let xhttp = XhttpEdge { ss: Some(edge), v4: None };
    let relayed = xhttp
        .relayed_echo()
        .expect("an admitted relay answers with the mesh echo, not the local negotiation");
    assert!(
        !relayed.symmetric_replay,
        "the XHTTP echo must not confirm v2 either — it is built from the mesh's answer",
    );
    assert_eq!(
        xhttp.issued_id(&local),
        Some(harness.session_id),
        "the id recorded on the XHTTP session is the id echoed",
    );
    Ok(())
}

/// Parking is a home concern: the edge holds no upstream socket to park, and a
/// park here would compete with the home's own for the same id.
#[tokio::test]
async fn edge_never_parks_a_relayed_session() -> Result<()> {
    let (harness, mut home) = EdgeHarness::with_credentials(
        "beerloga",
        "edge-secret",
        HomeAnswer::Park { acked_uplink: 0 },
    )
    .await;
    let mut edge = harness.open_relay().await.expect("the home holds a park");
    // Deliberately hand the relayed session an issued id, which `edge_upstream`
    // never does: with that field empty the park path bails before it ever looks
    // at the upstream, so the test would pass even with the mesh guard gone.
    assert!(
        edge.resume.issued_session_id.is_none(),
        "a relayed session mints no local id of its own",
    );
    edge.resume.issued_session_id = Some(harness.session_id);

    let (writer_alive, _writer_gone) = oneshot::channel();
    // No idle step: the script ends, which is the client disconnecting.
    let socket = MockWs::new(
        VecDeque::from_iter([Step::Binary(ss_frame_with_payload(
            &harness.user,
            unreachable_target(),
            b"x",
        )?)]),
        writer_alive,
    );
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        run_tcp_relay::<MockWs>(
            socket,
            &harness.server,
            &harness.route,
            edge.resume,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 40404))),
            None,
            edge.source,
        ),
    )
    .await
    .expect("a relayed session must tear down, not hang");

    assert_eq!(
        harness.local_registry_size(),
        0,
        "the edge must not park a session whose upstream lives on the home",
    );
    assert!(
        !harness.registry.has_park(harness.session_id),
        "least of all under the id the home parks it with",
    );
    // The uplink still reached the home before the teardown.
    assert_eq!(home.upstream_received(1).await, b"x");
    Ok(())
}

/// The home's acked-uplink offset is not the edge's to act on — it holds none of
/// the previous carrier's request body. It belongs to the client, which does,
/// so the edge re-emits it as the Ack-Prefix v1 frame under its own key. Without
/// this the client would replay from the wrong offset across a node switch.
#[tokio::test]
async fn edge_forwards_the_homes_acked_offset_to_the_client() -> Result<()> {
    let (harness, mut home) = EdgeHarness::with_credentials(
        "beerloga",
        "edge-secret",
        HomeAnswer::Park { acked_uplink: 4096 },
    )
    .await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    assert!(
        edge.resume.ack_prefix_requested,
        "the capability must survive into the relayed session, or the client will \
         misread the control frame as payload",
    );

    let (writer_alive, _writer_gone) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let socket = MockWs::new(
        VecDeque::from_iter([
            Step::Binary(ss_frame_with_payload(&harness.user, unreachable_target(), b"go")?),
            Step::Idle(released),
        ]),
        writer_alive,
    );
    let sent = Arc::clone(&socket.sent);
    let user = harness.user.clone();
    let relay = tokio::spawn(async move {
        let _ = run_tcp_relay::<MockWs>(
            socket,
            &harness.server,
            &harness.route,
            edge.resume,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 40404))),
            None,
            edge.source,
        )
        .await;
    });
    let _ = home.user_frame().await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frames = sent.lock().clone();
        let plaintext = decrypt_downlink(&user, &frames)?;
        if plaintext.len() >= build_v1_payload(0).len() {
            assert_eq!(
                plaintext,
                build_v1_payload(4096).to_vec(),
                "the client must be told how far the home's upstream actually got",
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the edge never emitted the ack-prefix frame"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = release.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    Ok(())
}

/// A client that vanishes mid-session without a Close frame makes `T::recv`
/// error, and the `?` unwinds `run_tcp_relay` past every teardown branch.
/// The spawned upstream→client task must still be cancelled: otherwise it
/// keeps the upstream socket and its `outbound_data_tx` clone alive against
/// a silent-but-open upstream, leaking a task plus two sockets per
/// disconnect with no upper bound.
#[tokio::test]
async fn client_reset_cancels_upstream_relay_task() -> Result<()> {
    let (upstream_addr, _upstream) = spawn_silent_upstream().await?;
    let user = test_user()?;
    let (server, route) = test_contexts(&user);
    let (writer_alive, writer_gone) = oneshot::channel();
    let socket = MockWs::new(
        VecDeque::from_iter([Step::Binary(ss_handshake_frame(&user, upstream_addr)?), Step::Reset]),
        writer_alive,
    );
    let resume = ResumeContext::from_request_headers(&HeaderMap::new(), &server.orphan_registry);

    run_tcp_relay::<MockWs>(socket, &server, &route, resume, None, None, UpstreamSource::Direct)
        .await
        .expect_err("a client reset must surface as an error");

    // The writer task returns only once every clone of the outbound data
    // sender is gone, so its writer half being dropped is proof that the
    // relay task was cancelled rather than detached.
    tokio::time::timeout(Duration::from_secs(5), writer_gone)
        .await
        .map_err(|_| {
            anyhow!(
                "upstream→client relay task outlived the session: it still holds the \
                 outbound data channel open"
            )
        })?
        .ok();
    Ok(())
}

/// The client stream ends without a Close frame (`recv` → `Ok(None)`), so
/// teardown takes the non-park branch that joins the relay task. Against a
/// silent-but-open upstream that join never returns unless the relay is
/// asked to stop first, hanging the whole session future — and with it the
/// carrier task, the upstream socket and the writer task.
#[tokio::test]
async fn client_eof_without_close_does_not_hang_teardown() -> Result<()> {
    let (upstream_addr, _upstream) = spawn_silent_upstream().await?;
    let user = test_user()?;
    let (server, route) = test_contexts(&user);
    let (writer_alive, _writer_gone) = oneshot::channel();
    let socket = MockWs::new(
        VecDeque::from_iter([Step::Binary(ss_handshake_frame(&user, upstream_addr)?)]),
        writer_alive,
    );
    let resume = ResumeContext::from_request_headers(&HeaderMap::new(), &server.orphan_registry);

    tokio::time::timeout(
        Duration::from_secs(5),
        run_tcp_relay::<MockWs>(
            socket,
            &server,
            &route,
            resume,
            None,
            None,
            UpstreamSource::Direct,
        ),
    )
    .await
    .map_err(|_| anyhow!("teardown hung joining the upstream→client relay task"))??;
    Ok(())
}
