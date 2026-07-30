use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use quinn::{Connection, ReadError, ReadToEndError, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::Instant;

use outline_wire::CipherKind;

use super::{
    DownlinkEnd, SpliceEnd, SpliceFault, StreamClose, handle_mesh_connection, needs_stopped_poll,
    splice_end, write_uplink_chunk,
};
use crate::crypto::UserKey;
use crate::metrics::{AppProtocol, Metrics, Protocol};
use crate::protocol::TargetAddr;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CloseIntent, CloseReason, MeshEndpoint, MeshFraming, MeshIdentity, MeshPeerPool, MeshProtocol,
    OPEN_ACK_ACCEPTED, OpenHeader, UPSTREAM_ACK_FRAME_LEN, UpstreamAckFrame, UserFrame,
    read_datagram, write_datagram,
};
use crate::server::dns_cache::DnsCache;
use crate::server::nat::{NatKey, NatTable, ServerSessionId};
use crate::server::replay::ReplayStore;
use crate::server::resumption::downlink_ring::DownlinkRing;
use crate::server::resumption::{
    OrphanRegistry, Parked, ParkedSsUdpStream, ParkedTcp, ResumeOutcome, ResumptionConfig,
    SessionId, TcpProtocolContext,
};
use crate::server::state::{Services, UdpServices};
use crate::server::tests::sample_config;
use crate::server::transport::XhttpRegistryLimits;

fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))))
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

// ── Home-side accept loop ──────────────────────────────────────────────────────

/// A home-side mesh runtime over a fresh loopback endpoint, with a
/// `relay_cap`-slot relayed-session cap and `registry` as its park store: enough
/// for `handle_mesh_connection` to admit relay streams and splice them. No route
/// tables — the home resolves none, the request path being a local matter of the
/// edge.
fn home_runtime(
    psk: &[u8],
    relay_cap: usize,
    registry: Arc<OrphanRegistry>,
) -> (Arc<ClusterCtx>, Arc<Services>) {
    let metrics = test_metrics();
    let endpoint = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let cluster = Arc::new(ClusterCtx {
        pool: Arc::new(MeshPeerPool::new(endpoint.clone(), HashMap::new(), 8)),
        endpoint,
        relay_budget: Duration::from_secs(5),
        relay_permits: Arc::new(Semaphore::new(relay_cap)),
        metrics: Arc::clone(&metrics),
    });
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        Some(registry),
        16,
        XhttpRegistryLimits::unbounded(),
    ));
    (cluster, services)
}

/// Connects an edge to `home` and hands back both ends of the mesh connection.
/// Both sides must be driven together: the home only progresses once it accepts.
async fn connect_edge(home: &MeshEndpoint, edge: &MeshEndpoint) -> (Connection, Connection) {
    let home_addr = home.local_addr().unwrap();
    tokio::join!(async { home.accept().await.unwrap().unwrap() }, async {
        edge.connect(home_addr).await.unwrap()
    })
}

/// Opens a relay stream and writes `open` as its length-prefixed OPEN header —
/// what `open_relay_stream` does on the edge, inlined here so a test can also
/// send a header this build cannot parse.
async fn open_relay(conn: &Connection, open: &[u8]) -> (SendStream, RecvStream) {
    let (mut send, recv) = conn.open_bi().await.unwrap();
    send.write_all(&(open.len() as u32).to_be_bytes()).await.unwrap();
    send.write_all(open).await.unwrap();
    (send, recv)
}

/// Polls `outline_ss_mesh_relay_active` until it reads `want`, panicking after
/// 5 s. The gauge is the observable "this relay was admitted and is being
/// served" — it rises inside `serve_relayed` and falls when that returns.
async fn wait_for_active_relays(metrics: &Arc<Metrics>, want: u32) {
    let needle = format!("outline_ss_mesh_relay_active {want}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rendered = metrics.render_prometheus();
        if rendered.lines().any(|line| line == needle) {
            return;
        }
        assert!(Instant::now() < deadline, "active relays never reached {want}:\n{rendered}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A relay stream whose OPEN this build cannot parse (a peer mid rolling
/// upgrade) is a *per-stream* failure, not a connection one: the QUIC
/// connection stays live, and the relays already riding it depend on the loop
/// staying up. So the loop must drop that one stream and keep accepting.
#[tokio::test]
async fn an_unparsable_open_header_does_not_stop_the_accept_loop() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([1u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // Version 0xFF: a header this build rejects, exactly as a peer on a newer
    // wire version would send. Waiting for the home to close the stream pins the
    // ordering — the loop has seen this failure before the next stream opens.
    let (_bad_send, mut bad_recv) = open_relay(&harness.edge_conn, &[0xFF; 8]).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), bad_recv.read_to_end(64))
        .await
        .expect("the home must close a relay stream whose OPEN it cannot parse");

    // A well-formed relay opened afterwards must still be served.
    let _session = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    wait_for_active_relays(harness.metrics(), 1).await;
    assert!(!harness.home.is_finished(), "the accept loop must outlive a per-stream failure");
}

/// v4 is retired. A straggler edge still sending a v4 OPEN must be refused
/// explicitly — a reset on both halves, before any ack — so it degrades to
/// serving its client a fresh local session. Version skew costs continuity, not
/// traffic; and the connection carrying it keeps serving every other relay.
#[tokio::test]
async fn a_v4_open_is_refused_and_the_edge_serves_locally() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([2u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // A well-formed OPEN of this build, re-stamped with the retired version
    // byte: the home must not misparse it into some other shape.
    let mut open = v5_header(id).encode();
    open[0] = 4;
    let (_send, mut recv) = open_relay(&harness.edge_conn, &open).await;
    let error = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
        .await
        .expect("a v4 OPEN must be answered, not left hanging")
        .expect_err("the home must reset a relay stream it cannot parse");
    let abort = VarInt::from_u32(CloseReason::Abort.code());
    assert!(
        matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == abort),
        "expected an Abort reset, got {error:?}",
    );

    // The park is untouched, so the session still resumes on a peer that speaks
    // the current version — the refusal cost continuity on that carrier, nothing
    // more.
    assert!(harness.registry().has_park(id), "a refused v4 OPEN must not consume the park");
    let _session = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    assert!(!harness.home.is_finished(), "refusing a v4 OPEN must not stop the accept loop");
}

/// The one exit condition: when the peer closes the QUIC connection, the accept
/// loop must return rather than spin on a dead connection.
#[tokio::test]
async fn a_closed_connection_ends_the_accept_loop() {
    let psk = b"mesh-accept-close-psk";
    let (cluster, services) = home_runtime(psk, 8, test_registry());
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services));
    edge_conn.close(0u32.into(), b"edge done");

    tokio::time::timeout(Duration::from_secs(5), home)
        .await
        .expect("a closed connection must end the accept loop")
        .unwrap();
    drop(edge);
}

/// Bounded resources: a home serves at most `relay_permits` relayed sessions at
/// once. A stream arriving past the cap is refused outright — both halves reset
/// with [`CloseReason::Capacity`], so the edge fails fast and serves its client
/// locally — instead of spawning one more unbounded relay.
#[tokio::test]
async fn relay_streams_past_the_cap_are_refused() {
    let harness = MeshHomeHarness::with_registry_and_cap(test_registry(), 1).await;
    let first_id = SessionId::from_bytes([3u8; 16]);
    let second_id = SessionId::from_bytes([4u8; 16]);
    let _first_upstream = park_test_session(harness.registry(), first_id, "beerloga").await;
    let _second_upstream = park_test_session(harness.registry(), second_id, "beerloga").await;

    // The single permit goes to the first relay, which idles on its parked
    // upstream and holds the permit for the rest of the test.
    let _first = harness.serve_v5_ok(v5_header(first_id), "beerloga").await;
    wait_for_active_relays(harness.metrics(), 1).await;

    let (_send, mut recv) = open_relay(&harness.edge_conn, &v5_header(second_id).encode()).await;
    let error = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
        .await
        .expect("a refused relay must be answered, not left hanging")
        .expect_err("the home must reset a relay stream it has no capacity for");
    let capacity = VarInt::from_u32(CloseReason::Capacity.code());
    assert!(
        matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == capacity),
        "expected a Capacity reset, got {error:?}",
    );
    // Refused, not served: the active-relay gauge never counted a second one.
    let rendered = harness.metrics().render_prometheus();
    assert!(
        rendered.lines().any(|line| line == "outline_ss_mesh_relay_active 1"),
        "a refused relay must not be spawned:\n{rendered}",
    );
    assert!(
        harness.registry().has_park(second_id),
        "a relay refused for capacity must leave its park for a later carrier",
    );
    assert!(!harness.home.is_finished(), "refusing a relay must not stop the accept loop");
}

// ── Home-side v5 (edge-terminated crypto) ─────────────────────────────────────

/// A resumption config with the feature and the v2 downlink ring both on — the
/// shape a home needs to hold parks and replay their unacked suffix.
fn enabled_resumption() -> ResumptionConfig {
    ResumptionConfig {
        enabled: true,
        downlink_buffer_bytes: 64 * 1024,
        ..ResumptionConfig::defaults_disabled()
    }
}

fn test_registry() -> Arc<OrphanRegistry> {
    Arc::new(OrphanRegistry::new(enabled_resumption(), test_metrics()))
}

/// A registry with resumption on but the v2 downlink ring off — the *default*
/// shape, since `downlink_buffer_bytes` defaults to `0`. Nothing here can replay
/// a chunk the home dropped, so any byte lost between two carriers is lost for
/// good; the continuity tests below run against this registry deliberately.
fn ringless_registry() -> Arc<OrphanRegistry> {
    Arc::new(OrphanRegistry::new(
        ResumptionConfig {
            enabled: true,
            downlink_buffer_bytes: 0,
            ..ResumptionConfig::defaults_disabled()
        },
        test_metrics(),
    ))
}

/// The far end of a parked session's upstream socket, standing in for the
/// target server. Held by the test so the socket stays open — dropping it would
/// EOF the parked upstream the home is about to splice onto.
struct TestUpstream {
    peer: tokio::net::TcpStream,
}

impl TestUpstream {
    /// Reads exactly `n` bytes the home wrote to the parked upstream.
    async fn read(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), self.peer.read_exact(&mut buf))
            .await
            .expect("the upstream must receive the relayed bytes")
            .expect("reading the relayed uplink");
        buf
    }

    /// Whether the target *eventually* sees the end of the request body: reads
    /// until the socket returns zero bytes, i.e. the home half-closed (or
    /// closed) it. Bytes still in flight are drained rather than answered with
    /// "no EOF" — the question is whether this socket ever EOFs, not whether
    /// one is pending at this instant. `false` on a timeout — the socket is
    /// still open — or on a read error.
    async fn saw_eof(&mut self) -> bool {
        let drain = async {
            let mut buf = [0u8; 4096];
            loop {
                match self.peer.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .unwrap_or(false)
    }

    /// Writes `data` as if the target server answered.
    async fn write(&mut self, data: &[u8]) {
        self.peer
            .write_all(data)
            .await
            .expect("writing the upstream downlink");
    }

    /// Kills the upstream with an RST, as a target that dies mid-response does.
    /// `SO_LINGER = 0` turns the close into a reset, so the home's next upstream
    /// read fails instead of reading a clean EOF. Set through `socket2` on the
    /// borrowed fd — tokio's own setter is deprecated, and a zero linger cannot
    /// block on close anyway (there is nothing to flush).
    fn abort(self) {
        let socket = socket2::SockRef::from(&self.peer);
        socket
            .set_linger(Some(Duration::ZERO))
            .expect("setting SO_LINGER on the test upstream");
        drop(self);
    }

    /// Splits the far end so a test can drive both directions at once: a task
    /// that keeps the target answering, and the test body reading what the home
    /// relayed onto the socket.
    fn split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        self.peer.into_split()
    }
}

/// 4 MiB of a self-describing pattern. Larger than the mesh stream's receive
/// window (quinn's 1.25 MB default), so a home writing it to an edge that is not
/// reading is guaranteed to be *inside* a write when the test intervenes — and
/// self-describing, so a dropped chunk surfaces as a content mismatch rather
/// than a short read.
fn flood_payload(seed: u8) -> Vec<u8> {
    (0..4 * 1024 * 1024).map(|i| (i % 251) as u8 ^ seed).collect()
}

/// Parks a TCP session under `id` owned by `owner`, returning the far end of
/// its upstream socket. Mirrors what the relay parks on a carrier drop.
async fn park_test_session(registry: &OrphanRegistry, id: SessionId, owner: &str) -> TestUpstream {
    park_parked_tcp(registry, id, owner, None, None).await
}

/// Like [`park_test_session`] but with a v2 downlink ring already holding
/// `already_sent` — the plaintext the session had emitted before the carrier
/// died, which the next resume replays the unacked suffix of.
async fn park_test_session_with_ring(
    registry: &OrphanRegistry,
    id: SessionId,
    owner: &str,
    already_sent: &[u8],
) -> TestUpstream {
    let ring = Arc::new(parking_lot::Mutex::new(DownlinkRing::new(64 * 1024)));
    ring.lock().push(already_sent);
    park_parked_tcp(registry, id, owner, Some(ring), None).await
}

/// Send-buffer size, in bytes, that forces the home's upstream writes to be
/// *partial*: well under the splice's 64 KiB chunk, so every chunk needs several
/// writes and a cancellation lands in the middle of one. Without this the kernel
/// swallows a whole chunk at a time and the interesting state never occurs.
const TINY_SOCKET_BUFFER: usize = 16 * 1024;

/// Like [`park_test_session`] but with the upstream socket's buffers shrunk to
/// [`TINY_SOCKET_BUFFER`], so a flooded uplink blocks part-way through a chunk.
async fn park_test_session_with_tiny_buffers(
    registry: &OrphanRegistry,
    id: SessionId,
    owner: &str,
) -> TestUpstream {
    park_parked_tcp(registry, id, owner, None, Some(TINY_SOCKET_BUFFER)).await
}

async fn park_parked_tcp(
    registry: &OrphanRegistry,
    id: SessionId,
    owner: &str,
    downlink_ring: Option<Arc<parking_lot::Mutex<DownlinkRing>>>,
    socket_buffer: Option<usize>,
) -> TestUpstream {
    let listener = tokio::net::TcpListener::bind(loopback()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (upstream, peer) = tokio::join!(
        async { listener.accept().await.unwrap().0 },
        tokio::net::TcpStream::connect(addr),
    );
    let peer = peer.unwrap();
    if let Some(size) = socket_buffer {
        for socket in [socket2::SockRef::from(&upstream), socket2::SockRef::from(&peer)] {
            socket
                .set_send_buffer_size(size)
                .expect("shrinking the test socket send buffer");
            socket
                .set_recv_buffer_size(size)
                .expect("shrinking the test socket recv buffer");
        }
    }
    let (upstream_reader, upstream_writer) = upstream.into_split();
    let metrics = test_metrics();
    let user = UserKey::new(owner, "relay-password", None, CipherKind::Chacha20IetfPoly1305, None)
        .unwrap();
    let user_id = user.id_arc();
    registry.park(
        id,
        Parked::Tcp(ParkedTcp {
            upstream_writer,
            upstream_reader,
            target_display: Arc::from("example.com:443"),
            owner: Arc::clone(&user_id),
            protocol_context: TcpProtocolContext::Ss(user),
            user_counters: metrics.user_counters(&user_id),
            upstream_guard: metrics.open_tcp_upstream_connection(
                user_id,
                Protocol::Http3,
                AppProtocol::Shadowsocks,
            ),
            upstream_bytes_acked: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            downlink_ring,
        }),
    );
    TestUpstream { peer }
}

/// Waits until `id` is parked again, panicking after 10 s. The re-park happens
/// on the home's own schedule once the mesh carrier ends, so every test that
/// resumes a session twice has to wait for it rather than assume it.
async fn wait_for_park(registry: &OrphanRegistry, id: SessionId) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !registry.has_park(id) {
        assert!(Instant::now() < deadline, "the home never re-parked the relayed session");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// An OPEN header for a TCP-framed relayed session under `id`. Shadowsocks,
/// matching what [`park_test_session`] parks (`TcpProtocolContext::Ss`).
fn v5_header(id: SessionId) -> OpenHeader {
    OpenHeader {
        framing: MeshFraming::Tcp,
        protocol: MeshProtocol::Ss,
        session_id: *id.as_bytes(),
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    }
}

/// What an edge observes from a relay attempt: whether the home acked, and
/// the reason it eventually closed the stream with (if any).
struct V5Outcome {
    acked: bool,
    close_reason: Option<CloseReason>,
}

impl V5Outcome {
    fn acked(&self) -> bool {
        self.acked
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }
}

/// A live relay: the edge's half of an admitted, spliced session.
struct V5Session {
    send: SendStream,
    recv: RecvStream,
    /// What the home's `UpstreamAckFrame` reported at setup, or `0` when the
    /// OPEN did not advertise the ACK-PREFIX capability (no frame is sent then).
    acked_uplink_offset: u64,
}

impl V5Session {
    /// Writes plaintext toward the home, as an edge does once it has decrypted
    /// a client frame.
    async fn edge_write(&mut self, data: &[u8]) {
        self.send
            .write_all(data)
            .await
            .expect("writing plaintext to the home");
    }

    /// How far the home said its upstream socket had actually got when this
    /// carrier took over the session.
    fn acked_uplink_offset(&self) -> u64 {
        self.acked_uplink_offset
    }

    /// Replays a request body the edge still holds, skipping the prefix the
    /// upstream already took — what an edge does with the acked offset on a
    /// resume.
    async fn edge_write_from_offset(&mut self, data: &[u8], acked: u64) {
        self.edge_write(&data[acked as usize..]).await;
    }

    /// Reads exactly `n` plaintext bytes the home relayed back.
    async fn edge_read(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), self.recv.read_exact(&mut buf))
            .await
            .expect("the home must relay the downlink")
            .expect("reading the relayed downlink");
        buf
    }

    /// Ends the edge's half as a carrier switch does — a bare FIN, no close
    /// intent — then waits for the home to close its own. A carrier switch is a
    /// failure-free end, so the home must answer it with a FIN rather than a
    /// reset.
    async fn close_with_carrier_ended(mut self) {
        self.send.finish().expect("finishing the edge half");
        tokio::time::timeout(Duration::from_secs(5), self.recv.read_to_end(4096))
            .await
            .expect("the home must close its half once the edge finishes")
            .expect("a carrier switch must be a clean FIN, not a reset");
    }

    /// Ends the edge's half as a client that is done for good does: the FIN
    /// still carries every uplink byte, and the `STOP_SENDING` on the downlink
    /// half carries the [`CloseIntent::ClientDone`] code that says not to expect
    /// this client back.
    fn close_with_client_done(mut self) {
        self.send.finish().expect("finishing the edge half");
        self.recv
            .stop(VarInt::from_u32(CloseIntent::ClientDone.code()))
            .expect("stopping the home's downlink half");
    }

    /// Aborts the edge's uplink half without a FIN, as a client carrier that
    /// dies mid-request does. The home's next mesh read then fails — an uplink
    /// fault, deterministically and without touching the upstream.
    fn edge_reset(&mut self) {
        self.send
            .reset(VarInt::from_u32(CloseReason::Abort.code()))
            .expect("resetting the edge uplink half");
    }

    /// Ends the edge's uplink half with a FIN, as a carrier switch does, without
    /// waiting for the home — the caller goes on to read the downlink.
    fn edge_switch(&mut self) {
        self.send.finish().expect("finishing the edge half");
    }

    /// Reads the home's half to its end: the bytes it relayed, or the reason it
    /// reset instead of finishing.
    async fn drain(mut self, limit: usize) -> Result<Vec<u8>, CloseReason> {
        let ended = tokio::time::timeout(Duration::from_secs(10), self.recv.read_to_end(limit))
            .await
            .expect("the home must end the relay, not leave it hanging");
        match ended {
            Ok(bytes) => Ok(bytes),
            Err(ReadToEndError::Read(error)) => Err(reset_reason_read(&error)),
            Err(other) => panic!("unexpected read-to-end failure: {other:?}"),
        }
    }

    /// Waits for the home to end the stream and reports how: `None` for a clean
    /// FIN, `Some(reason)` for a reset.
    async fn end_reason(self) -> Option<CloseReason> {
        self.drain(4096).await.err()
    }

    /// Writes one length-framed datagram toward the home, as a v5 SS-UDP edge
    /// does once it has opened a client packet: the SOCKS5-wrapped body, with no
    /// crypto left on it.
    async fn edge_send_datagram(&mut self, datagram: &[u8]) {
        write_datagram(&mut self.send, datagram)
            .await
            .expect("writing a relayed datagram to the home");
    }

    /// Reads one datagram the home relayed back, failing the test if none comes.
    async fn edge_recv_datagram(&mut self) -> Vec<u8> {
        self.edge_recv_datagram_within(Duration::from_secs(5))
            .await
            .expect("the home must relay the upstream response")
    }

    /// Reads one datagram if the home sends one inside `wait`. `None` covers
    /// both "nothing arrived" and "the home ended the stream" — either way no
    /// response reached this carrier.
    async fn edge_recv_datagram_within(&mut self, wait: Duration) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        match tokio::time::timeout(wait, read_datagram(&mut self.recv, &mut buf)).await {
            Ok(Ok(Some(_))) => Some(buf),
            Ok(Ok(None)) => None,
            Ok(Err(error)) => panic!("reading a relayed datagram: {error}"),
            Err(_elapsed) => None,
        }
    }
}

/// An OPEN header for a **datagram**-framed relayed session under `id`. Always
/// Shadowsocks: an SS-UDP park has no other way to be minted.
fn v5_udp_header(id: SessionId) -> OpenHeader {
    OpenHeader {
        framing: MeshFraming::Udp,
        ..v5_header(id)
    }
}

/// A UDP echo target standing in for the internet: it bounces every datagram
/// back and records the address it came from, which is how a test tells *which*
/// NAT socket carried it — a reattached parked entry or a freshly created one.
struct UdpEcho {
    addr: SocketAddr,
    sources: mpsc::UnboundedReceiver<SocketAddr>,
    _task: crate::server::abort::AbortOnDrop<()>,
}

impl UdpEcho {
    /// The source address of the next datagram this target receives.
    async fn next_source(&mut self) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(5), self.sources.recv())
            .await
            .expect("the target must receive a datagram")
            .expect("the echo task outlives the test")
    }
}

async fn spawn_udp_echo() -> UdpEcho {
    let socket = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, sources) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let _ = tx.send(from);
            let _ = socket.send_to(&buf[..len], from).await;
        }
    });
    UdpEcho {
        addr,
        sources,
        _task: crate::server::abort::AbortOnDrop::new(task),
    }
}

/// The SOCKS5-wrapped body of an SS-UDP packet: `TargetAddr || payload`. This is
/// exactly what a v5 edge forwards once it has stripped the client's crypto, and
/// what the home routes on.
fn socks5_wrap(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut wrapped = TargetAddr::from(target)
        .to_wire_bytes()
        .expect("a socket address always encodes");
    wrapped.extend_from_slice(payload);
    wrapped
}

/// The NAT key an SS-UDP session under `id` owns for `target`. `scope` is what
/// keeps two sessions to the same target on separate entries, and it is taken
/// from the session — never from a datagram.
fn udp_nat_key(owner: &str, id: SessionId, target: SocketAddr) -> NatKey {
    NatKey {
        user_id: Arc::from(owner),
        fwmark: None,
        target,
        scope: Some(*id.as_bytes()),
    }
}

/// Parks an SS-UDP session under `id` with a live NAT entry per target, as a
/// carrier drop leaves behind: the entries stay in the table (detached, still
/// ageing) and the park keeps only their keys.
async fn park_test_udp_session(
    harness: &MeshHomeHarness,
    id: SessionId,
    owner: &str,
    targets: &[SocketAddr],
) -> Vec<NatKey> {
    let keys: Vec<NatKey> = targets.iter().map(|t| udp_nat_key(owner, id, *t)).collect();
    for key in &keys {
        harness
            .nat_table()
            .get_or_create(key.clone(), ServerSessionId::Generate, Arc::clone(harness.metrics()))
            .await
            .expect("binding a test NAT entry");
    }
    harness.registry().park(
        id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: keys.clone(),
            owner: Arc::from(owner),
        }),
    );
    keys
}

/// The source port of the NAT socket behind `key` — the observable identity of
/// the entry, and exactly what a target sees. The port alone, because the socket
/// is wildcard-bound (`0.0.0.0`) while the target reads a concrete source IP.
fn nat_socket_port(harness: &MeshHomeHarness, key: &NatKey) -> u16 {
    harness
        .nat_table()
        .try_get(key)
        .expect("the NAT entry is live")
        .socket()
        .local_addr()
        .expect("a bound NAT socket has a local address")
        .port()
}

/// A home node running the real mesh accept loop, plus an edge connection to
/// drive it with. Every header goes over a real mesh QUIC stream into
/// `handle_mesh_connection`, so these tests exercise the live accept path rather
/// than calling the splice directly.
struct MeshHomeHarness {
    /// Held so the home endpoint and its relay-permit pool outlive the harness.
    _cluster: Arc<ClusterCtx>,
    /// The same bundle the accept loop serves with, so a UDP test can reach the
    /// NAT table the splice routes through.
    services: Arc<Services>,
    registry: Arc<OrphanRegistry>,
    metrics: Arc<Metrics>,
    /// Held so the edge socket stays bound for the harness's lifetime.
    _edge_endpoint: MeshEndpoint,
    edge_conn: Connection,
    home: tokio::task::JoinHandle<()>,
}

impl MeshHomeHarness {
    async fn new() -> Self {
        Self::with_registry(test_registry()).await
    }

    async fn with_registry(registry: Arc<OrphanRegistry>) -> Self {
        Self::with_registry_and_cap(registry, 8).await
    }

    async fn with_registry_and_cap(registry: Arc<OrphanRegistry>, relay_cap: usize) -> Self {
        let psk = b"mesh-home-psk";
        let (cluster, services) = home_runtime(psk, relay_cap, Arc::clone(&registry));
        let edge_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge_endpoint).await;
        let metrics = Arc::clone(&cluster.metrics);
        let home = tokio::spawn(handle_mesh_connection(
            home_conn,
            Arc::clone(&cluster),
            Arc::clone(&services),
        ));
        Self {
            _cluster: cluster,
            services,
            registry,
            metrics,
            _edge_endpoint: edge_endpoint,
            edge_conn,
            home,
        }
    }

    fn registry(&self) -> &Arc<OrphanRegistry> {
        &self.registry
    }

    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    fn nat_table(&self) -> &Arc<NatTable> {
        &self.services.udp_server.nat_table
    }

    /// Opens a relay and reports the outcome, sending the USER frame only if
    /// the home acked (as a real edge does).
    async fn serve_v5(&self, header: OpenHeader) -> V5Outcome {
        self.serve_v5_with_user(header, "beerloga").await
    }

    async fn serve_v5_with_user(&self, header: OpenHeader, user: &str) -> V5Outcome {
        self.serve_v5_raw_user(header, &UserFrame { user: user.to_string() }.encode())
            .await
    }

    /// Like [`Self::serve_v5_with_user`] but running `between` in the window the
    /// phase-2 re-probe exists to cover: after the home's ack has been read and
    /// strictly before the USER frame that makes it consume the park. The home
    /// is blocked reading that frame, so whatever `between` does to the registry
    /// is ordered before phase 2 without a sleep.
    async fn serve_v5_between_the_phases(
        &self,
        header: OpenHeader,
        user: &str,
        between: impl Future<Output = ()>,
    ) -> V5Outcome {
        self.serve_v5_raw_user_between(
            header,
            &UserFrame { user: user.to_string() }.encode(),
            between,
        )
        .await
    }

    /// Like [`Self::serve_v5_with_user`] but writing `user_frame` verbatim, so a
    /// test can hand the home a second-phase frame it cannot parse.
    async fn serve_v5_raw_user(&self, header: OpenHeader, user_frame: &[u8]) -> V5Outcome {
        self.serve_v5_raw_user_between(header, user_frame, std::future::ready(()))
            .await
    }

    async fn serve_v5_raw_user_between(
        &self,
        header: OpenHeader,
        user_frame: &[u8],
        between: impl Future<Output = ()>,
    ) -> V5Outcome {
        let (mut send, mut recv) = open_relay(&self.edge_conn, &header.encode()).await;
        let mut ack = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack))
            .await
            .expect("the home must answer a v5 OPEN, not leave it hanging");
        if let Err(error) = read {
            return V5Outcome {
                acked: false,
                close_reason: Some(reset_reason(&error)),
            };
        }
        assert_eq!(ack[0], OPEN_ACK_ACCEPTED, "an ack byte must mark the relay accepted");
        between.await;
        send.write_all(user_frame).await.expect("writing the USER frame");
        let ended = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
            .await
            .expect("the home must resolve phase 2, not leave it hanging");
        let close_reason = match ended {
            Ok(_) => None,
            Err(ReadToEndError::Read(error)) => Some(reset_reason_read(&error)),
            Err(other) => panic!("unexpected read-to-end failure: {other:?}"),
        };
        V5Outcome { acked: true, close_reason }
    }

    /// Opens a v5 relay that must be admitted, returning the spliced session.
    async fn serve_v5_ok(&self, header: OpenHeader, user: &str) -> V5Session {
        let (mut send, mut recv) = open_relay(&self.edge_conn, &header.encode()).await;
        let mut ack = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack))
            .await
            .expect("the home must ack an admitted v5 relay")
            .expect("reading the v5 OPEN ack");
        assert_eq!(ack[0], OPEN_ACK_ACCEPTED);
        send.write_all(&UserFrame { user: user.to_string() }.encode())
            .await
            .expect("writing the USER frame");
        // A real edge reads the continuity prologue it asked for before any
        // downlink byte; the frame is present exactly when the OPEN set the
        // ACK-PREFIX flag.
        let acked_uplink_offset = if header.ack_prefix {
            let mut frame = [0u8; UPSTREAM_ACK_FRAME_LEN];
            tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut frame))
                .await
                .expect("the home must send the upstream-ack frame")
                .expect("reading the upstream-ack frame");
            UpstreamAckFrame::parse(&frame)
                .expect("the upstream-ack frame parses")
                .upstream_acked
        } else {
            0
        };
        V5Session { send, recv, acked_uplink_offset }
    }
}

impl Drop for MeshHomeHarness {
    fn drop(&mut self) {
        self.home.abort();
    }
}

/// The `CloseReason` behind a `quinn` read failure, or `Abort` for any other
/// failure shape (a reset is a reset).
fn reset_reason(error: &quinn::ReadExactError) -> CloseReason {
    match error {
        quinn::ReadExactError::ReadError(error) => reset_reason_read(error),
        quinn::ReadExactError::FinishedEarly(_) => CloseReason::Fin,
    }
}

fn reset_reason_read(error: &ReadError) -> CloseReason {
    match error {
        ReadError::Reset(code) => CloseReason::from_code(
            u32::try_from(code.into_inner()).expect("close reasons fit in a u32"),
        ),
        _ => CloseReason::Abort,
    }
}

#[tokio::test]
async fn has_park_reports_a_committed_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([3u8; 16]);
    assert!(!registry.has_park(id), "no park yet");

    let _upstream = park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id), "a committed park must be visible");
}

#[tokio::test]
async fn has_park_reports_an_in_flight_reservation() {
    // The phase-1 ack must not answer "no session" while a park is still
    // landing — that is the park-miss race `take_for_resume` already guards.
    let registry = test_registry();
    let id = SessionId::from_bytes([4u8; 16]);
    let _reservation = registry.reserve_park(id);

    assert!(registry.has_park(id), "a reserved park must count as present");
}

#[tokio::test]
async fn has_park_does_not_consume_the_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([5u8; 16]);
    let _upstream = park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id));
    assert!(registry.has_park(id), "the probe must be read-only");

    let outcome = registry.take_for_resume(id, "beerloga").await;
    assert!(matches!(outcome, ResumeOutcome::Hit(_)), "the park must still be takeable");
}

#[tokio::test]
async fn v5_home_refuses_when_no_park_exists() {
    let harness = MeshHomeHarness::new().await;

    let outcome = harness.serve_v5(v5_header(SessionId::from_bytes([6u8; 16]))).await;

    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
    assert!(
        !outcome.acked(),
        "the refusal replaces the ack, before the edge upgrades its client"
    );
}

#[tokio::test]
async fn v5_home_refuses_when_the_user_does_not_own_the_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([7u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let outcome = harness.serve_v5_with_user(v5_header(id), "cloud").await;

    assert!(outcome.acked(), "phase 1 cannot know the user yet, so it acks");
    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
}

#[tokio::test]
async fn v5_home_splices_plaintext_to_the_parked_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([8u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    // Uplink: what the edge writes as plaintext reaches the parked upstream verbatim.
    session.edge_write(b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(upstream.read(18).await, b"GET / HTTP/1.1\r\n\r\n");

    // Downlink: the home encrypts nothing — the edge seals it under its own key.
    upstream.write(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert_eq!(session.edge_read(19).await, b"HTTP/1.1 200 OK\r\n\r\n");
}

#[tokio::test]
async fn v5_home_replays_the_ring_suffix_before_new_downlink() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([9u8; 16]);
    // 12 plaintext bytes already sent, client acked the first 5.
    let _upstream =
        park_test_session_with_ring(harness.registry(), id, "beerloga", b"HELLO-WORLD!").await;

    let mut header = v5_header(id);
    header.symmetric_replay = true;
    header.client_down_acked = 5;

    let mut session = harness.serve_v5_ok(header, "beerloga").await;

    assert_eq!(
        session.edge_read(7).await,
        b"-WORLD!",
        "the home replays exactly the unacked suffix, as plaintext"
    );
}

/// Value of the rendered Prometheus counter whose line starts with `prefix`, or
/// `0` when the series was never touched (an untouched counter is not rendered).
fn counter_value(rendered: &str, prefix: &str) -> u64 {
    rendered
        .lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Sum of every rendered series of counter family `family` whose labels name
/// `user`. Zero covers both "registered but never incremented" (rendered as `0`)
/// and "never registered" (not rendered at all) — for a `user`-labelled series
/// the two are the same claim: this node accounted nothing for that user.
fn per_user_total(rendered: &str, family: &str, user: &str) -> u64 {
    let prefix = format!("{family}{{");
    let label = format!("user=\"{user}\"");
    rendered
        .lines()
        .filter(|line| line.starts_with(&prefix) && line.contains(&label))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

/// Polls a mesh counter until it reads `want`, panicking after 5 s. The home
/// increments its downlink counters right after the mesh write returns, which
/// may land just after the edge has already read the datagram.
async fn wait_for_counter(metrics: &Arc<Metrics>, prefix: &str, want: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rendered = metrics.render_prometheus();
        if counter_value(&rendered, prefix) == want {
            return;
        }
        assert!(Instant::now() < deadline, "{prefix} never reached {want}:\n{rendered}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn rejected(rendered: &str, reason: &str) -> u64 {
    counter_value(
        rendered,
        &format!("outline_ss_mesh_relay_rejected_total{{reason=\"{reason}\"}}"),
    )
}

/// Total of `outline_ss_mesh_relay_outcome_total` for `outcome`, across every
/// `close` label it was recorded under.
fn outcome(rendered: &str, outcome: &str) -> u64 {
    let prefix = format!("outline_ss_mesh_relay_outcome_total{{outcome=\"{outcome}\",");
    rendered
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

/// The same series narrowed to one `close` label — the ratio an operator reads
/// to see whether edges emit the close intent at all.
fn outcome_close(rendered: &str, outcome: &str, close: &str) -> u64 {
    counter_value(
        rendered,
        &format!("outline_ss_mesh_relay_outcome_total{{outcome=\"{outcome}\",close=\"{close}\"}}"),
    )
}

/// Parks a session of a kind the TCP splice cannot serve, so a TCP-framed v5
/// OPEN for the same id hits the parked-kind mismatch arm.
fn park_ss_udp_stream(registry: &OrphanRegistry, id: SessionId, owner: &str) {
    registry.park(
        id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: Vec::new(),
            owner: Arc::from(owner),
        }),
    );
}

/// The mirror of [`v5_home_refuses_a_park_of_the_wrong_kind`], now that both
/// framings splice something: a **UDP**-framed OPEN whose id resolves to a
/// byte-stream park must be refused in phase 1 too. The shape check runs in both
/// directions or the new splice would consume TCP parks it cannot serve —
/// exactly the destruction loop the probe exists to prevent, reintroduced from
/// the other side.
#[tokio::test]
async fn v5_home_refuses_udp_framing_on_a_byte_stream_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([20u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let outcome_seen = harness.serve_v5(v5_udp_header(id)).await;

    assert!(!outcome_seen.acked(), "the refusal replaces the ack");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::NoSession));
    assert!(
        harness.registry().has_park(id),
        "a refused UDP relay must leave the park untouched for a servable carrier",
    );
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "park_shape"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 1, "{rendered}");
}

/// A TCP-framed v5 OPEN whose id resolves to a park of another kind must be
/// refused in **phase 1** — before the ack, and critically before
/// `take_for_resume` consumes anything, so the session survives for a carrier
/// this home can serve.
///
/// Earlier this refusal came one phase too late: phase 1 asked only whether *a*
/// park existed, so the park was taken and only then found to be the wrong
/// shape. That was unreachable while every byte-stream carrier parked as
/// `Parked::Tcp`; the VLESS edge makes it reachable, because VLESS multiplexes
/// TCP, UDP and mux onto one carrier and parks three shapes under ids an edge
/// cannot tell apart. The park assertion below is the one that would catch a
/// regression back to the late check — the metric reason alone would not, since
/// both spellings refuse.
#[tokio::test]
async fn v5_home_refuses_a_park_of_the_wrong_kind() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([21u8; 16]);
    park_ss_udp_stream(harness.registry(), id, "beerloga");

    let outcome_seen = harness.serve_v5(v5_header(id)).await;

    assert!(!outcome_seen.acked(), "the refusal replaces the ack");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::NoSession));
    assert!(
        harness.registry().has_park(id),
        "refusing on shape must leave the park for a carrier this home can serve",
    );
    let rendered = harness.metrics().render_prometheus();
    // Counted apart from `no_session`: an expired park and a park this home has
    // no splice for are different problems, and with VLESS on v5 the latter is
    // an ordinary, expected event rather than a symptom.
    assert_eq!(rejected(&rendered, "park_shape"), 1, "{rendered}");
    assert_eq!(rejected(&rendered, "no_session"), 0, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 1, "{rendered}");
}

/// A relayed resume never crosses the proxy-protocol boundary, whatever the
/// user says.
///
/// Both direct resume paths (`transport::tcp` and `transport::vless::tcp`)
/// refuse to reattach an SS carrier to a VLESS-authenticated park and vice
/// versa. The v5 splice must apply the same rule: it became reachable the moment
/// VLESS-TCP edges started speaking v5, because from then on an SS edge and a
/// VLESS edge can present the same id, and phase 2's owner check confines that
/// to one user rather than ruling it out.
///
/// Without the check the home splices the park onto the relay instead of
/// refusing it, so the assertions below fail on both counts: no refusal reason
/// is counted, and the relay is a live `hit`.
#[tokio::test]
async fn v5_home_refuses_a_park_of_another_proxy_protocol() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([41u8; 16]);
    // Parked by the SS path: `TcpProtocolContext::Ss`.
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // Same id, same user, but the edge terminated VLESS.
    let mut header = v5_header(id);
    header.protocol = MeshProtocol::Vless;
    let outcome_seen = harness.serve_v5(header).await;

    // Phase 1 admits it — the park is TCP-shaped and the protocol is not part of
    // that question — so the refusal lands after the ack, like the owner check.
    assert!(outcome_seen.acked(), "the shape question is answered before the protocol one");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    assert!(
        upstream.saw_eof().await,
        "the refused park must not be left half-spliced onto the relay",
    );
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "protocol_mismatch"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "hit"), 0, "{rendered}");
}

/// Accounting completeness: every terminal path through the v5 handler records
/// exactly one outcome, so `outline_ss_mesh_relay_outcome_total` reconciles
/// against the relays this home actually served. A never-working relay went
/// unnoticed in production precisely because it did not.
#[tokio::test]
async fn v5_relay_outcomes_are_counted_on_every_path() {
    let harness = MeshHomeHarness::new().await;

    // Miss: nothing parked under the id.
    let missed = harness.serve_v5(v5_header(SessionId::from_bytes([22u8; 16]))).await;
    assert_eq!(missed.close_reason(), Some(CloseReason::NoSession));

    // Miss: a park exists but belongs to someone else.
    let stolen = SessionId::from_bytes([23u8; 16]);
    let _stolen_upstream = park_test_session(harness.registry(), stolen, "beerloga").await;
    let rejected_owner = harness.serve_v5_with_user(v5_header(stolen), "cloud").await;
    assert_eq!(rejected_owner.close_reason(), Some(CloseReason::NoSession));

    // Hit: the park this user owns is spliced onto the relay. The hit is
    // recorded when the splice ends — that is when its `close` label is known —
    // so the carrier is ended before the counters are read.
    let served = SessionId::from_bytes([24u8; 16]);
    let _served_upstream = park_test_session(harness.registry(), served, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(served), "beerloga").await;
    wait_for_active_relays(harness.metrics(), 1).await;
    session.close_with_carrier_ended().await;
    wait_for_active_relays(harness.metrics(), 0).await;

    let rendered = harness.metrics().render_prometheus();
    assert_eq!(outcome(&rendered, "hit"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 2, "{rendered}");
    assert_eq!(rejected(&rendered, "no_session"), 1, "{rendered}");
    assert_eq!(rejected(&rendered, "unknown_user"), 1, "{rendered}");
}

/// The `close` label is the one number telling an operator whether edges emit
/// the close intent at all, so the two intents must land on different series of
/// `outline_ss_mesh_relay_outcome_total` — and everything that never reached a
/// close must stay out of both.
#[tokio::test]
async fn a_relay_outcome_is_labelled_with_how_its_carrier_closed() {
    let harness = MeshHomeHarness::new().await;

    let switched = SessionId::from_bytes([38u8; 16]);
    let _switched_upstream = park_test_session(harness.registry(), switched, "beerloga").await;
    let carrier = harness.serve_v5_ok(v5_header(switched), "beerloga").await;
    carrier.close_with_carrier_ended().await;
    wait_for_active_relays(harness.metrics(), 0).await;

    let finished = SessionId::from_bytes([39u8; 16]);
    let mut finished_upstream = park_test_session(harness.registry(), finished, "beerloga").await;
    let done = harness.serve_v5_ok(v5_header(finished), "beerloga").await;
    done.close_with_client_done();
    assert!(finished_upstream.saw_eof().await);
    wait_for_active_relays(harness.metrics(), 0).await;

    // A miss never splices, so it has no close to report.
    let missed = harness.serve_v5(v5_header(SessionId::from_bytes([40u8; 16]))).await;
    assert_eq!(missed.close_reason(), Some(CloseReason::NoSession));

    let rendered = harness.metrics().render_prometheus();
    assert_eq!(outcome_close(&rendered, "hit", "carrier_ended"), 1, "{rendered}");
    assert_eq!(outcome_close(&rendered, "hit", "client_done"), 1, "{rendered}");
    assert_eq!(outcome_close(&rendered, "hit", "none"), 0, "{rendered}");
    assert_eq!(outcome_close(&rendered, "miss", "none"), 1, "{rendered}");
}

/// A v5 session must survive more than one carrier switch. The home owns the
/// upstream socket, so when the mesh carrier ends it has to put the session back
/// into the registry under the same id — otherwise the second switch closes the
/// upstream and the client silently loses its connection.
#[tokio::test]
async fn a_v5_session_can_be_resumed_twice() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([25u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // First carrier.
    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    first.edge_write(b"first").await;
    assert_eq!(upstream.read(5).await, b"first");
    upstream.write(b"one").await;
    assert_eq!(first.edge_read(3).await, b"one");
    first.close_with_carrier_ended().await;

    // The home must have re-parked the still-healthy upstream.
    wait_for_park(harness.registry(), id).await;

    // Second carrier: the same upstream socket, still live.
    let mut second = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    second.edge_write(b"second").await;
    assert_eq!(
        upstream.read(6).await,
        b"second",
        "the second carrier must reach the very same upstream socket"
    );
    upstream.write(b"two").await;
    assert_eq!(second.edge_read(3).await, b"two");
    // Each hit is counted as its splice ends, so end the second carrier too.
    second.close_with_carrier_ended().await;
    wait_for_active_relays(harness.metrics(), 0).await;

    let rendered = harness.metrics().render_prometheus();
    assert_eq!(outcome(&rendered, "hit"), 2, "both carriers are hits:\n{rendered}");
}

/// A failure mid-splice must not reach the edge as a graceful FIN. Dropping the
/// mesh send half would `finish` it, and the edge would seal a truncated
/// response to its client as complete — so every failure arm resets instead.
#[tokio::test]
async fn a_failed_splice_does_not_present_as_a_clean_close() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([26u8; 16]);
    let upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    // The target dies with an RST, so the home's upstream read fails.
    upstream.abort();

    assert_eq!(
        session.end_reason().await,
        Some(CloseReason::Abort),
        "a broken upstream must reach the edge as a reset, never as a clean FIN",
    );
}

/// The other half of the contract: a genuine upstream EOF still ends the mesh
/// stream gracefully, so the edge can seal a complete response.
#[tokio::test]
async fn a_clean_upstream_eof_still_finishes_the_relay_stream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([27u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    upstream.write(b"done").await;
    drop(upstream); // ordinary close: FIN, not RST

    assert_eq!(
        session.end_reason().await,
        None,
        "a clean upstream EOF must finish the relay stream, not reset it",
    );
}

/// A stream the downlink already finished must never be reset afterwards. The
/// common shape: the target answers in full and closes, the client is still
/// uploading, so the uplink faults *after* the FIN. quinn does not reject a
/// reset after a finish — it drops whatever is still unacked and queues
/// RESET_STREAM — so resetting here would hand the edge a **complete** response
/// as an abort, the exact harm the reset was added to prevent.
#[tokio::test]
async fn an_uplink_fault_after_a_clean_upstream_eof_still_finishes() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([28u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\ndone";
    upstream.write(response).await;
    drop(upstream); // ordinary close: the response is complete

    // Order the two events: once the edge holds the response the home has
    // written it and looped back into its upstream read, where the FIN is
    // already queued. The sleep covers the scheduling gap between that read
    // returning 0 and the reset below arriving.
    assert_eq!(session.edge_read(response.len()).await, response);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now the edge's client carrier dies without a FIN: the home's next mesh
    // read fails, which is an uplink fault on an already-finished stream.
    session.edge_reset();
    // Give a RESET_STREAM the home should never send time to arrive; reading
    // straight away would race it and pass either way.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        session.drain(4096).await,
        Ok(Vec::new()),
        "a finished stream must stay finished; the edge must not see an abort",
    );
}

/// Bytes already read out of the upstream must not vanish when the carrier
/// switches. `select!` drops the losing future wherever it stands, so a downlink
/// cancelled inside its mesh write would discard a chunk — and with the session
/// re-parked right afterwards and no v2 ring by default, the next carrier would
/// resume a stream with a silent hole. Stopping the pump at a read boundary
/// leaves the unread bytes in the socket, which is exactly what the park hands
/// on: carrier one plus carrier two must reconstruct the payload exactly.
#[tokio::test]
async fn a_carrier_switch_mid_downlink_loses_no_bytes() {
    let registry = ringless_registry();
    let harness = MeshHomeHarness::with_registry(Arc::clone(&registry)).await;
    let id = SessionId::from_bytes([29u8; 16]);
    let upstream = park_test_session(&registry, id, "beerloga").await;
    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    let payload = flood_payload(0x00);
    // The far end only writes here; the home's own read half stays untouched.
    let (_peer_reader, mut peer_writer) = upstream.split();
    let target = {
        let payload = payload.clone();
        tokio::spawn(async move {
            peer_writer
                .write_all(&payload)
                .await
                .expect("the target answers in full");
            peer_writer
        })
    };

    // The edge reads nothing yet, so the home fills the mesh stream's receive
    // window and parks inside `write_all` — the state a plain `select!` would
    // cancel it in.
    tokio::time::sleep(Duration::from_millis(200)).await;
    first.edge_switch();
    let delivered = first
        .drain(payload.len() + 1)
        .await
        .expect("a carrier switch is a clean end, not a reset");
    assert!(delivered.len() < payload.len(), "the switch must land mid-payload");

    // The home must have re-parked the still-healthy upstream.
    wait_for_park(&registry, id).await;

    // Second carrier: the remainder must continue exactly where the first left
    // off — no hole, no duplicate.
    let mut second = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    let rest = second.edge_read(payload.len() - delivered.len()).await;
    assert_eq!(
        [delivered, rest].concat(),
        payload,
        "the two carriers must reconstruct the payload"
    );

    target.await.expect("the target write task must finish");
}

/// `upstream_bytes_acked` must name exactly the bytes the upstream socket took,
/// including at a cancellation point: the uplink pump is dropped where it stands
/// when the downlink faults. Counting a whole chunk only after `write_all`
/// returns reports nothing for a cancelled partial write, and a later ack-prefix
/// replay from that counter would resend a prefix the target already has.
///
/// The far end reads in a slow trickle rather than not at all: that keeps
/// re-opening a small send window, so the home's writes are genuinely partial
/// and the cancellation lands inside one. A far end that never reads leaves the
/// socket flatly full, where even the whole-chunk accounting happens to be right.
#[tokio::test]
async fn a_cancelled_uplink_write_accounts_for_every_byte_the_socket_took() {
    let registry = ringless_registry();
    let harness = MeshHomeHarness::with_registry(Arc::clone(&registry)).await;
    let id = SessionId::from_bytes([30u8; 16]);
    let upstream = park_test_session_with_tiny_buffers(&registry, id, "beerloga").await;
    let V5Session { mut send, mut recv, .. } = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    let (mut peer_reader, mut peer_writer) = upstream.split();
    // The target keeps answering into a mesh stream the edge never reads, so the
    // home's downlink pump sits inside a write that STOP_SENDING can fail.
    let target = tokio::spawn(async move {
        let _ = peer_writer.write_all(&flood_payload(0xff)).await;
        peer_writer
    });
    // The edge floods the uplink, so the home's uplink pump is always writing.
    let edge = tokio::spawn(async move {
        let _ = send.write_all(&flood_payload(0x5a)).await;
        send
    });
    let received = Arc::new(AtomicUsize::new(0));
    let trickle = {
        let received = Arc::clone(&received);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match tokio::time::timeout(Duration::from_millis(500), peer_reader.read(&mut buf))
                    .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return peer_reader,
                    Ok(Ok(n)) => {
                        received.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    },
                }
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // STOP_SENDING fails the home's pending downlink write: a mesh fault, which
    // leaves the upstream healthy and cancels the uplink where it stands.
    recv.stop(VarInt::from_u32(CloseReason::Abort.code()))
        .expect("stopping the edge downlink half");

    wait_for_park(&registry, id).await;
    let ResumeOutcome::Hit(Parked::Tcp(parked)) = registry.take_for_resume(id, "beerloga").await
    else {
        panic!("the re-parked tcp session must be takeable");
    };
    // The uplink pump is gone, so the counter is final. The parked halves stay
    // alive until the trickle has drained the socket — dropping them first would
    // reset the connection and discard the very tail being measured.
    let accounted = parked.upstream_bytes_acked.load(std::sync::atomic::Ordering::Relaxed);
    let _peer_reader = trickle.await.expect("the trickle reader must finish");
    let received = received.load(std::sync::atomic::Ordering::Relaxed);

    assert!(received > 0, "the test must have moved bytes before cancelling");
    assert_eq!(
        accounted, received as u64,
        "upstream_bytes_acked must equal what the upstream socket actually received",
    );

    drop(parked);
    let _ = target.await;
    let _ = edge.await;
}

/// The malformed-USER-frame arm. Deterministic (a zero-length name can never
/// name a park owner, and `read_user_frame` rejects it without waiting), unlike
/// the 5 s timeout arm beside it.
#[tokio::test]
async fn a_malformed_user_frame_is_refused_and_counted() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([31u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let outcome_seen = harness.serve_v5_raw_user(v5_header(id), &[0u8]).await;

    assert!(outcome_seen.acked(), "phase 1 answers before the USER frame is read");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "bad_setup"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "error"), 1, "{rendered}");
}

// ── v5 splice end-state decisions ─────────────────────────────────────────────

/// A stream the downlink pump already finished on upstream EOF must never be
/// reset afterwards, however the splice ended. quinn accepts a reset after a
/// finish — it drops whatever is still unacked and queues RESET_STREAM — so the
/// edge would read a **complete** response as an abort.
///
/// Asserted on the decision rather than over a live mesh: on loopback the FIN is
/// acknowledged within microseconds, after which quinn retires the send stream
/// and swallows the late reset, so an end-to-end test cannot observe the harm.
#[test]
fn a_finished_stream_is_never_reset() {
    let switch = CloseIntent::CarrierEnded;

    let faulted = SpliceFault::mesh(anyhow::anyhow!("the edge carrier died")).into_end();
    assert_eq!(faulted.stream_close(false, switch), StreamClose::Reset(CloseReason::Abort));
    assert_eq!(faulted.stream_close(true, switch), StreamClose::Finish);

    let stalled = SpliceFault::stalled_mesh(anyhow::anyhow!("the edge wedged")).into_end();
    assert_eq!(stalled.stream_close(false, switch), StreamClose::Reset(CloseReason::Budget));
    assert_eq!(stalled.stream_close(true, switch), StreamClose::Finish);

    let graceful = SpliceEnd::Graceful { upstream_healthy: true };
    assert_eq!(graceful.stream_close(false, switch), StreamClose::Finish);
    assert_eq!(graceful.stream_close(true, switch), StreamClose::Finish);
}

/// A `CloseIntent` code must never reach the wire as a stream *reset* code,
/// where `CloseReason::from_code` would read `0x5002` as an `Abort`.
///
/// The intent rides a `STOP_SENDING` applied to this very half, and quinn's
/// `finish()` on a stopped half is a silent no-op — leaving `Drop for
/// SendStream` to reset the stream with the `STOP_SENDING` code it received.
/// The home therefore resets it itself, with `CloseReason::Fin`: the same
/// "nothing more is coming" the finish meant, said in the vocabulary the edge
/// parses resets in.
#[test]
fn a_client_done_close_never_puts_an_intent_code_on_the_wire() {
    let graceful = SpliceEnd::Graceful { upstream_healthy: true };
    assert_eq!(
        graceful.stream_close(false, CloseIntent::ClientDone),
        StreamClose::Reset(CloseReason::Fin),
        "a stopped half must be closed explicitly, not left to quinn's drop",
    );
    assert_eq!(
        graceful.stream_close(false, CloseIntent::CarrierEnded),
        StreamClose::Finish,
        "a bare carrier switch still ends with a plain FIN",
    );
    // A stream the downlink already finished on upstream EOF still wins over
    // everything: resetting it would hand the edge a complete response as an
    // abort.
    assert_eq!(graceful.stream_close(true, CloseIntent::ClientDone), StreamClose::Finish);
}

/// `SendStream::stopped()` inserts a per-stream `Arc<Notify>` into quinn's
/// connection state the first time it polls `Pending`, and only
/// `StreamEvent::Finished`, `StreamEvent::Stopped` or the connection dying take
/// it back out. A reset produces none of those, so polling on a relay that is
/// about to be reset would strand one entry per faulted relay for the life of a
/// pooled — long-lived — mesh connection.
///
/// So the poll is confined to the one end that both needs an answer and finishes
/// the stream that reaps the entry.
#[test]
fn the_stopped_poll_runs_only_where_it_is_both_needed_and_reaped() {
    let healthy = SpliceEnd::Graceful { upstream_healthy: true };
    assert!(
        needs_stopped_poll(&healthy, CloseIntent::CarrierEnded),
        "a bare-FIN switch with a live upstream is the case the intent exists for",
    );
    assert!(
        !needs_stopped_poll(&healthy, CloseIntent::ClientDone),
        "the downlink pump already saw the intent; asking again only leaks",
    );
    assert!(
        !needs_stopped_poll(
            &SpliceEnd::Graceful { upstream_healthy: false },
            CloseIntent::CarrierEnded,
        ),
        "an EOF'd upstream never reparks, and its send half is already finished",
    );
    for faulted in [
        SpliceFault::mesh(anyhow::anyhow!("the edge carrier died")).into_end(),
        SpliceFault::stalled_mesh(anyhow::anyhow!("the edge wedged")).into_end(),
        SpliceFault::upstream(anyhow::anyhow!("rst")).into_end(),
        SpliceFault::stalled_upstream(anyhow::anyhow!("stuck")).into_end(),
    ] {
        assert!(
            !needs_stopped_poll(&faulted, CloseIntent::CarrierEnded),
            "a faulted relay is reset, so an entry inserted here is never reaped",
        );
    }
}

/// The two halves' verdicts merge: the fault decides what the edge sees, while
/// the park decision is the AND of both — an upstream either half found EOF'd or
/// broken must never be handed to a later carrier.
#[test]
fn a_splice_end_merges_both_halves() {
    assert!(matches!(
        splice_end(Ok(()), Ok(DownlinkEnd::Stopped)).end,
        SpliceEnd::Graceful { upstream_healthy: true },
    ));
    assert!(matches!(
        splice_end(Ok(()), Ok(DownlinkEnd::UpstreamEof)).end,
        SpliceEnd::Graceful { upstream_healthy: false },
    ));
    assert!(matches!(
        splice_end(Err(SpliceFault::mesh(anyhow::anyhow!("gone"))), Ok(DownlinkEnd::Stopped)).end,
        SpliceEnd::Faulted {
            upstream_healthy: true,
            reset: CloseReason::Abort,
            ..
        },
    ));
    assert!(matches!(
        splice_end(Err(SpliceFault::mesh(anyhow::anyhow!("gone"))), Ok(DownlinkEnd::UpstreamEof))
            .end,
        SpliceEnd::Faulted { upstream_healthy: false, .. },
    ));
    assert!(matches!(
        splice_end(Ok(()), Err(SpliceFault::upstream(anyhow::anyhow!("rst")))).end,
        SpliceEnd::Faulted {
            upstream_healthy: false,
            reset: CloseReason::Abort,
            ..
        },
    ));
}

/// The splice reports which half finished the mesh stream and which intent its
/// pumps observed, so the end-of-splice decisions read facts the pumps already
/// established rather than re-deriving them from quinn's stream state.
#[test]
fn a_splice_end_carries_what_the_pumps_observed() {
    let eofed = splice_end(Ok(()), Ok(DownlinkEnd::UpstreamEof));
    assert!(eofed.stream_finished, "only an upstream EOF finishes the stream");
    assert_eq!(eofed.observed_intent, CloseIntent::CarrierEnded);

    let done = splice_end(Ok(()), Ok(DownlinkEnd::ClientDone));
    assert!(!done.stream_finished);
    assert_eq!(
        done.observed_intent,
        CloseIntent::ClientDone,
        "a downlink write that failed with STOP_SENDING(ClientDone) already proves the intent",
    );
    assert!(
        !done.end.reparks(done.observed_intent),
        "a finished client's session must not go back into the registry",
    );

    let switched = splice_end(Ok(()), Ok(DownlinkEnd::Stopped));
    assert!(!switched.stream_finished);
    assert_eq!(switched.observed_intent, CloseIntent::CarrierEnded);

    let broken = splice_end(Ok(()), Err(SpliceFault::upstream(anyhow::anyhow!("rst"))));
    assert!(!broken.stream_finished);
    assert_eq!(broken.observed_intent, CloseIntent::CarrierEnded);
}

/// A writer that takes at most `capacity` bytes and then blocks forever, as a
/// socket does once its send buffer fills. Records everything it took.
struct BlockingWriter {
    capacity: usize,
    written: usize,
}

impl tokio::io::AsyncWrite for BlockingWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let free = self.capacity - self.written;
        if free == 0 {
            // Never woken: the test polls once and then drops the future, which
            // is exactly the cancellation being exercised.
            return std::task::Poll::Pending;
        }
        let took = free.min(buf.len());
        self.written += took;
        std::task::Poll::Ready(Ok(took))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Cancelling the uplink pump part-way through a chunk must leave
/// `upstream_bytes_acked` naming exactly the bytes the socket took. Counting the
/// whole chunk after `write_all` returns records nothing for the partial write,
/// and a later ack-prefix replay from that counter would resend a prefix the
/// target already has.
#[tokio::test]
async fn a_cancelled_uplink_chunk_write_counts_only_what_the_socket_took() {
    let mut writer = BlockingWriter { capacity: 3000, written: 0 };
    let chunk = vec![0x7fu8; 8192];
    let acked = std::sync::atomic::AtomicU64::new(0);
    let counter = test_metrics().mesh_bytes_counter("home", "up", "tcp");

    let mut pump = Box::pin(write_uplink_chunk(
        &mut writer,
        &chunk,
        Duration::from_secs(5),
        &counter,
        &acked,
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        std::future::Future::poll(pump.as_mut(), &mut cx).is_pending(),
        "the socket must block part-way through the chunk",
    );
    drop(pump);

    assert_eq!(writer.written, 3000, "the socket took a partial chunk");
    assert_eq!(
        acked.load(std::sync::atomic::Ordering::Relaxed),
        3000,
        "every byte the socket took must be accounted for at the cancellation point",
    );
}

// ── v5 resume continuity: close intent + acked uplink offset ──────────────────

/// A client that is done for good must not leave a live upstream parked. Reading
/// every mesh FIN as a carrier switch left the target waiting for a request-body
/// FIN it never got (a half-close-then-read protocol hangs until `orphan_ttl_tcp`)
/// while the dead session held one of the user's `orphan_per_user_cap` slots,
/// where it can evict a park that is still wanted.
#[tokio::test]
async fn a_client_done_close_does_not_park_and_finishes_the_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([32u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    session.close_with_client_done();

    assert!(
        upstream.saw_eof().await,
        "a finished client must let the target see the request-body FIN",
    );
    assert!(
        !harness.registry().has_park(id),
        "a session the client finished must not occupy an orphan slot",
    );
}

/// The other half of the contract: a bare FIN still means "the carrier ended,
/// expect a resume", so the session is re-parked exactly as before.
#[tokio::test]
async fn a_carrier_ended_close_still_parks() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([33u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    session.close_with_carrier_ended().await;

    wait_for_park(harness.registry(), id).await;
}

/// The home must tell a resuming edge how far its upstream socket actually got.
/// The number is reported at the head of the *resumed* carrier — where the edge
/// needs it and where it is final — exactly as the direct path emits its
/// Ack-Prefix v1 frame at the head of a resumed session.
#[tokio::test]
async fn the_home_reports_the_acked_uplink_offset_to_the_edge() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([34u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    assert_eq!(first.acked_uplink_offset(), 0, "nothing had reached the upstream yet");
    first.edge_write(b"twelve bytes").await;
    assert_eq!(upstream.read(12).await, b"twelve bytes");
    first.close_with_carrier_ended().await;
    wait_for_park(harness.registry(), id).await;

    let second = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    assert_eq!(
        second.acked_uplink_offset(),
        12,
        "the edge must learn how far the upstream actually got",
    );
}

/// The hole this task exists to close: bytes consumed from the mesh but not yet
/// written to the upstream must be recoverable, and already-written bytes must
/// not be sent twice.
#[tokio::test]
async fn a_resume_replays_uplink_from_the_acked_offset_without_duplicating() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([35u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    first.edge_write(b"AAAABBBB").await;
    assert_eq!(upstream.read(8).await, b"AAAABBBB");
    first.close_with_carrier_ended().await;
    wait_for_park(harness.registry(), id).await;

    // The resuming edge still holds the whole request body and replays only the
    // suffix the target never took.
    let mut second = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    let acked = second.acked_uplink_offset();
    second.edge_write_from_offset(b"AAAABBBBCCCC", acked).await;

    assert_eq!(
        upstream.read(4).await,
        b"CCCC",
        "the upstream must see each byte exactly once across the switch",
    );
}

/// An edge that never advertised the Ack-Prefix capability gets no frame at all,
/// so the byte after the USER frame is the first relayed byte. The flag is the
/// only thing that makes the prologue unambiguous on a stream with no framing.
#[tokio::test]
async fn no_ack_prefix_capability_means_no_continuity_prologue() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([36u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut header = v5_header(id);
    header.ack_prefix = false;
    let mut session = harness.serve_v5_ok(header, "beerloga").await;

    upstream.write(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert_eq!(
        session.edge_read(19).await,
        b"HTTP/1.1 200 OK\r\n\r\n",
        "the downlink must start with the target's own bytes",
    );
}

/// The park decision is the AND of two independent questions: is the upstream
/// still usable, and does the client still want it. Asserted on the decision
/// itself — the end-to-end tests above cover the wire, this pins the table.
#[test]
fn a_client_done_close_never_reparks() {
    let healthy = SpliceEnd::Graceful { upstream_healthy: true };
    assert!(healthy.reparks(CloseIntent::CarrierEnded));
    assert!(!healthy.reparks(CloseIntent::ClientDone));

    let eofed = SpliceEnd::Graceful { upstream_healthy: false };
    assert!(!eofed.reparks(CloseIntent::CarrierEnded));
    assert!(!eofed.reparks(CloseIntent::ClientDone));

    // A mesh fault leaves the upstream healthy, so it re-parks — unless the
    // edge also said the client was done with it.
    let mesh_fault = SpliceFault::mesh(anyhow::anyhow!("the edge carrier died")).into_end();
    assert!(mesh_fault.reparks(CloseIntent::CarrierEnded));
    assert!(!mesh_fault.reparks(CloseIntent::ClientDone));

    let broken = SpliceFault::upstream(anyhow::anyhow!("rst")).into_end();
    assert!(!broken.reparks(CloseIntent::CarrierEnded));
    assert!(!broken.reparks(CloseIntent::ClientDone));
}

/// A `ClientDone` close must never truncate the request body, even when it
/// lands while the home is inside a downlink write.
///
/// The intent rides a `STOP_SENDING`, which fails that write — and the ordinary
/// reading of a failed downlink is "the relay is over", which would drop the
/// uplink pump with request-body bytes still buffered on the mesh. There is no
/// resume behind a finished client to replay them, so the target would simply
/// never see the tail. The home must instead keep draining the uplink to its FIN
/// and only then close the upstream.
///
/// Forced rather than raced: the target floods a mesh stream the edge never
/// reads, so the home is certainly inside a downlink write, while the request
/// body is far larger than the mesh window and the (shrunken) upstream socket
/// buffers put together, so most of it is certainly still in flight.
#[tokio::test]
async fn a_client_done_close_still_drains_the_request_body() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([37u8; 16]);
    let upstream = park_test_session_with_tiny_buffers(harness.registry(), id, "beerloga").await;
    let V5Session { mut send, mut recv, .. } = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    let (mut peer_reader, mut peer_writer) = upstream.split();
    let target = tokio::spawn(async move {
        let _ = peer_writer.write_all(&flood_payload(0x11)).await;
        peer_writer
    });

    let body = flood_payload(0x22);
    let edge = {
        let body = body.clone();
        tokio::spawn(async move {
            send.write_all(&body)
                .await
                .expect("the client sends its whole request body");
            send.finish().expect("finishing the edge half");
            send
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The client is done: stop the downlink half with the intent code, which
    // fails the home's pending downlink write.
    recv.stop(VarInt::from_u32(CloseIntent::ClientDone.code()))
        .expect("stopping the home's downlink half");

    let mut got = vec![0u8; body.len()];
    tokio::time::timeout(Duration::from_secs(20), peer_reader.read_exact(&mut got))
        .await
        .expect("the target must receive the whole request body")
        .expect("reading the relayed request body");
    assert_eq!(got, body, "every request-body byte must reach the target exactly once");

    // ...and once the relay is done the session is not parked: the client is
    // finished with it. (The upstream's own FIN is asserted by the test above;
    // here the target is still being flooded, so the close is an RST.)
    wait_for_active_relays(harness.metrics(), 0).await;
    assert!(!harness.registry().has_park(id), "a finished client leaves no park");

    let _ = edge.await;
    let _ = target.await;
}

// ── v5 home: the plaintext SS-UDP splice ──────────────────────────────────────

/// The base case: the home routes a relayed datagram to its target and the
/// response back, without ever holding a key. Everything it needs it has — the
/// identity from the park (cross-checked against the edge's USER attestation)
/// and the target from inside the datagram — so no crypto is involved on this
/// node at all.
#[tokio::test]
async fn the_home_routes_plaintext_datagrams_without_decrypting() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([31u8; 16]);
    let mut target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target.addr, b"ping")).await;

    assert_eq!(target.next_source().await.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(target.addr, b"ping"),
        "the echo must come back through the same session, still plaintext",
    );
}

/// Per-user byte and request accounting belongs to the node that terminates the
/// client session — the edge on a v5 relay — exactly as the byte-stream splice
/// has it by dropping `ParkedTcp::user_counters`. A home that also counted would
/// double every relayed user's `outline_ss_udp_*{user=…}` series once the SS-UDP
/// edge lands, and would do it under `protocol="http3"`, where the duplicate is
/// indistinguishable from genuine direct H3 traffic on the same node and so
/// cannot be subtracted back out.
///
/// The traffic is not unaccounted, only attributed to the hop that actually
/// happened here: the `role="home"` mesh counters, asserted below so this test
/// cannot pass by the relay simply not running.
#[tokio::test]
async fn the_home_leaves_per_user_udp_accounting_to_the_edge() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([43u8; 16]);
    let mut target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target.addr, b"ping")).await;
    let _ = target.next_source().await;
    assert_eq!(session.edge_recv_datagram().await, socks5_wrap(target.addr, b"ping"));

    // A full round trip crossed the home in both directions...
    wait_for_counter(
        harness.metrics(),
        "outline_ss_mesh_datagrams_total{role=\"home\",direction=\"up\"}",
        1,
    )
    .await;
    wait_for_counter(
        harness.metrics(),
        "outline_ss_mesh_datagrams_total{role=\"home\",direction=\"down\"}",
        1,
    )
    .await;

    // ...and not one byte of it landed on a per-user series here.
    let rendered = harness.metrics().render_prometheus();
    for family in [
        "outline_ss_udp_payload_bytes_total",
        "outline_ss_udp_requests_total",
        "outline_ss_udp_response_datagrams_total",
    ] {
        assert_eq!(
            per_user_total(&rendered, family, "beerloga"),
            0,
            "{family} must stay empty for a user this node only relays:\n{rendered}",
        );
    }
}

/// The property whose loss over XHTTP caused the production incident that
/// started this work. Two datagrams in, two out — never one coalesced blob, in
/// either direction.
#[tokio::test]
async fn datagram_boundaries_survive_the_mesh() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([32u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target.addr, b"first")).await;
    session.edge_send_datagram(&socks5_wrap(target.addr, b"second")).await;

    // Order between two datagrams to one target over loopback is not the
    // property under test — that each arrives whole and alone is.
    let mut got = vec![session.edge_recv_datagram().await, session.edge_recv_datagram().await];
    got.sort();
    let mut want = vec![socks5_wrap(target.addr, b"first"), socks5_wrap(target.addr, b"second")];
    want.sort();
    assert_eq!(got, want, "each datagram must cross the mesh whole and on its own");
}

/// Reattach owned: a resumed session sends from the NAT socket it parked with,
/// not a fresh one. That socket — and therefore the source port every target
/// sees, plus whatever upstream state is pinned to it — is the whole reason the
/// park exists, so the assertion is on the port rather than on bookkeeping.
#[tokio::test]
async fn a_udp_session_reattaches_its_parked_nat_keys() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([33u8; 16]);
    let mut target = spawn_udp_echo().await;
    let keys = park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;
    let parked_port = nat_socket_port(&harness, &keys[0]);
    let entries_before = harness.nat_table().len();

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session
        .edge_send_datagram(&socks5_wrap(target.addr, b"resumed"))
        .await;

    assert_eq!(
        target.next_source().await.port(),
        parked_port,
        "the resumed session must send from its parked NAT socket, not a fresh one",
    );
    assert_eq!(
        harness.nat_table().len(),
        entries_before,
        "reattaching must not create a second entry for a parked target",
    );
}

/// Create unowned: a target first reached *after* the resume is still routable.
/// Forbidding it — the rule this task originally carried — would black-hole
/// every new destination for the life of the session, and a live UDP session
/// meets new destinations constantly.
#[tokio::test]
async fn a_resumed_session_may_still_reach_a_brand_new_target() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([35u8; 16]);
    let parked_target = spawn_udp_echo().await;
    let fresh_target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[parked_target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session
        .edge_send_datagram(&socks5_wrap(fresh_target.addr, b"hello"))
        .await;

    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(fresh_target.addr, b"hello"),
        "a target first reached after the resume must still be routable",
    );
}

/// Refuse foreign, part one: a datagram cannot reach the NAT entry another
/// session owns, even when it names the same target address.
///
/// The home trusts the edge's attestation of *who* the user is, and nothing
/// about the datagram beyond its target. Because the key is built from the
/// session's own identity and scope, the foreign entry is not merely refused but
/// unaddressable: the session gets an entry of its own, on its own port, and the
/// other session's socket is never used. Sharing it would cross two clients'
/// response streams — which is exactly what `NatKey::scope` exists to prevent,
/// and what makes refusing the *target* the wrong rule (two sessions using one
/// DNS resolver is the normal case, not an attack).
#[tokio::test]
async fn a_datagram_cannot_reach_another_sessions_nat_entry() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([34u8; 16]);
    let other_id = SessionId::from_bytes([99u8; 16]);
    let mine = spawn_udp_echo().await;
    let mut shared = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[mine.addr]).await;
    // Another session of the same user, already talking to the same target.
    let theirs = udp_nat_key("beerloga", other_id, shared.addr);
    harness
        .nat_table()
        .get_or_create(theirs.clone(), ServerSessionId::Generate, Arc::clone(harness.metrics()))
        .await
        .expect("binding the other session's NAT entry");
    let foreign_port = nat_socket_port(&harness, &theirs);

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(shared.addr, b"mine")).await;

    assert_ne!(
        shared.next_source().await.port(),
        foreign_port,
        "a session must never send out of another session's NAT socket",
    );
    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(shared.addr, b"mine"),
        "the session still reaches the target — through an entry of its own",
    );
}

/// Refuse foreign, part one and a half: the same rule across *users*, not just
/// across sessions of one user. The key mechanism is identical — `user_id` is a
/// field of [`NatKey`] like `scope` is — but the rule was stated as "another
/// session **or** user", and the cross-user half is the one with a real trust
/// boundary behind it, so it is pinned rather than inferred.
#[tokio::test]
async fn a_datagram_cannot_reach_another_users_nat_entry() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([44u8; 16]);
    let mine = spawn_udp_echo().await;
    let mut shared = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[mine.addr]).await;
    // Another *user*, under this very session id, already talking to the target
    // our datagram will name — so only `user_id` separates the two keys.
    let theirs = udp_nat_key("someone-else", id, shared.addr);
    harness
        .nat_table()
        .get_or_create(theirs.clone(), ServerSessionId::Generate, Arc::clone(harness.metrics()))
        .await
        .expect("binding the other user's NAT entry");
    let foreign_port = nat_socket_port(&harness, &theirs);

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(shared.addr, b"mine")).await;

    assert_ne!(
        shared.next_source().await.port(),
        foreign_port,
        "a session must never send out of another user's NAT socket",
    );
    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(shared.addr, b"mine"),
        "the session still reaches the target — through an entry of its own",
    );
}

/// Refuse foreign, part two: the reattach itself filters. A parked key naming a
/// different user is not re-pointed at this carrier and does not come back in
/// the re-park — the one path by which a relayed session could otherwise take
/// over a socket that is not its own, since every other key it uses is built
/// from its own identity.
#[tokio::test]
async fn a_relayed_session_never_reattaches_a_foreign_nat_key() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([36u8; 16]);
    let mine = spawn_udp_echo().await;
    let theirs = spawn_udp_echo().await;
    let ours = udp_nat_key("beerloga", id, mine.addr);
    let foreign = udp_nat_key("someone-else", id, theirs.addr);
    for key in [&ours, &foreign] {
        harness
            .nat_table()
            .get_or_create(key.clone(), ServerSessionId::Generate, Arc::clone(harness.metrics()))
            .await
            .expect("binding a test NAT entry");
    }
    harness.registry().park(
        id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: vec![ours.clone(), foreign.clone()],
            owner: Arc::from("beerloga"),
        }),
    );

    let session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.close_with_carrier_ended().await;
    wait_for_park(harness.registry(), id).await;

    let ResumeOutcome::Hit(Parked::SsUdpStream(reparked)) =
        harness.registry().take_for_resume(id, "beerloga").await
    else {
        panic!("the relayed ss-udp session must be re-parked");
    };
    assert_eq!(
        reparked.nat_keys,
        vec![ours],
        "only the keys the resuming user owns may be reattached and re-parked",
    );
}

/// A park whose keys all belong to someone else names no identity this session
/// could serve under, so the relay is refused rather than served with an invented
/// one — an unmarked `fwmark`, say, would route the user's traffic outside the
/// policy route it is configured for.
#[tokio::test]
async fn a_udp_park_with_no_key_for_the_attested_user_is_refused() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([37u8; 16]);
    let target = spawn_udp_echo().await;
    harness.registry().park(
        id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: vec![udp_nat_key("someone-else", id, target.addr)],
            owner: Arc::from("beerloga"),
        }),
    );

    let outcome_seen = harness.serve_v5(v5_udp_header(id)).await;

    assert!(outcome_seen.acked(), "the identity check happens after phase 1");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "park_identity"), 1, "{rendered}");
}

/// A relayed SS-UDP session survives a second carrier switch: the home re-parks
/// its NAT keys when the mesh carrier ends, so the next edge resumes the same
/// entries — and therefore the same source ports. Without the re-park a v5
/// session would survive exactly one switch.
#[tokio::test]
async fn a_relayed_udp_session_is_reparked_for_the_next_carrier() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([38u8; 16]);
    let mut target = spawn_udp_echo().await;
    let keys = park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;
    let parked_port = nat_socket_port(&harness, &keys[0]);

    let mut first = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    first.edge_send_datagram(&socks5_wrap(target.addr, b"one")).await;
    assert_eq!(target.next_source().await.port(), parked_port);
    let _ = first.edge_recv_datagram().await;
    first.close_with_carrier_ended().await;
    wait_for_park(harness.registry(), id).await;

    let mut second = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    second.edge_send_datagram(&socks5_wrap(target.addr, b"two")).await;

    assert_eq!(
        target.next_source().await.port(),
        parked_port,
        "the second carrier must resume the same NAT socket as the first",
    );
    assert_eq!(second.edge_recv_datagram().await, socks5_wrap(target.addr, b"two"));
}

/// A client that says it is done leaves no park behind: the session would never
/// be claimed, and the park would hold one of the user's orphan slots until its
/// TTL. The same rule the byte-stream splice follows, on the datagram side.
#[tokio::test]
async fn a_finished_udp_client_leaves_no_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([39u8; 16]);
    let mut target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target.addr, b"last")).await;
    let _ = target.next_source().await;
    let _ = session.edge_recv_datagram().await;
    session.close_with_client_done();

    wait_for_active_relays(harness.metrics(), 0).await;
    assert!(!harness.registry().has_park(id), "a finished client leaves no park");
}

/// The continuity prologue is present exactly when the OPEN asked for it, on
/// both framings — an edge parses the stream head the same way either way. Its
/// value is `0` because a datagram session acknowledges no uplink byte offset.
#[tokio::test]
async fn a_relayed_udp_session_reports_a_zero_acked_offset() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([40u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;

    assert_eq!(session.acked_uplink_offset(), 0);
}

/// A datagram-framed VLESS OPEN is the one (framing, protocol) pair no edge
/// produces: a VLESS edge picks the framing before it can read the command, so
/// it always picks `Tcp` and the home's ack names the real shape. Such a header
/// therefore asks a shape question that has no answer, and is refused outright —
/// before the park it names is even looked up, let alone consumed.
#[tokio::test]
async fn a_udp_framed_vless_relay_is_refused_before_the_park_is_touched() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([41u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut header = v5_udp_header(id);
    header.protocol = MeshProtocol::Vless;
    let outcome_seen = harness.serve_v5(header).await;

    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "bad_setup"), 1, "{rendered}");
    assert!(
        harness.registry().has_park(id),
        "the park must survive a header it cannot serve"
    );
}

/// The phase-2 re-probe, which is what makes the ack an *advertisement* rather
/// than the check.
///
/// The shape the home names in its ack is true when it is written and nothing
/// more: the park can expire and be replaced under the same id before the USER
/// frame arrives, and a peer is free to ignore what it was told anyway. So the
/// home re-asks with the shape it advertised immediately before
/// `take_for_resume` — the last moment a mismatch can be refused *without*
/// destroying the park, because the take consumes it and the splice's own shape
/// check runs after that.
///
/// Here the byte-stream park phase 1 saw is replaced by an SS-UDP one in exactly
/// that window. Without the re-probe the home consumes the park, discovers the
/// mismatch in the post-take arm and resets with `Abort` — the park gone, the
/// client's id now worthless. With it, the relay is refused as an ordinary
/// `NoSession` and the park is still there.
#[tokio::test]
async fn a_park_swapped_between_the_two_phases_is_refused_without_being_consumed() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([45u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // The swap: `park` overwrites the entry under the id, which is what a park
    // expiring and the same client re-establishing a *differently shaped*
    // session looks like from the registry's side. No NAT entry is needed — the
    // relay must be refused long before anything routes a datagram.
    let registry = Arc::clone(harness.registry());
    let outcome_seen = harness
        .serve_v5_between_the_phases(v5_header(id), "beerloga", async {
            registry.park(
                id,
                Parked::SsUdpStream(ParkedSsUdpStream {
                    nat_keys: Vec::new(),
                    owner: Arc::from("beerloga"),
                }),
            );
        })
        .await;

    assert_eq!(
        outcome_seen.close_reason(),
        Some(CloseReason::NoSession),
        "a shape that changed under the ack must be refused, not spliced or aborted",
    );
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "park_shape"), 1, "{rendered}");
    assert_eq!(
        rejected(&rendered, "framing_mismatch"),
        0,
        "reaching the post-take arm means the park was already consumed:\n{rendered}",
    );
    assert!(
        harness.registry().has_park(id),
        "the re-probe must refuse before `take_for_resume`, leaving the park resumable",
    );
}

/// The same window, the other way it can fail: the park is *gone* rather than
/// differently shaped. That is an expiry, and it is counted as one — `no_session`,
/// the reason a park that never existed gets — because an operator reading
/// `park_shape` would otherwise see a shape disagreement where there was only a
/// TTL.
#[tokio::test]
async fn a_park_that_expires_between_the_two_phases_is_counted_as_a_missing_one() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([46u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let registry = Arc::clone(harness.registry());
    let outcome_seen = harness
        .serve_v5_between_the_phases(v5_header(id), "beerloga", async {
            // Whoever takes it first wins; here it is a concurrent direct resume
            // on the home itself, which is also how a real park leaves the
            // registry between the phases.
            assert!(matches!(
                registry.take_for_resume(id, "beerloga").await,
                ResumeOutcome::Hit(_)
            ));
        })
        .await;

    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::NoSession));
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "no_session"), 1, "{rendered}");
    assert_eq!(
        rejected(&rendered, "park_shape"),
        0,
        "an expiry is not a shape disagreement:\n{rendered}",
    );
}

/// A burst keeps every datagram whole. The uplink pump drains its in-flight
/// relays concurrently with reading the next datagram, and the read is *not*
/// cancel-safe — it consumes a length prefix and then a body — so a pump that
/// let the drain cancel a part-way read would leave the stream mid-datagram and
/// mis-frame everything after it. Two datagrams rarely interleave; a burst does.
#[tokio::test]
async fn a_burst_of_datagrams_stays_framed_under_concurrent_relays() {
    const BURST: usize = 64;

    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([42u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(&harness, id, "beerloga", &[target.addr]).await;

    let mut session = harness.serve_v5_ok(v5_udp_header(id), "beerloga").await;
    for index in 0..BURST {
        session
            .edge_send_datagram(&socks5_wrap(target.addr, format!("packet-{index:04}").as_bytes()))
            .await;
    }

    let mut got = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        got.push(session.edge_recv_datagram().await);
    }
    got.sort();
    let mut want: Vec<Vec<u8>> = (0..BURST)
        .map(|index| socks5_wrap(target.addr, format!("packet-{index:04}").as_bytes()))
        .collect();
    want.sort();
    assert_eq!(
        got, want,
        "every datagram of a burst must cross the mesh whole and exactly once"
    );
}
