//! Unit tests for the SS-UDP-over-WS stream state that lives in
//! `server::transport::udp`: the bounded set of NAT keys a stream owns, and
//! the per-stream lifetime of its downlink response sender.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use outline_wire::cluster::{ObfuscationKey, ShardId};
use outline_wire::padding::PaddingScheme;
use quinn::VarInt;
use ring::rand::SystemRandom;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::timeout;

use super::{NAT_KEYS_RECONCILE_FLOOR, StreamNatKeys, UdpRouteCtx, UdpServerCtx, run_udp_relay};
use crate::config::CipherKind;
use crate::crypto::{SessionKeyCache, UserKey, decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::{AppProtocol, Metrics, Protocol};
use crate::protocol::TargetAddr;
use crate::server::abort::AbortOnDrop;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CloseReason, MeshEndpoint, MeshFraming, MeshIdentity, MeshPeerPool, MeshProtocol,
    OPEN_ACK_ACCEPTED, OpenHeader, UpstreamAckFrame, UserFrame, read_datagram, write_datagram,
};
use crate::server::dns_cache::DnsCache;
use crate::server::nat::{NatKey, NatTable, ResponseSender, UdpResponseSender};
use crate::server::replay::ReplayStore;
use crate::server::resumption::{
    OrphanRegistry, Parked, ResumeOutcome, ResumptionConfig, SessionId,
};
use crate::server::tests::sample_config;
use crate::server::transport::mesh_relay::{
    EdgeUpstream, edge_udp_echo, edge_upstream, open_edge_relay,
};
use crate::server::transport::resume_headers::{
    ACK_PREFIX_HEADER, EdgeResumeAdvert, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER,
    ResumeContext, SYMMETRIC_REPLAY_HEADER,
};
use crate::server::transport::upstream_source::UpstreamSource;
use crate::server::transport::ws_socket::{WsFrame, WsSocket};

fn key(port: u16) -> NatKey {
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid target");
    NatKey {
        user_id: Arc::from("user"),
        fwmark: None,
        target,
        scope: None,
    }
}

#[test]
fn tracking_below_the_threshold_keeps_every_key() {
    let mut keys = StreamNatKeys::new();
    for port in 0..8u16 {
        keys.track(key(port), |_| true);
    }
    assert_eq!(keys.len(), 8);
}

#[test]
fn duplicate_targets_are_deduplicated() {
    let mut keys = StreamNatKeys::new();
    for _ in 0..100 {
        keys.track(key(1), |_| true);
    }
    assert_eq!(keys.len(), 1);
}

#[test]
fn evicted_nat_entries_are_reconciled_away() {
    // A long-lived stream touching a stream of one-shot targets: every NAT
    // entry but the most recent has since been idle-evicted. The tracked set
    // must not grow without bound.
    let mut keys = StreamNatKeys::new();
    let mut live: Option<NatKey> = None;
    for port in 0..1000u16 {
        let key = key(port);
        live = Some(key.clone());
        let live_key = live.clone().expect("just set");
        keys.track(key, |candidate| *candidate == live_key);
        assert!(
            keys.len() <= NAT_KEYS_RECONCILE_FLOOR,
            "tracked set grew past the reconcile threshold: {}",
            keys.len()
        );
    }
    // The surviving key is the one whose NAT entry is still live.
    let parked: HashSet<NatKey> = keys.take();
    assert!(parked.contains(&live.expect("at least one key tracked")));
}

#[test]
fn live_keys_survive_reconciliation_and_raise_the_threshold() {
    // Every entry stays live: reconciliation must keep all of them and re-arm
    // at twice the live count, so the sweep stays amortised.
    let mut keys = StreamNatKeys::new();
    let total = NAT_KEYS_RECONCILE_FLOOR * 3;
    for port in 0..total as u16 {
        keys.track(key(port), |_| true);
    }
    assert_eq!(keys.len(), total);
}

#[test]
fn take_drains_the_set_and_resets_the_threshold() {
    let mut keys = StreamNatKeys::new();
    for port in 0..4u16 {
        keys.track(key(port), |_| true);
    }
    let drained = keys.take();
    assert_eq!(drained.len(), 4);
    assert_eq!(keys.len(), 0);

    // Re-armed at the floor: a fresh run of dead targets is reconciled again.
    for port in 100..(100 + NAT_KEYS_RECONCILE_FLOOR as u16 + 1) {
        keys.track(key(port), |_| false);
    }
    assert!(keys.len() <= 1, "reconcile did not re-arm after take: {}", keys.len());
}

#[test]
fn adopted_resume_keys_are_tracked() {
    let mut keys = StreamNatKeys::new();
    keys.adopt(vec![key(1), key(2)]);
    assert_eq!(keys.len(), 2);
    assert!(keys.take().contains(&key(2)));
}

// ── Response-sender lifetime ─────────────────────────────────────────────────

/// How many response senders each test's carrier has been asked to build.
/// `make_udp_response_sender` is a static trait fn, so the count cannot live on
/// the carrier instance; the `SLOT` const parameter gives every test its own
/// counter instead, so tests running concurrently never share one.
static RESPONSE_SENDERS_BUILT: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

enum CountingMsg {
    Binary(Bytes),
    Control,
}

/// A [`WsSocket`] carrier that feeds the relay a scripted sequence of inbound
/// datagrams, reports every downlink frame the writer task emits, and counts
/// how many response senders the relay builds for the stream (into
/// `RESPONSE_SENDERS_BUILT[SLOT]`).
struct CountingCarrier<const SLOT: usize> {
    inbound: mpsc::Receiver<Bytes>,
    downlink: mpsc::UnboundedSender<Bytes>,
}

struct CountingReader(mpsc::Receiver<Bytes>);

struct CountingWriter(mpsc::UnboundedSender<Bytes>);

impl<const SLOT: usize> WsSocket for CountingCarrier<SLOT> {
    type Msg = CountingMsg;
    type Reader = CountingReader;
    type Writer = CountingWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (CountingReader(self.inbound), CountingWriter(self.downlink))
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Self::Msg>> {
        Ok(reader.0.recv().await.map(CountingMsg::Binary))
    }

    async fn send(writer: &mut Self::Writer, msg: Self::Msg) -> Result<()> {
        if let CountingMsg::Binary(bytes) = msg {
            let _ = writer.0.send(bytes);
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
            CountingMsg::Binary(b) => WsFrame::Binary(b),
            CountingMsg::Control => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> Self::Msg {
        CountingMsg::Binary(data)
    }
    fn close_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn close_try_again_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn ping_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn pong_msg(_payload: Bytes) -> Self::Msg {
        CountingMsg::Control
    }
    fn binary_len(msg: &Self::Msg) -> Option<usize> {
        match msg {
            CountingMsg::Binary(b) => Some(b.len()),
            CountingMsg::Control => None,
        }
    }
    fn msg_len(msg: &Self::Msg) -> usize {
        match msg {
            CountingMsg::Binary(b) => b.len(),
            CountingMsg::Control => 0,
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        _scheme: PaddingScheme,
        _monitor: Option<Arc<crate::server::transport::throughput_monitor::ThroughputMonitor>>,
    ) -> UdpResponseSender {
        RESPONSE_SENDERS_BUILT[SLOT].fetch_add(1, Ordering::SeqCst);
        UdpResponseSender::new(Arc::new(CountingResponseSender { tx, protocol, app_protocol }))
    }
}

struct CountingResponseSender {
    tx: mpsc::Sender<CountingMsg>,
    protocol: Protocol,
    app_protocol: AppProtocol,
}

impl ResponseSender for CountingResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(CountingMsg::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn app_protocol(&self) -> AppProtocol {
        self.app_protocol
    }
}

fn test_server_ctx() -> Arc<UdpServerCtx> {
    test_server_ctx_with_resumption(false)
}

/// Server context whose orphan registry is live (`resumption = true`) or the
/// permanently disabled no-op one. The disabled registry is what a deployment
/// with session resumption off runs — and, together with a `ResumeContext`
/// carrying no issued id, also what any client that sends no `X-Outline-Resume-*`
/// header gets.
fn test_server_ctx_with_resumption(resumption: bool) -> Arc<UdpServerCtx> {
    let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))));
    let orphan_registry = if resumption {
        OrphanRegistry::new(
            ResumptionConfig {
                enabled: true,
                ..ResumptionConfig::defaults_disabled()
            },
            Arc::clone(&metrics),
        )
    } else {
        OrphanRegistry::new_disabled(Arc::clone(&metrics))
    };
    Arc::new(UdpServerCtx {
        metrics,
        nat_table: NatTable::new(Duration::from_secs(60)),
        replay_store: ReplayStore::new(Duration::from_secs(60), 1024),
        dns_cache: DnsCache::new(Duration::from_secs(60)),
        prefer_ipv4_upstream: true,
        relay_semaphore: None,
        orphan_registry: Arc::new(orphan_registry),
        session_key_cache: Arc::new(SessionKeyCache::with_default_capacity()),
        ws_data_channel_capacity: 8,
    })
}

fn test_route_ctx(user: &UserKey) -> Arc<UdpRouteCtx> {
    Arc::new(UdpRouteCtx {
        users: Arc::from(vec![user.clone()]),
        protocol: Protocol::Http1,
        path: Arc::from("/udp"),
        candidate_users: Arc::from(vec![Arc::from("alice")]),
        padding: PaddingScheme::disabled(),
    })
}

/// A route serving several credentials, as a multi-user path does: any of them
/// authenticates a datagram, and which one did is only known after decryption.
fn multi_user_route_ctx(users: &[UserKey]) -> Arc<UdpRouteCtx> {
    Arc::new(UdpRouteCtx {
        users: Arc::from(users.to_vec()),
        protocol: Protocol::Http1,
        path: Arc::from("/udp"),
        candidate_users: users.iter().map(|user| Arc::from(user.id())).collect(),
        padding: PaddingScheme::disabled(),
    })
}

/// One SS-UDP packet for `target`, encrypted for `user`.
fn client_datagram(user: &UserKey, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut plaintext = TargetAddr::from(target).to_wire_bytes()?;
    plaintext.extend_from_slice(payload);
    Ok(Bytes::from(encrypt_udp_packet(user, &plaintext)?))
}

/// Every field of an SS-UDP response sender (channel, protocol, app protocol,
/// padding scheme, throttle monitor) is fixed for the lifetime of the stream —
/// only the `UdpCipherMode` handed to `register_session` varies per datagram,
/// and the NAT entry stores that separately. So the relay must build the sender
/// once per stream and hand every datagram a clone, not allocate a fresh
/// `Arc<dyn ResponseSender>` per packet.
#[tokio::test]
async fn response_sender_is_built_once_per_stream() -> Result<()> {
    const SLOT: usize = 0;

    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let user = UserKey::new("alice", "secret", None, CipherKind::Aes256Gcm, None)?;

    let (inbound_tx, inbound_rx) = mpsc::channel::<Bytes>(4);
    let (downlink_tx, _downlink_rx) = mpsc::unbounded_channel::<Bytes>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<SLOT>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        test_server_ctx(),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
        UpstreamSource::Direct,
    ));

    const DATAGRAMS: usize = 3;
    for index in 0..DATAGRAMS {
        inbound_tx
            .send(client_datagram(&user, upstream_addr, format!("packet-{index}").as_bytes())?)
            .await?;
    }

    // A datagram observed upstream has already passed the response-sender
    // construction site, so after the last one the count is final.
    let mut buf = [0_u8; 64];
    for _ in 0..DATAGRAMS {
        timeout(Duration::from_secs(5), upstream.recv_from(&mut buf)).await??;
    }

    assert_eq!(
        RESPONSE_SENDERS_BUILT[SLOT].load(Ordering::SeqCst),
        1,
        "the relay must build one response sender per stream, not one per datagram"
    );

    relay.abort();
    Ok(())
}

/// The stream-scoped sender must stay a working downlink: an upstream response
/// still reaches the carrier's writer through the sender the NAT entry holds.
#[tokio::test]
async fn reused_response_sender_still_delivers_the_downlink() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let user = UserKey::new("alice", "secret", None, CipherKind::Aes256Gcm, None)?;

    let (inbound_tx, inbound_rx) = mpsc::channel::<Bytes>(4);
    let (downlink_tx, mut downlink_rx) = mpsc::unbounded_channel::<Bytes>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<1>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        test_server_ctx(),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
        UpstreamSource::Direct,
    ));

    // Two datagrams to the same target: the second re-registers the session on
    // the NAT entry the first created.
    for index in 0..2 {
        inbound_tx
            .send(client_datagram(&user, upstream_addr, format!("packet-{index}").as_bytes())?)
            .await?;
        let mut buf = [0_u8; 64];
        let (_, source) = timeout(Duration::from_secs(5), upstream.recv_from(&mut buf)).await??;
        upstream.send_to(b"reply", source).await?;
        let framed = timeout(Duration::from_secs(5), downlink_rx.recv())
            .await?
            .expect("carrier writer must emit the encrypted upstream reply");
        assert!(!framed.is_empty(), "downlink frame must carry the encrypted reply");
    }

    relay.abort();
    Ok(())
}

// ── Teardown ─────────────────────────────────────────────────────────────────

/// A stream that never negotiated resumption still registers its response
/// sender — a clone of the writer's data-channel sender — on every NAT entry it
/// touches. Teardown must release those clones, or the writer never observes
/// the data channel close: against a silent upstream (the classic case being
/// DNS over UDP, one reply and then nothing) no downlink send ever fails, so
/// nothing clears the entry's session slot on its own and the writer task, the
/// carrier's write half and the client's read half stay pinned until the NAT
/// entry is idle-evicted tens of seconds later.
#[tokio::test]
async fn teardown_without_resumption_releases_the_writer() -> Result<()> {
    const SLOT: usize = 2;

    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let user = UserKey::new("alice", "secret", None, CipherKind::Aes256Gcm, None)?;

    // Resumption off and no issued session id — the park-on-drop path is inert,
    // exactly as for a third-party client that sends no `X-Outline-Resume-*`.
    let server = test_server_ctx();
    let (inbound_tx, inbound_rx) = mpsc::channel::<Bytes>(4);
    let (downlink_tx, mut downlink_rx) = mpsc::unbounded_channel::<Bytes>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<SLOT>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        Arc::clone(&server),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
        UpstreamSource::Direct,
    ));

    inbound_tx
        .send(client_datagram(&user, upstream_addr, b"query")?)
        .await?;
    // Seeing the datagram upstream proves `register_session` already stored this
    // stream's sender on the NAT entry. The upstream stays silent from here on.
    let mut buf = [0_u8; 64];
    timeout(Duration::from_secs(5), upstream.recv_from(&mut buf)).await??;

    // Client goes away: the carrier's read half ends and the relay tears down.
    // Nothing else can unblock it — the NAT idle timeout is 60s out and no
    // eviction sweep runs in this test.
    drop(inbound_tx);
    timeout(Duration::from_secs(5), relay)
        .await
        .expect("teardown must not block until the NAT entry is idle-evicted")??;
    assert!(
        downlink_rx.recv().await.is_none(),
        "the writer task must have finished, dropping the carrier's write half"
    );
    // Only the response-sender slot is released: the entry itself keeps ageing
    // on its own idle timer, as it does after a park.
    assert_eq!(server.nat_table.len(), 1, "the NAT entry must outlive the stream");
    Ok(())
}

/// Releasing the writer unconditionally must not cost the resumption path its
/// park: a stream that did issue a session id still hands its NAT keys to the
/// orphan registry, and the entries behind them stay live for the resuming
/// carrier to re-point at itself.
#[tokio::test]
async fn teardown_with_resumption_still_parks_the_nat_keys() -> Result<()> {
    const SLOT: usize = 3;

    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let user = UserKey::new("alice", "secret", None, CipherKind::Aes256Gcm, None)?;

    let server = test_server_ctx_with_resumption(true);
    let session_id = server
        .orphan_registry
        .mint_session_id()
        .expect("an enabled registry mints session ids");
    let (inbound_tx, inbound_rx) = mpsc::channel::<Bytes>(4);
    let (downlink_tx, mut downlink_rx) = mpsc::unbounded_channel::<Bytes>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<SLOT>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        Arc::clone(&server),
        test_route_ctx(&user),
        ResumeContext {
            issued_session_id: Some(session_id),
            ..ResumeContext::default()
        },
        None,
        UpstreamSource::Direct,
    ));

    inbound_tx
        .send(client_datagram(&user, upstream_addr, b"query")?)
        .await?;
    let mut buf = [0_u8; 64];
    timeout(Duration::from_secs(5), upstream.recv_from(&mut buf)).await??;

    drop(inbound_tx);
    timeout(Duration::from_secs(5), relay)
        .await
        .expect("teardown must not block until the NAT entry is idle-evicted")??;
    assert!(
        downlink_rx.recv().await.is_none(),
        "the writer task must have finished, dropping the carrier's write half"
    );

    assert_eq!(server.nat_table.len(), 1, "the parked NAT entry must stay live");
    match server.orphan_registry.take_for_resume(session_id, "alice").await {
        ResumeOutcome::Hit(Parked::SsUdpStream(parked)) => {
            assert_eq!(parked.nat_keys.len(), 1, "the stream's NAT key must be parked");
        },
        ResumeOutcome::Hit(other) => {
            panic!("parked entry is not an ss-udp stream: {}", other.kind())
        },
        ResumeOutcome::Miss(_) => panic!("the stream must park its NAT keys for a later resume"),
    }
    Ok(())
}

// ── Read cancellation ────────────────────────────────────────────────────────

/// A carrier whose `recv` is **not** cancel-safe, exactly as the mesh SS-UDP
/// relay's datagram read is not: it reads a length prefix and then the body with
/// the very framing [`crate::server::cluster::mesh::read_datagram`] uses, so a
/// read dropped part-way leaves the stream mid-datagram and every later read is
/// mis-framed. The relay loop is shared by four carriers and must not cancel any
/// of their reads, so a carrier that *notices* the cancellation is what pins the
/// property down.
struct FramedCarrier(DuplexStream);

struct FramedReader(ReadHalf<DuplexStream>);

struct FramedWriter(WriteHalf<DuplexStream>);

impl WsSocket for FramedCarrier {
    type Msg = CountingMsg;
    type Reader = FramedReader;
    type Writer = FramedWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        let (reader, writer) = tokio::io::split(self.0);
        (FramedReader(reader), FramedWriter(writer))
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Self::Msg>> {
        let mut buf = Vec::new();
        Ok(read_datagram(&mut reader.0, &mut buf)
            .await?
            .map(|_| CountingMsg::Binary(Bytes::from(buf))))
    }

    async fn send(writer: &mut Self::Writer, msg: Self::Msg) -> Result<()> {
        if let CountingMsg::Binary(bytes) = msg {
            write_datagram(&mut writer.0, &bytes).await?;
        }
        Ok(())
    }

    async fn finish(_writer: &mut Self::Writer) {}

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        Ok(())
    }

    fn is_h3() -> bool {
        true
    }

    fn classify(msg: Self::Msg) -> WsFrame {
        match msg {
            CountingMsg::Binary(b) => WsFrame::Binary(b),
            CountingMsg::Control => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> Self::Msg {
        CountingMsg::Binary(data)
    }
    fn close_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn close_try_again_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn ping_msg() -> Self::Msg {
        CountingMsg::Control
    }
    fn pong_msg(_payload: Bytes) -> Self::Msg {
        CountingMsg::Control
    }
    fn binary_len(msg: &Self::Msg) -> Option<usize> {
        match msg {
            CountingMsg::Binary(b) => Some(b.len()),
            CountingMsg::Control => None,
        }
    }
    fn msg_len(msg: &Self::Msg) -> usize {
        match msg {
            CountingMsg::Binary(b) => b.len(),
            CountingMsg::Control => 0,
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        _scheme: PaddingScheme,
        _monitor: Option<Arc<crate::server::transport::throughput_monitor::ThroughputMonitor>>,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(CountingResponseSender { tx, protocol, app_protocol }))
    }
}

/// A burst keeps every datagram whole. The relay loop drains its in-flight
/// relays concurrently with reading the next frame, and a carrier's `recv` need
/// not be cancel-safe — the mesh SS-UDP carrier's is not, since it consumes a
/// length prefix and then a body — so a loop that let the drain cancel a
/// part-way read would leave the carrier mid-datagram and mis-frame everything
/// after it. Two datagrams rarely interleave; a burst does.
#[tokio::test]
async fn a_burst_of_datagrams_stays_framed_under_concurrent_relays() -> Result<()> {
    const BURST: usize = 64;

    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let user = UserKey::new("alice", "secret", None, CipherKind::Aes256Gcm, None)?;

    // A pipe far narrower than one datagram, so a read pends part-way through
    // nearly every frame — which is when a cancellation costs bytes.
    let (home, edge) = tokio::io::duplex(16);
    let relay = tokio::spawn(run_udp_relay::<FramedCarrier>(
        FramedCarrier(home),
        test_server_ctx(),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
        UpstreamSource::Direct,
    ));

    let datagrams = (0..BURST)
        .map(|index| client_datagram(&user, upstream_addr, format!("packet-{index:04}").as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    // The burst goes out from its own task: the pipe holds only a fraction of a
    // datagram, so writing it blocks on the relay reading, while this task
    // collects what reaches the target.
    let burst = tokio::spawn(async move {
        let mut edge = edge;
        for datagram in datagrams {
            write_datagram(&mut edge, &datagram).await?;
        }
        Ok::<_, anyhow::Error>(edge)
    });

    let mut got = Vec::with_capacity(BURST);
    let mut buf = [0_u8; 256];
    for _ in 0..BURST {
        let (len, _) = timeout(Duration::from_secs(10), upstream.recv_from(&mut buf)).await??;
        got.push(buf[..len].to_vec());
    }
    got.sort();
    let mut want: Vec<Vec<u8>> = (0..BURST)
        .map(|index| format!("packet-{index:04}").into_bytes())
        .collect();
    want.sort();
    assert_eq!(
        got, want,
        "every datagram of a burst must cross the carrier whole and exactly once"
    );

    let _edge = timeout(Duration::from_secs(10), burst).await??;
    relay.abort();
    Ok(())
}

// ── Cluster edge: SS-UDP with the NAT on the home (v5) ────────────────────────

/// A stand-in home: it speaks the home half of the v5 mesh protocol over a real
/// mesh QUIC connection, but owns no park and no NAT table — the test plays the
/// target itself. Everything the edge is *supposed* to do is therefore
/// observable here: the OPEN version and framing, the user it attests, and
/// whether what crosses the mesh is plaintext, one datagram at a time.
struct FakeUdpHome {
    /// The USER frame the edge sent after authenticating its client.
    user: Option<oneshot::Receiver<UserFrame>>,
    /// One entry per datagram the edge relayed, in order.
    uplink: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Responses the test wants the "target" to answer with, already
    /// SOCKS5-wrapped as the home's NAT reader wraps them.
    downlink: mpsc::UnboundedSender<Vec<u8>>,
    _task: AbortOnDrop<()>,
}

impl FakeUdpHome {
    /// The user name the edge attested, waiting for it if it has not arrived.
    async fn user_frame(&mut self) -> UserFrame {
        let rx = self.user.take().expect("the USER frame is read once");
        timeout(Duration::from_secs(5), rx)
            .await
            .expect("the edge must send a USER frame after authenticating")
            .expect("the home task must not drop before the USER frame")
    }

    /// The next `want` datagrams the edge relayed, each exactly as it crossed
    /// the mesh.
    async fn datagrams_received(&mut self, want: usize) -> Vec<Vec<u8>> {
        let mut got = Vec::with_capacity(want);
        let collect = async {
            while got.len() < want {
                match self.uplink.recv().await {
                    Some(datagram) => got.push(datagram),
                    None => break,
                }
            }
        };
        timeout(Duration::from_secs(5), collect)
            .await
            .expect("the edge must relay the client's datagrams to the home");
        got
    }

    /// Answers as the home's NAT reader does under
    /// [`crate::server::nat::UdpResponseCoding::Plaintext`]: the source address
    /// SOCKS5-wrapped ahead of the payload, with no crypto on it.
    fn send_plaintext_response(&self, source: SocketAddr, payload: &[u8]) {
        self.downlink
            .send(socks5_wrap(source, payload))
            .expect("the home task must still be running");
    }
}

/// `TargetAddr || payload`: the body of an SS-UDP packet, and exactly what a v5
/// edge forwards once it has stripped the client's crypto.
fn socks5_wrap(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut wrapped = TargetAddr::from(target)
        .to_wire_bytes()
        .expect("a socket address always encodes");
    wrapped.extend_from_slice(payload);
    wrapped
}

/// How the fake home answers the edge's OPEN.
enum UdpHomeAnswer {
    /// A park exists: ack, take the USER frame, then route datagrams.
    Park,
    /// No park under this id: refuse before the edge upgrades its client.
    NoSession,
}

/// The edge's own cluster runtime plus the fake home it relays to. The edge's
/// credentials are its own: the home in these tests holds no key at all, which
/// is the property edge-terminated crypto exists to allow.
struct UdpEdgeHarness {
    cluster: ClusterCtx,
    shard: ShardId,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    registry: Arc<OrphanRegistry>,
    user: UserKey,
    /// A second credential configured on the *same* path, as a multi-user route
    /// has. Nothing but the identity-guard test authenticates as it; every other
    /// test's client keeps using [`Self::user`].
    other_user: UserKey,
    session_id: SessionId,
    _home_endpoint: MeshEndpoint,
}

impl UdpEdgeHarness {
    /// An edge serving `user`/`secret`, wired to a home answering `answer`.
    async fn with_credentials(
        user: &str,
        secret: &str,
        answer: UdpHomeAnswer,
    ) -> (Self, FakeUdpHome) {
        let psk = b"edge-v5-udp-psk";
        let home_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let home_addr = home_endpoint.local_addr().unwrap();
        let home = spawn_fake_udp_home(home_endpoint.clone(), answer);

        let shard = ShardId::new(1).unwrap();
        let edge_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))));
        let cluster = ClusterCtx {
            pool: Arc::new(MeshPeerPool::new(
                edge_endpoint.clone(),
                HashMap::from([(shard, home_addr)]),
                8,
            )),
            endpoint: edge_endpoint,
            relay_budget: Duration::from_secs(5),
            relay_permits: Arc::new(Semaphore::new(8)),
            metrics: Arc::clone(&metrics),
        };

        // Resumption is *on*: a disabled registry could never park, so "the edge
        // parks nothing" would prove nothing about the edge declining to.
        let obfuscation = ObfuscationKey::derive_from_psk(psk);
        let registry = Arc::new(
            OrphanRegistry::new(
                ResumptionConfig {
                    enabled: true,
                    ..ResumptionConfig::defaults_disabled()
                },
                Arc::clone(&metrics),
            )
            // A *different* shard from the home, which is what makes the
            // client's resume id a foreign one to route away.
            .with_cluster(obfuscation.clone(), ShardId::new(2).unwrap()),
        );
        let user = UserKey::new(user, secret, None, CipherKind::Aes256Gcm, None).unwrap();
        let other_user =
            UserKey::new("bystander", "other-secret", None, CipherKind::Aes256Gcm, None).unwrap();
        let server = Arc::new(UdpServerCtx {
            metrics: Arc::clone(&metrics),
            nat_table: NatTable::new(Duration::from_secs(60)),
            replay_store: ReplayStore::new(Duration::from_secs(60), 1024),
            dns_cache: DnsCache::new(Duration::from_secs(60)),
            prefer_ipv4_upstream: true,
            relay_semaphore: None,
            orphan_registry: Arc::clone(&registry),
            session_key_cache: Arc::new(SessionKeyCache::with_default_capacity()),
            ws_data_channel_capacity: 8,
        });
        (
            Self {
                cluster,
                shard,
                server,
                route: multi_user_route_ctx(&[user.clone(), other_user.clone()]),
                registry,
                user,
                other_user,
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

    /// The request headers the client behind [`Self::advert`] presents.
    fn resume_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(RESUME_CAPABLE_HEADER, "1".parse().unwrap());
        headers.insert(ACK_PREFIX_HEADER, "1".parse().unwrap());
        headers.insert(SYMMETRIC_REPLAY_HEADER, "1".parse().unwrap());
        headers.insert(RESUME_REQUEST_HEADER, self.session_id.to_hex().parse().unwrap());
        headers
    }

    /// The resume negotiation this node would run on its own, i.e. what the
    /// upgrade falls back to when no relay is in play.
    fn local_resume(&self) -> ResumeContext {
        ResumeContext::from_request_headers(&self.resume_headers(), &self.registry)
    }

    /// Runs phase 1 of the relay: `None` means the home refused and the caller
    /// serves the client locally instead.
    async fn open_relay(&self) -> Option<EdgeUpstream> {
        let advert = self.advert();
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40404));
        let pooled = timeout(
            Duration::from_secs(5),
            open_edge_relay(
                &self.cluster,
                self.shard,
                &advert,
                MeshFraming::Udp,
                MeshProtocol::Ss,
                peer,
            ),
        )
        .await
        .expect("the home must answer the OPEN, not hang the upgrade")?;
        Some(edge_upstream(
            pooled,
            &advert,
            &self.cluster,
            MeshFraming::Udp,
            &self.server.metrics,
            &self.registry,
        ))
    }

    /// One SS-UDP packet for `target`, encrypted for this edge's user.
    fn client_packet(&self, target: SocketAddr, payload: &[u8]) -> Bytes {
        client_datagram(&self.user, target, payload).expect("encrypting a client datagram")
    }

    /// The same, under the *other* credential this path serves: a datagram the
    /// edge authenticates just as happily, but for a different user.
    fn other_user_packet(&self, target: SocketAddr, payload: &[u8]) -> Bytes {
        client_datagram(&self.other_user, target, payload).expect("encrypting a client datagram")
    }

    /// Starts the real relay over a scripted client carrier, exactly as an
    /// upgrade handler would.
    fn spawn_relay<const SLOT: usize>(
        &self,
        edge: EdgeUpstream,
    ) -> (
        mpsc::Sender<Bytes>,
        mpsc::UnboundedReceiver<Bytes>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::channel::<Bytes>(4);
        let (downlink_tx, downlink_rx) = mpsc::unbounded_channel::<Bytes>();
        let relay = tokio::spawn(run_udp_relay::<CountingCarrier<SLOT>>(
            CountingCarrier {
                inbound: inbound_rx,
                downlink: downlink_tx,
            },
            Arc::clone(&self.server),
            Arc::clone(&self.route),
            edge.resume,
            None,
            edge.source,
        ));
        (inbound_tx, downlink_rx, relay)
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Drives the home half of one v5 datagram relay stream: version- and
/// framing-checks the OPEN, answers it, and — when it admitted the relay — pumps
/// length-framed plaintext both ways.
fn spawn_fake_udp_home(endpoint: MeshEndpoint, answer: UdpHomeAnswer) -> FakeUdpHome {
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
        let header = OpenHeader::parse(&buf).expect("parsing the OPEN header");
        assert_eq!(
            header.framing,
            MeshFraming::Udp,
            "SS-UDP is datagram-framed on the mesh: a byte splice would coalesce packets",
        );
        assert_eq!(
            header.protocol,
            MeshProtocol::Ss,
            "an SS-UDP edge must name its protocol, or the home cannot keep a VLESS park \
             from being spliced onto it",
        );
        if matches!(answer, UdpHomeAnswer::NoSession) {
            let code = VarInt::from_u32(CloseReason::NoSession.code());
            let _ = send.reset(code);
            let _ = recv.stop(code);
            return;
        }
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

        // A datagram session acknowledges no uplink byte offset, but the frame
        // is on the wire whenever the OPEN asked for it.
        if header.ack_prefix {
            send.write_all(&UpstreamAckFrame { upstream_acked: 0 }.encode())
                .await
                .expect("writing the upstream-ack frame");
        }

        tokio::join!(
            async {
                let mut buf = Vec::new();
                while let Ok(Some(len)) = read_datagram(&mut recv, &mut buf).await {
                    if uplink_tx.send(buf[..len].to_vec()).is_err() {
                        break;
                    }
                }
            },
            async {
                while let Some(response) = downlink_rx.recv().await {
                    if write_datagram(&mut send, &response).await.is_err() {
                        break;
                    }
                }
            },
        );
    });
    FakeUdpHome {
        user: Some(user_rx),
        uplink: uplink_rx,
        downlink: downlink_tx,
        _task: AbortOnDrop::new(task),
    }
}

/// Datagram boundaries must survive the mesh — the same property whose loss over
/// XHTTP caused the production incident this cluster work followed. Two client
/// packets are two mesh datagrams, each carrying the SOCKS5-wrapped plaintext
/// the edge decrypted and nothing else.
#[tokio::test]
async fn udp_edge_relays_plaintext_datagrams_preserving_boundaries() -> Result<()> {
    const SLOT: usize = 4;
    let (harness, mut home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::Park).await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    let (client, _downlink, relay) = harness.spawn_relay::<SLOT>(edge);

    let target: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    client.send(harness.client_packet(target, b"first")).await?;
    client.send(harness.client_packet(target, b"second")).await?;

    assert_eq!(
        home.user_frame().await.user,
        "beerloga",
        "the edge attests the user it authenticated, which is what lets the home own the park",
    );
    assert_eq!(
        home.datagrams_received(2).await,
        vec![socks5_wrap(target, b"first"), socks5_wrap(target, b"second")],
        "two datagrams in, two datagrams out — plaintext, in order, never one coalesced blob",
    );

    relay.abort();
    Ok(())
}

/// The NAT belongs to the home that owns the socket. An edge that allocated one
/// would bind a second upstream port for a session whose source port the target
/// has already seen — and would then have something to park, which it must not.
#[tokio::test]
async fn udp_edge_keeps_the_nat_on_the_home() -> Result<()> {
    const SLOT: usize = 5;
    let (harness, mut home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::Park).await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    let (client, _downlink, relay) = harness.spawn_relay::<SLOT>(edge);

    let target: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    client.send(harness.client_packet(target, b"x")).await?;
    // Observing it at the home proves the datagram passed every point where a
    // NAT entry could have been created.
    assert_eq!(home.datagrams_received(1).await.len(), 1);
    assert_eq!(
        harness.server.nat_table.len(),
        0,
        "NAT belongs to the home that owns the socket",
    );

    // Client goes away: the edge tears down and must leave nothing behind.
    drop(client);
    timeout(Duration::from_secs(5), relay)
        .await
        .expect("the edge must not block on the downlink pump at teardown")??;
    assert_eq!(
        harness.registry.len(),
        0,
        "the edge parks nothing: the entries a park would hand on live on the home",
    );
    Ok(())
}

/// The home relays a response as plaintext, because it holds no key; the edge is
/// the node that seals it for the client. A client-decryptable reply is the
/// whole hand-off working end to end.
#[tokio::test]
async fn udp_edge_seals_the_homes_plaintext_response_for_the_client() -> Result<()> {
    const SLOT: usize = 6;
    let (harness, mut home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::Park).await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    let (client, mut downlink, relay) = harness.spawn_relay::<SLOT>(edge);

    let target: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    client.send(harness.client_packet(target, b"ping")).await?;
    assert_eq!(home.datagrams_received(1).await.len(), 1);
    home.send_plaintext_response(target, b"pong");

    let sealed = timeout(Duration::from_secs(5), downlink.recv())
        .await?
        .expect("the edge must deliver the relayed response to its client");
    let opened = decrypt_udp_packet(std::slice::from_ref(&harness.user), &sealed)?;
    assert!(
        opened.payload.ends_with(b"pong"),
        "the edge must seal the home's plaintext under the client's own key",
    );
    assert_eq!(
        opened.payload,
        socks5_wrap(target, b"pong"),
        "the response must name the source the home reported, byte for byte",
    );

    relay.abort();
    Ok(())
}

/// One carrier attests exactly one user, and the home routes everything on it
/// under that user's NAT identity and fwmark without re-authenticating — it
/// holds no key. So a datagram opened under a second valid credential must not
/// ride the same carrier: it would egress as the attested user, under the
/// attested user's policy routing, and be billed to them.
#[tokio::test]
async fn udp_edge_drops_a_datagram_from_a_user_it_did_not_attest() -> Result<()> {
    const SLOT: usize = 7;
    let (harness, mut home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::Park).await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    let (client, _downlink, relay) = harness.spawn_relay::<SLOT>(edge);

    let target: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    client.send(harness.client_packet(target, b"first")).await?;
    assert_eq!(
        home.user_frame().await.user,
        "beerloga",
        "the first authenticated datagram is what the carrier attests",
    );
    assert_eq!(home.datagrams_received(1).await, vec![socks5_wrap(target, b"first")]);

    // The second credential's datagram, on the very same carrier — and then one
    // the attested user is allowed to send, so the assertion below waits on a
    // real event instead of on a timeout. The edge forwards inline, in read
    // order, so an unguarded edge would deliver the intruder's datagram first.
    client.send(harness.other_user_packet(target, b"intruder")).await?;
    client.send(harness.client_packet(target, b"third")).await?;

    assert_eq!(
        home.datagrams_received(1).await,
        vec![socks5_wrap(target, b"third")],
        "a datagram from a user this carrier never attested must not reach the target",
    );
    assert!(
        harness.server.metrics.render_prometheus().contains(
            "outline_ss_udp_relay_drops_total{transport=\"udp\",protocol=\"http1\",\
             app_protocol=\"shadowsocks\",reason=\"relayed_user_mismatch\"} 1"
        ),
        "the drop must be observable, and named for what it was",
    );

    relay.abort();
    Ok(())
}

/// The id echoed on an admitted relay is the id the client presented, because
/// that is the one the home parks under — echo anything else and the session can
/// never resume. The datagram edge resolves it through the same helper the
/// byte-stream edges use.
#[tokio::test]
async fn an_admitted_udp_relay_echoes_the_presented_id() {
    let (harness, _home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::Park).await;
    let edge = harness.open_relay().await.expect("the home holds a park");
    let local = harness.local_resume();
    assert!(
        local.issued_session_id.is_some_and(|id| id != harness.session_id),
        "the fixture must mint a *different* local id, or this cannot discriminate",
    );

    let echo = edge_udp_echo(Some(&edge), &local);
    assert_eq!(
        echo.session_id,
        Some(harness.session_id),
        "continuity: the home parks under the id the client presented",
    );
    assert!(
        !echo.ack_prefix && !echo.symmetric_replay,
        "a datagram path confirms neither v1 nor v2, relayed or not",
    );
}

/// The mirror: a home holding no park refuses, and the edge becomes this
/// session's home. Echoing the foreign id back would send the client's next
/// reconnect to the node that just refused it — a session that can never resume.
#[tokio::test]
async fn a_refused_udp_relay_echoes_a_local_id() {
    let (harness, _home) =
        UdpEdgeHarness::with_credentials("beerloga", "edge-secret", UdpHomeAnswer::NoSession).await;
    let edge = harness.open_relay().await;
    assert!(edge.is_none(), "the fixture must actually refuse, or this proves nothing");

    let local = harness.local_resume();
    let echo = edge_udp_echo(edge.as_ref(), &local);
    assert_ne!(
        echo.session_id,
        Some(harness.session_id),
        "a refused relay must not echo the foreign id the client presented",
    );
    assert_eq!(
        echo.session_id, local.issued_session_id,
        "the id echoed must be the one this node will park under",
    );
}
