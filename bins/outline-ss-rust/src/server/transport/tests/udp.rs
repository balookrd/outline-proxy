//! Unit tests for the SS-UDP-over-WS stream state that lives in
//! `server::transport::udp`: the bounded set of NAT keys a stream owns, and
//! the per-stream lifetime of its downlink response sender.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use outline_wire::padding::PaddingScheme;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{NAT_KEYS_RECONCILE_FLOOR, StreamNatKeys, UdpRouteCtx, UdpServerCtx, run_udp_relay};
use crate::config::CipherKind;
use crate::crypto::{SessionKeyCache, UserKey, encrypt_udp_packet};
use crate::metrics::{AppProtocol, Metrics, Protocol};
use crate::protocol::TargetAddr;
use crate::server::dns_cache::DnsCache;
use crate::server::nat::{NatKey, NatTable, ResponseSender, UdpResponseSender};
use crate::server::replay::ReplayStore;
use crate::server::resumption::OrphanRegistry;
use crate::server::tests::sample_config;
use crate::server::transport::resume_headers::ResumeContext;
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
static RESPONSE_SENDERS_BUILT: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];

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
    downlink: mpsc::UnboundedSender<usize>,
}

struct CountingReader(mpsc::Receiver<Bytes>);

struct CountingWriter(mpsc::UnboundedSender<usize>);

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
            let _ = writer.0.send(bytes.len());
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
    let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))));
    Arc::new(UdpServerCtx {
        metrics: Arc::clone(&metrics),
        nat_table: NatTable::new(Duration::from_secs(60)),
        replay_store: ReplayStore::new(Duration::from_secs(60), 1024),
        dns_cache: DnsCache::new(Duration::from_secs(60)),
        prefer_ipv4_upstream: true,
        relay_semaphore: None,
        orphan_registry: Arc::new(OrphanRegistry::new_disabled(metrics)),
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
    let (downlink_tx, _downlink_rx) = mpsc::unbounded_channel::<usize>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<SLOT>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        test_server_ctx(),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
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
    let (downlink_tx, mut downlink_rx) = mpsc::unbounded_channel::<usize>();
    let relay = tokio::spawn(run_udp_relay::<CountingCarrier<1>>(
        CountingCarrier {
            inbound: inbound_rx,
            downlink: downlink_tx,
        },
        test_server_ctx(),
        test_route_ctx(&user),
        ResumeContext::default(),
        None,
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
        assert!(framed > 0, "downlink frame must carry the encrypted reply");
    }

    relay.abort();
    Ok(())
}
