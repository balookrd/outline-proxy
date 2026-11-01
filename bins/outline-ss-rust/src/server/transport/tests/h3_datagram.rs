//! `DatagramResponseSender` over a real loopback QUIC pair: what goes into a
//! datagram on a padded path, and what the stream fallback receives.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use outline_wire::h3_datagram::{datagram_overhead, decode_datagram};
use outline_wire::padding::{PADDING_FRAME_HEADER_LEN, PaddingDecoder, PaddingScheme};
use tokio::time::timeout;

use super::{
    AnchorUpdate, DatagramActivity, DatagramAnchor, DatagramDownlink, DatagramPeer,
    DatagramResponseSender, DatagramTarget, H3DatagramRoute,
};
use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::constants::H3_DATAGRAM_BUFFER_BYTES;
use crate::server::h3::build_h3_quinn_server_config;
use crate::server::nat::{ResponseSender, UdpResponseSender};
use crate::server::tests::{sample_config, test_h3_client_config, test_h3_server_tls};

/// A connected QUIC pair with datagrams on both sides. The endpoints are kept
/// so the connections outlive the helper.
pub(in crate::server::transport) struct QuicDatagramPair {
    pub(in crate::server::transport) client: quinn::Connection,
    pub(in crate::server::transport) server: quinn::Connection,
    _endpoints: (quinn::Endpoint, quinn::Endpoint),
}

pub(in crate::server::transport) async fn quic_datagram_pair() -> Result<QuicDatagramPair> {
    let (tls, cert) = test_h3_server_tls()?;
    let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let server_config = build_h3_quinn_server_config(tls, &config.tuning, None)?;
    let server_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let addr = server_endpoint.local_addr()?;

    let mut client_config = test_h3_client_config(cert)?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .initial_mtu(1400)
        .datagram_receive_buffer_size(Some(H3_DATAGRAM_BUFFER_BYTES))
        .datagram_send_buffer_size(H3_DATAGRAM_BUFFER_BYTES);
    client_config.transport_config(Arc::new(transport));
    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    client_endpoint.set_default_client_config(client_config);

    let accept = tokio::spawn({
        let endpoint = server_endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.context("server endpoint closed")?;
            Ok::<_, anyhow::Error>(incoming.await?)
        }
    });
    let client = client_endpoint.connect(addr, "localhost")?.await?;
    let server = accept.await??;
    Ok(QuicDatagramPair {
        client,
        server,
        _endpoints: (server_endpoint, client_endpoint),
    })
}

/// Stream-side sender that records every packet handed to it.
#[derive(Default)]
struct RecordingSender(Mutex<Vec<Bytes>>);

impl ResponseSender for Arc<RecordingSender> {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        self.0.lock().expect("recording lock").push(data);
        Box::pin(async { true })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http3
    }

    fn app_protocol(&self) -> AppProtocol {
        AppProtocol::Shadowsocks
    }
}

const SCHEME: PaddingScheme = PaddingScheme::new(4, 16);
const QUARTER_ID: u64 = 70; // two-byte varint prefix

fn padded_sender(
    pair: &QuicDatagramPair,
    stream: &Arc<RecordingSender>,
    activity: &Arc<DatagramActivity>,
) -> DatagramResponseSender {
    DatagramResponseSender {
        downlink: DatagramDownlink {
            target: Arc::new(DatagramTarget::from_pointee(DatagramPeer {
                connection: pair.server.clone(),
                quarter_stream_id: QUARTER_ID,
            })),
            monitor: None,
            metrics: Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))),
            activity: Arc::clone(activity),
            transport: Transport::Udp,
            protocol: Protocol::Http3,
            app_protocol: AppProtocol::Shadowsocks,
            proto: super::SS_PROTO_LABEL,
        },
        stream: UdpResponseSender::new(Arc::new(Arc::clone(stream))),
        padding: SCHEME,
    }
}

#[tokio::test]
async fn padded_downlink_datagram_carries_the_stream_frame() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let stream = Arc::new(RecordingSender::default());
    let activity = Arc::new(DatagramActivity::default());
    let sender = padded_sender(&pair, &stream, &activity);

    let data = Bytes::from_static(b"sealed ss packet");
    assert!(sender.send_bytes(data.clone()).await);

    let datagram = timeout(Duration::from_secs(5), pair.client.read_datagram()).await??;
    let (id, body) = decode_datagram(datagram).context("datagram prefix")?;
    assert_eq!(id, QUARTER_ID);
    // `frame_downlink_message` layout: real_len, pad_len, real, pad.
    let real_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let pad_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    assert_eq!(real_len, data.len());
    assert!((4..=16).contains(&pad_len), "pad {pad_len} outside the scheme");
    assert_eq!(body.len(), PADDING_FRAME_HEADER_LEN + real_len + pad_len);
    assert_eq!(&body[PADDING_FRAME_HEADER_LEN..PADDING_FRAME_HEADER_LEN + real_len], &data[..]);
    let mut decoded = Vec::new();
    PaddingDecoder::new().push(&body, &mut decoded);
    assert_eq!(decoded, data);

    assert!(stream.0.lock().expect("recording lock").is_empty(), "nothing rode the stream");
    assert_eq!(activity.sends(), 1, "the writer's cover timer sees the datagram");
    Ok(())
}

#[tokio::test]
async fn near_full_packet_goes_as_a_datagram_with_a_cut_pad() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let stream = Arc::new(RecordingSender::default());
    let activity = Arc::new(DatagramActivity::default());
    let mut sender = padded_sender(&pair, &stream, &activity);
    sender.padding = PaddingScheme::new(0, 256);

    let room = pair.server.max_datagram_size().context("datagrams negotiated")?
        - datagram_overhead(QUARTER_ID);
    let data = Bytes::from(vec![0x5b; room - PADDING_FRAME_HEADER_LEN - 8]);
    for _ in 0..50 {
        assert!(sender.send_bytes(data.clone()).await);
        let datagram = timeout(Duration::from_secs(5), pair.client.read_datagram()).await??;
        // PMTU discovery may grow the datagram size during the test, even
        // between a read of the room and the send that uses it. On loopback it
        // only grows, so the room read after the datagram arrived bounds the
        // one the send cut the pad to.
        let room_now = pair.server.max_datagram_size().context("datagrams negotiated")?
            - datagram_overhead(QUARTER_ID);
        let (_, body) = decode_datagram(datagram).context("datagram prefix")?;
        let pad_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        let budget = room_now - PADDING_FRAME_HEADER_LEN - data.len();
        assert!(pad_len <= budget, "pad {pad_len} must be cut to the room left ({budget})");
        assert!(body.len() <= room_now);
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&body, &mut decoded);
        assert_eq!(decoded, data);
    }
    assert!(stream.0.lock().expect("recording lock").is_empty(), "nothing rode the stream");
    Ok(())
}

#[tokio::test]
async fn oversized_downlink_falls_back_with_the_unpadded_original() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let stream = Arc::new(RecordingSender::default());
    let activity = Arc::new(DatagramActivity::default());
    let sender = padded_sender(&pair, &stream, &activity);

    let max = pair.server.max_datagram_size().context("datagrams negotiated")?;
    let data = Bytes::from(vec![0x5a; max]);
    assert!(sender.send_bytes(data.clone()).await);

    // The stream sender pads on its own, so it must get the original bytes.
    assert_eq!(*stream.0.lock().expect("recording lock"), vec![data]);
    assert_eq!(activity.sends(), 0);
    assert!(
        timeout(Duration::from_millis(200), pair.client.read_datagram())
            .await
            .is_err(),
        "an oversized packet must not also go out as a datagram"
    );
    Ok(())
}

/// Without an agreed anchor the sender is the stream path, untouched: the
/// original bytes, no datagram, no activity, no counter.
#[tokio::test]
async fn sender_without_a_target_is_the_stream_path() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let stream = Arc::new(RecordingSender::default());
    let activity = Arc::new(DatagramActivity::default());
    let mut sender = padded_sender(&pair, &stream, &activity);
    sender.downlink.target = Arc::new(DatagramTarget::empty());

    let data = Bytes::from_static(b"sealed ss packet");
    assert!(sender.send_bytes(data.clone()).await);

    assert_eq!(*stream.0.lock().expect("recording lock"), vec![data]);
    assert_eq!(activity.sends(), 0);
    assert!(
        !sender
            .downlink
            .metrics
            .render_prometheus()
            .contains("outline_ss_udp_h3_datagram")
    );
    assert!(
        timeout(Duration::from_millis(200), pair.client.read_datagram())
            .await
            .is_err(),
        "no datagram without an anchor"
    );
    Ok(())
}

fn route_on(
    pair: &QuicDatagramPair,
    demux: &Arc<outline_wire::h3_datagram::DatagramDemux>,
    id: u64,
) -> H3DatagramRoute {
    H3DatagramRoute {
        connection: pair.server.clone(),
        quarter_stream_id: id,
        registration: demux.register(id),
    }
}

/// The relay sees only the latest anchor change; an attach it never picked up
/// is dropped — and unregistered — when a newer change supersedes it.
#[tokio::test]
async fn anchor_keeps_the_latest_update_and_unregisters_the_superseded_route() -> Result<()> {
    use outline_wire::h3_datagram::{DatagramDemux, DropReason, encode_datagram};

    let pair = quic_datagram_pair().await?;
    let unknown = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&unknown);
    let demux = DatagramDemux::spawn(
        pair.server.clone(),
        Arc::new(move |reason| {
            if reason == DropReason::UnknownStream {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }),
    );
    let anchor = DatagramAnchor::default();
    assert!(anchor.take_update().is_none());

    anchor.attach(route_on(&pair, &demux, 4));
    anchor.attach(route_on(&pair, &demux, 8));
    let Some(AnchorUpdate::Attach(route)) = anchor.take_update() else {
        panic!("expected the latest attach");
    };
    assert_eq!(route.quarter_stream_id, 8);
    assert!(anchor.take_update().is_none(), "an update is handed out once");

    // The superseded route for id 4 is gone from the demux.
    pair.client.send_datagram(encode_datagram(4, b"late"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while unknown.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "superseded route still registered");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    anchor.attach(route_on(&pair, &demux, 12));
    anchor.detach();
    assert!(matches!(anchor.take_update(), Some(AnchorUpdate::Detach)));
    drop(route);
    Ok(())
}

/// `next_update` wakes on a change published while it waits, and on one
/// published before it started waiting.
#[tokio::test]
async fn anchor_next_update_wakes_on_attach() -> Result<()> {
    use outline_wire::h3_datagram::DatagramDemux;

    let pair = quic_datagram_pair().await?;
    let demux = DatagramDemux::spawn(pair.server.clone(), Arc::new(|_| {}));
    let anchor = Arc::new(DatagramAnchor::default());

    let waiter = tokio::spawn({
        let anchor = Arc::clone(&anchor);
        async move { anchor.next_update().await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    anchor.attach(route_on(&pair, &demux, 4));
    let update = timeout(Duration::from_secs(5), waiter).await??;
    assert!(matches!(update, AnchorUpdate::Attach(route) if route.quarter_stream_id == 4));

    anchor.detach();
    let update = timeout(Duration::from_secs(5), anchor.next_update()).await?;
    assert!(matches!(update, AnchorUpdate::Detach));
    Ok(())
}

/// A route that stops delivering (its id registered again, or its connection
/// closed) must not keep the downlink: from then on packets ride the stream
/// until the next anchor brings a live route.
#[tokio::test]
async fn link_empties_the_target_when_its_route_stops_delivering() -> Result<()> {
    use outline_wire::h3_datagram::DatagramDemux;

    use super::{DatagramLink, LinkPolicy};

    let pair = quic_datagram_pair().await?;
    let demux = DatagramDemux::spawn(pair.server.clone(), Arc::new(|_| {}));
    let anchor = DatagramAnchor::with_route(route_on(&pair, &demux, QUARTER_ID));
    let target = Arc::new(DatagramTarget::empty());
    let mut link = DatagramLink::new(
        Arc::clone(&anchor),
        Arc::clone(&target),
        LinkPolicy::Immediate,
        Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))),
    );
    assert!(target.load().is_some());

    // Re-registering the id ends the link's registration.
    let _stolen = demux.register(QUARTER_ID);
    let _ = timeout(Duration::from_millis(300), link.next_datagram()).await;
    assert!(
        target.load().is_none(),
        "a route that stopped delivering must not take downlink"
    );
    Ok(())
}
