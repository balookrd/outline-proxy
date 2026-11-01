//! `forward_vless_udp_datagram` on a padded path: what a client HTTP/3
//! datagram must hold to reach the upstream, and how the rest is counted.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use outline_wire::h3_datagram::decode_datagram;
use outline_wire::padding::{PaddingDecoder, PaddingScheme};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

use super::super::carrier_padding::frame_downlink_message;
use super::super::h3_datagram::tests::{QuicDatagramPair, quic_datagram_pair};
use super::super::h3_datagram::{
    DatagramActivity, DatagramPeer, DatagramTarget, VLESS_PROTO_LABEL,
};
use super::super::upstream_source::VlessUdpSink;
use super::super::vless::{UdpUpstream, VlessRelayOutcome, VlessWsRouteCtx};
use super::{DatagramDownlink, forward_vless_udp_datagram, send_downlink};
use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::abort::AbortOnDrop;
use crate::server::tests::sample_config;

const SCHEME: PaddingScheme = PaddingScheme::new(4, 16);

fn padded(real: &'static [u8]) -> Bytes {
    frame_downlink_message(SCHEME, Bytes::from_static(real))
}

/// Sum of the samples of `metric` whose labels include every `labels` pair.
fn counter(metrics: &Metrics, metric: &str, labels: &[&str]) -> f64 {
    metrics
        .render_prometheus()
        .lines()
        .filter(|line| line.starts_with(metric) && labels.iter().all(|l| line.contains(l)))
        .filter_map(|line| line.rsplit_once(' ')?.1.parse::<f64>().ok())
        .sum()
}

#[tokio::test]
async fn padded_datagrams_reach_the_upstream_only_as_one_whole_record() -> Result<()> {
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    socket.connect(target.local_addr()?).await?;
    let mut udp = UdpUpstream {
        sink: VlessUdpSink::Socket(Arc::new(socket)),
        reader_task: AbortOnDrop::new(tokio::spawn(async {
            Ok::<_, anyhow::Error>(VlessRelayOutcome::Closed)
        })),
        cancel: Arc::new(Notify::new()),
        target_display: Arc::from("test"),
        client_buffer: BytesMut::new(),
    };
    let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))));
    let route = VlessWsRouteCtx {
        users: Arc::from(Vec::new()),
        protocol: Protocol::Http3,
        path: Arc::from("/vless"),
        candidate_users: Arc::from(Vec::new()),
        padding: SCHEME,
        peer: None,
    };
    let malformed = ["outline_ss_udp_h3_datagram_dropped_total", "reason=\"malformed\""];

    // A truncated padding frame decodes to nothing: not a cover (none travels
    // as a datagram), so malformed.
    let truncated = padded(&[0, 3, b'x', b'y', b'z']).slice(..6);
    forward_vless_udp_datagram(&mut udp, truncated, None, &metrics, &route).await?;
    // A whole frame around a record whose length overruns it.
    forward_vless_udp_datagram(&mut udp, padded(&[0, 9, b'q']), None, &metrics, &route).await?;
    assert_eq!(counter(&metrics, malformed[0], &malformed[1..]), 2.0);

    // One padded record goes out, alone.
    forward_vless_udp_datagram(&mut udp, padded(&[0, 3, b'a', b'b', b'c']), None, &metrics, &route)
        .await?;
    let mut buf = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), target.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], b"abc");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.recv(&mut buf))
            .await
            .is_err(),
        "a dropped datagram reached the upstream"
    );
    assert_eq!(
        counter(
            &metrics,
            "outline_ss_udp_h3_datagrams_total",
            &["direction=\"up\"", "proto=\"vless\""]
        ),
        1.0
    );
    assert_eq!(counter(&metrics, malformed[0], &malformed[1..]), 2.0);
    Ok(())
}

fn datagram_downlink(pair: &QuicDatagramPair) -> DatagramDownlink {
    DatagramDownlink {
        target: Arc::new(DatagramTarget::from_pointee(DatagramPeer {
            connection: pair.server.clone(),
            quarter_stream_id: 70,
        })),
        monitor: None,
        metrics: Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))),
        activity: Arc::new(DatagramActivity::default()),
        transport: Transport::Udp,
        protocol: Protocol::Http3,
        app_protocol: AppProtocol::Vless,
        proto: VLESS_PROTO_LABEL,
    }
}

/// A padded record that fits only with a cut pad rides a datagram; one that
/// cannot fit even bare goes to the stream, framed over the full pad range.
#[tokio::test]
async fn downlink_record_is_cut_to_the_datagram_or_framed_for_the_stream() -> Result<()> {
    let pair = quic_datagram_pair().await?;
    let downlink = datagram_downlink(&pair);
    let scheme = PaddingScheme::new(0, 256);
    let (tx, mut rx) = mpsc::channel::<Bytes>(8);
    let room = pair.server.max_datagram_size().context("datagrams negotiated")? - 2;
    assert!(room >= 1356, "test needs the usual room, got {room}");

    let record = Bytes::from(vec![0x42; 1352]);
    for _ in 0..50 {
        send_downlink(&tx, |bytes| bytes, Some(&downlink), scheme, record.clone()).await?;
        let datagram =
            tokio::time::timeout(Duration::from_secs(5), pair.client.read_datagram()).await??;
        let (_, body) = decode_datagram(datagram).context("datagram prefix")?;
        assert_eq!(u16::from_be_bytes([body[0], body[1]]), 1352);
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&body, &mut decoded);
        assert_eq!(decoded, record);
    }
    assert!(rx.try_recv().is_err(), "nothing rode the stream");

    // Past any datagram size QUIC can reach here, even after PMTU growth.
    let oversized = Bytes::from(vec![0x24; 4096]);
    send_downlink(&tx, |bytes| bytes, Some(&downlink), scheme, oversized.clone()).await?;
    let message = rx.try_recv().expect("one Binary message");
    assert!(rx.try_recv().is_err());
    let pad_len = u16::from_be_bytes([message[2], message[3]]) as usize;
    assert!(pad_len <= 256, "pad {pad_len} outside the scheme");
    let mut decoded = Vec::new();
    PaddingDecoder::new().push(&message, &mut decoded);
    assert_eq!(decoded, oversized);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), pair.client.read_datagram())
            .await
            .is_err(),
        "an oversized record must not also go out as a datagram"
    );
    Ok(())
}
