//! Datagram record framing on the client-side XHTTP carrier.
//!
//! The carrier hands the reader arbitrary slices of the HTTP body, so these
//! tests feed the inbound channel chunks that do NOT line up with datagram
//! boundaries and assert the stream still yields exactly the datagrams the
//! server framed.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use outline_wire::udp_records::encode_record_into;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::guards::AbortOnDrop;
use crate::xhttp::{XhttpStream, XhttpSubmode, inbound_channel, outbound_channel};

fn framed(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for payload in payloads {
        encode_record_into(payload, &mut out).expect("test payloads fit a record");
    }
    out
}

/// Builds a stream over channels the test drives directly. The driver task is
/// an immediately-finished no-op: these tests exercise the framing layer, not
/// the HTTP carrier underneath it.
fn test_stream(
    udp_records: bool,
) -> (crate::xhttp::InboundSender, XhttpStream, crate::xhttp::OutboundReceiver) {
    let (in_tx, in_rx) = inbound_channel();
    let (out_tx, out_rx) = outbound_channel();
    let driver = AbortOnDrop::new(tokio::spawn(std::future::pending::<()>()));
    let stream = XhttpStream::from_channels(
        in_rx,
        out_tx,
        driver,
        XhttpSubmode::PacketUp,
        false,
        udp_records,
        None,
        None,
    );
    (in_tx, stream, out_rx)
}

async fn feed(tx: &crate::xhttp::InboundSender, chunk: &[u8]) {
    let bytes = Bytes::copy_from_slice(chunk);
    let len = bytes.len();
    tx.send(Ok(Message::Binary(bytes)), len)
        .await
        .expect("inbound channel open");
}

async fn next_binary(stream: &mut XhttpStream) -> Vec<u8> {
    match stream.next().await {
        Some(Ok(Message::Binary(b))) => b.to_vec(),
        other => panic!("expected a binary frame, got {other:?}"),
    }
}

#[tokio::test]
async fn splits_two_datagrams_delivered_in_one_chunk() {
    let (tx, mut stream, _out) = test_stream(true);
    feed(&tx, &framed(&[b"first datagram", b"second"])).await;

    assert_eq!(next_binary(&mut stream).await, b"first datagram".to_vec());
    assert_eq!(next_binary(&mut stream).await, b"second".to_vec());
}

#[tokio::test]
async fn rejoins_a_datagram_split_across_two_chunks() {
    let (tx, mut stream, _out) = test_stream(true);
    let wire = framed(&[b"a datagram sliced mid-flight"]);
    let (head, tail) = wire.split_at(5);
    feed(&tx, head).await;
    feed(&tx, tail).await;

    assert_eq!(next_binary(&mut stream).await, b"a datagram sliced mid-flight".to_vec());
}

#[tokio::test]
async fn recovers_datagrams_from_chunks_that_straddle_boundaries() {
    // The pathological mix seen in production: a chunk carries the tail of one
    // datagram, a whole second one, and the head of a third.
    let (tx, mut stream, _out) = test_stream(true);
    let wire = framed(&[b"alpha", b"bravo", b"charlie"]);
    feed(&tx, &wire[..4]).await;
    feed(&tx, &wire[4..15]).await;
    feed(&tx, &wire[15..]).await;

    assert_eq!(next_binary(&mut stream).await, b"alpha".to_vec());
    assert_eq!(next_binary(&mut stream).await, b"bravo".to_vec());
    assert_eq!(next_binary(&mut stream).await, b"charlie".to_vec());
}

#[tokio::test]
async fn frames_outbound_datagrams() {
    let (_tx, mut stream, mut out) = test_stream(true);
    stream
        .send(Message::Binary(Bytes::from_static(b"uplink")))
        .await
        .expect("send on an open stream");

    let queued = out.recv().await.expect("outbound queue carries the frame");
    let (msg, _permit) = queued.into_parts();
    match msg {
        Message::Binary(b) => assert_eq!(b.to_vec(), framed(&[b"uplink"])),
        other => panic!("expected a binary frame, got {other:?}"),
    }
}

#[tokio::test]
async fn leaves_the_wire_untouched_when_framing_is_not_negotiated() {
    // Unnegotiated sessions (a server that predates the feature, or any
    // non-datagram XHTTP session) must keep the historical byte-for-byte wire.
    let (tx, mut stream, mut out) = test_stream(false);
    feed(&tx, b"raw chunk").await;
    assert_eq!(next_binary(&mut stream).await, b"raw chunk".to_vec());

    stream
        .send(Message::Binary(Bytes::from_static(b"uplink")))
        .await
        .expect("send on an open stream");
    let queued = out.recv().await.expect("outbound queue carries the frame");
    let (msg, _permit) = queued.into_parts();
    match msg {
        Message::Binary(b) => assert_eq!(b.to_vec(), b"uplink".to_vec()),
        other => panic!("expected a binary frame, got {other:?}"),
    }
}

#[tokio::test]
async fn passes_control_frames_through_unframed() {
    let (tx, mut stream, _out) = test_stream(true);
    tx.send_control(Ok(Message::Close(None)))
        .await
        .expect("inbound channel open");

    match stream.next().await {
        Some(Ok(Message::Close(None))) => {},
        other => panic!("expected the close frame, got {other:?}"),
    }
}

/// The UDP-over-HTTP/3-datagram offer rides the session-opening request next to
/// the record-framing one, and only when asked for; the echo counts only when
/// it answers an offer.
#[test]
fn udp_datagram_offer_and_echo() {
    use crate::request_headers::{HttpVersion, RequestKind};
    use crate::xhttp::{
        SessionRequest, UDP_DATAGRAM_HEADER, UDP_RECORDS_HEADER, build_session_request_headers,
        parse_udp_datagram_echo,
    };

    let request = SessionRequest {
        profile: None,
        kind: RequestKind::FetchGet,
        version: HttpVersion::H3,
        origin: "https://example.com",
        host: None,
    };
    let offered =
        build_session_request_headers(request, None, false, false, 0, true, true).expect("headers");
    assert_eq!(offered.get(UDP_DATAGRAM_HEADER).map(|v| v.as_bytes()), Some(&b"1"[..]));
    assert_eq!(offered.get(UDP_RECORDS_HEADER).map(|v| v.as_bytes()), Some(&b"1"[..]));
    let plain = build_session_request_headers(request, None, false, false, 0, true, false)
        .expect("headers");
    assert!(plain.get(UDP_DATAGRAM_HEADER).is_none(), "no offer unless asked");
    let mut without_offer = offered.clone();
    without_offer.remove(UDP_DATAGRAM_HEADER);
    assert_eq!(plain, without_offer, "the offer adds exactly one header");

    let mut echo = http::HeaderMap::new();
    echo.insert(UDP_DATAGRAM_HEADER, http::HeaderValue::from_static("1"));
    assert!(parse_udp_datagram_echo(true, &echo));
    assert!(!parse_udp_datagram_echo(false, &echo), "an unsolicited echo is ignored");
    assert!(!parse_udp_datagram_echo(true, &http::HeaderMap::new()));
    echo.insert(UDP_DATAGRAM_HEADER, http::HeaderValue::from_static("0"));
    assert!(!parse_udp_datagram_echo(true, &echo));
}
