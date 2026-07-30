use super::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

/// The relay's keepalive tick reaches the XHTTP carrier as
/// `XhttpMsg::Noop`. It must `touch()` the session so the registry
/// janitor does not evict an idle-but-live UDP datagram relay — an
/// eviction the client observes as a spurious `ws closed`.
#[tokio::test]
async fn noop_keepalive_touches_session() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));

    // Let real wall-clock advance so a cutoff can sit strictly between
    // session creation and the keepalive touch. `touch`/`is_idle_since`
    // read `std::time::Instant`, which tokio's paused clock does not
    // move — a short real sleep is the simplest reliable lever.
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Never touched: last activity == creation (~40 ms ago), older than
    // a 20-ms-ago cutoff → reads as idle.
    let cutoff_before = Instant::now() - Duration::from_millis(20);
    assert!(
        session.is_idle_since(cutoff_before),
        "a never-touched session should read as idle past the cutoff"
    );

    let duplex = XhttpDuplex {
        session: Arc::clone(&session),
        udp_records: false,
    };
    let (_reader, mut writer) = duplex.split_io();
    XhttpDuplex::send(&mut writer, XhttpMsg::Noop)
        .await
        .expect("Noop keepalive send must succeed");

    // Touched: last activity is now ~now, newer than a 20-ms-ago cutoff
    // → no longer idle. This is what keeps the janitor off a live relay
    // during a lull between datagrams.
    let cutoff_after = Instant::now() - Duration::from_millis(20);
    assert!(
        !session.is_idle_since(cutoff_after),
        "Noop keepalive must touch the session so the janitor spares a live relay"
    );
}

/// A `Close` on the XHTTP carrier still tears the session down — the
/// keepalive change must not blunt the close path.
#[tokio::test]
async fn close_still_closes_session() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    let duplex = XhttpDuplex {
        session: Arc::clone(&session),
        udp_records: false,
    };
    let (_reader, mut writer) = duplex.split_io();

    XhttpDuplex::send(&mut writer, XhttpMsg::Close).await.unwrap();
    assert!(session.is_closed(), "Close must close the session");
}

/// The XHTTP carrier is a byte stream: an uplink chunk is an arbitrary slice
/// of it, so two datagrams can arrive glued together and one can arrive split
/// in half. With record framing negotiated, `recv` must hand the relay back
/// exactly the datagrams the client framed — anything else feeds a spliced
/// buffer into the per-packet AEAD decrypt.
#[tokio::test]
async fn recv_recovers_datagram_boundaries_from_arbitrary_chunks() {
    use outline_wire::udp_records::encode_record_into;

    let mut wire = Vec::new();
    for payload in [b"first datagram".as_slice(), b"second".as_slice(), b"third".as_slice()] {
        encode_record_into(payload, &mut wire).expect("test payloads fit a record");
    }

    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    // Chunk 1 holds datagram one plus the head of datagram two; chunk 2 the
    // rest of two and the head of three; chunk 3 the tail.
    let cuts = [20usize, 30usize];
    session
        .ingest_uplink_inorder(Bytes::copy_from_slice(&wire[..cuts[0]]))
        .unwrap();
    session
        .ingest_uplink_inorder(Bytes::copy_from_slice(&wire[cuts[0]..cuts[1]]))
        .unwrap();
    session
        .ingest_uplink_inorder(Bytes::copy_from_slice(&wire[cuts[1]..]))
        .unwrap();
    session.close_uplink();

    let duplex = XhttpDuplex::with_udp_records(Arc::clone(&session), true);
    let (mut reader, _writer) = duplex.split_io();

    let mut received = Vec::new();
    while let Some(msg) = XhttpDuplex::recv(&mut reader).await.expect("uplink read") {
        match XhttpDuplex::classify(msg) {
            WsFrame::Binary(data) => received.push(data.to_vec()),
            other => panic!("expected binary frames, got {:?}", std::mem::discriminant(&other)),
        }
    }

    assert_eq!(
        received,
        vec![b"first datagram".to_vec(), b"second".to_vec(), b"third".to_vec()],
    );
}

/// Downlink half: every datagram the relay writes goes on the wire as its own
/// length-prefixed record, so the client can recover the boundary from a body
/// chunk that carries several of them.
#[tokio::test]
async fn send_frames_each_downlink_datagram() {
    use outline_wire::udp_records::encode_record_into;

    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    let duplex = XhttpDuplex::with_udp_records(Arc::clone(&session), true);
    let (_reader, mut writer) = duplex.split_io();

    XhttpDuplex::send(&mut writer, XhttpMsg::Binary(Bytes::from_static(b"alpha")))
        .await
        .unwrap();
    XhttpDuplex::send(&mut writer, XhttpMsg::Binary(Bytes::from_static(b"bravo")))
        .await
        .unwrap();

    let mut drained: Vec<Bytes> = Vec::new();
    session.drain_downlink(&mut drained);
    let on_wire: Vec<u8> = drained.iter().flat_map(|chunk| chunk.to_vec()).collect();

    let mut expected = Vec::new();
    encode_record_into(b"alpha", &mut expected).unwrap();
    encode_record_into(b"bravo", &mut expected).unwrap();
    assert_eq!(on_wire, expected);
}

/// A session that did not negotiate framing (an older client, or any non
/// SS-UDP path) keeps the historical wire byte-for-byte.
#[tokio::test]
async fn unnegotiated_session_keeps_the_plain_wire() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    session
        .ingest_uplink_inorder(Bytes::from_static(b"raw chunk"))
        .unwrap();
    session.close_uplink();

    let duplex = XhttpDuplex {
        session: Arc::clone(&session),
        udp_records: false,
    };
    let (mut reader, mut writer) = duplex.split_io();

    match XhttpDuplex::recv(&mut reader)
        .await
        .unwrap()
        .map(XhttpDuplex::classify)
    {
        Some(WsFrame::Binary(data)) => assert_eq!(data.to_vec(), b"raw chunk".to_vec()),
        _ => panic!("expected the chunk to pass through unframed"),
    }

    XhttpDuplex::send(&mut writer, XhttpMsg::Binary(Bytes::from_static(b"alpha")))
        .await
        .unwrap();
    let mut drained: Vec<Bytes> = Vec::new();
    session.drain_downlink(&mut drained);
    assert_eq!(drained, vec![Bytes::from_static(b"alpha")]);
}
