use std::sync::Arc;

use bytes::Bytes;
use outline_wire::padding::{PaddingDecoder, PaddingScheme};
use tokio::sync::mpsc;

use super::*;

const HEADER: &[u8] = &[0x00, 0x00];

fn held() -> HeldResponseHeader {
    HeldResponseHeader::new(Bytes::from_static(HEADER))
}

#[tokio::test]
async fn header_rides_only_the_first_message() {
    let header = held();
    let (tx, mut rx) = mpsc::channel::<Bytes>(8);
    assert_eq!(header.pending_len(), 2);
    send_downlink(Some(&header), &tx, |b| b, PaddingScheme::disabled(), Bytes::from_static(b"one"))
        .await
        .unwrap();
    assert_eq!(header.pending_len(), 0);
    send_downlink(Some(&header), &tx, |b| b, PaddingScheme::disabled(), Bytes::from_static(b"two"))
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"\x00\x00one"));
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"two"));
}

#[tokio::test]
async fn no_header_sends_the_frame_unchanged() {
    let (tx, mut rx) = mpsc::channel::<Bytes>(8);
    send_downlink(None, &tx, |b| b, PaddingScheme::disabled(), Bytes::from_static(b"one"))
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"one"));
}

/// The header and its frame share one padding frame on a padded path, so the
/// header is no message of its own there either.
#[tokio::test]
async fn padded_header_shares_the_first_padding_frame() {
    let header = held();
    let scheme = PaddingScheme::new(0, 64);
    let (tx, mut rx) = mpsc::channel::<Bytes>(8);
    send_downlink(Some(&header), &tx, |b| b, scheme, Bytes::from_static(b"data"))
        .await
        .unwrap();
    let message = rx.recv().await.unwrap();
    let mut decoder = PaddingDecoder::new();
    let mut plain = Vec::new();
    decoder.push(&message, &mut plain);
    assert_eq!(plain, b"\x00\x00data");
    assert!(rx.try_recv().is_err(), "header and data must be one message");
}

/// Many writers racing for the first message: whatever order they land in, the
/// header is the first two bytes of the stream and appears exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_never_overtake_the_header() {
    for _ in 0..200 {
        let header = Arc::new(held());
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let header = Arc::clone(&header);
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..4 {
                    send_downlink(
                        Some(&header),
                        &tx,
                        |b| b,
                        PaddingScheme::disabled(),
                        Bytes::from(vec![0xA0 | i; 3]),
                    )
                    .await
                    .unwrap();
                }
            }));
        }
        drop(tx);
        for task in tasks {
            task.await.unwrap();
        }
        let mut stream = Vec::new();
        while let Some(m) = rx.recv().await {
            stream.extend_from_slice(&m);
        }
        assert_eq!(&stream[..2], HEADER);
        assert_eq!(stream.len(), 2 + 8 * 4 * 3, "header must appear exactly once");
        assert!(stream[2..].iter().all(|b| b & 0xF0 == 0xA0));
    }
}

/// A send dropped while it waits on a full channel queues nothing, so the
/// header must still lead the next message.
#[tokio::test]
async fn cancelled_send_keeps_the_header_for_the_next_writer() {
    let header = held();
    let (tx, mut rx) = mpsc::channel::<Bytes>(1);
    tx.send(Bytes::from_static(b"filler")).await.unwrap();
    let blocked = send_downlink(
        Some(&header),
        &tx,
        |b| b,
        PaddingScheme::disabled(),
        Bytes::from_static(b"lost"),
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), blocked)
            .await
            .is_err(),
        "the send must block on the full channel",
    );
    assert_eq!(header.pending_len(), 2, "a cancelled send must not consume the header");
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"filler"));
    send_downlink(
        Some(&header),
        &tx,
        |b| b,
        PaddingScheme::disabled(),
        Bytes::from_static(b"next"),
    )
    .await
    .unwrap();
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"\x00\x00next"));
}
