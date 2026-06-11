//! Regression: `XhttpStream` Sink must apply real back-pressure
//! when its outbound channel is full instead of failing fast.
//!
//! The earlier implementation reported `Poll::Ready(Ok(()))` from
//! `poll_ready` unconditionally and used `try_send` in `start_send`,
//! returning `Err("xhttp outgoing buffer full")` once the channel
//! filled up. The writer task above us treats any Sink error as
//! fatal and exits, so a bulk upload would stall after roughly
//! `OUTBOUND_CHANNEL_CAPACITY` messages with no recovery path.
//!
//! With the `PollSender`-based Sink the third send below must pend
//! until the receiver drains a slot — exactly the property bulk
//! transfers depend on.

use std::time::Duration;

use bytes::Bytes;
use futures_util::SinkExt;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::guards::AbortOnDrop;
use crate::xhttp::{XhttpStream, XhttpSubmode};

#[tokio::test]
async fn full_outbound_channel_pends_instead_of_erroring() {
    let (_in_tx, in_rx) = mpsc::channel::<Result<Message, _>>(4);
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(2);
    let dummy_driver = AbortOnDrop::new(tokio::spawn(async {
        std::future::pending::<()>().await;
    }));
    let mut stream =
        XhttpStream::from_channels(in_rx, out_tx, dummy_driver, XhttpSubmode::PacketUp);

    stream.send(Message::Binary(Bytes::from_static(&[1]))).await.unwrap();
    stream.send(Message::Binary(Bytes::from_static(&[2]))).await.unwrap();

    let pending = tokio::time::timeout(
        Duration::from_millis(50),
        stream.send(Message::Binary(Bytes::from_static(&[3]))),
    )
    .await;
    assert!(pending.is_err(), "Sink::send must pend on a full outbound channel");

    let first = out_rx.recv().await.expect("receiver still open");
    match first {
        Message::Binary(payload) => assert_eq!(payload.as_ref(), &[1]),
        other => panic!("unexpected first message: {other:?}"),
    }

    tokio::time::timeout(
        Duration::from_millis(200),
        stream.send(Message::Binary(Bytes::from_static(&[3]))),
    )
    .await
    .expect("send must complete once a permit is freed")
    .expect("send must succeed once a permit is freed");
}

#[tokio::test]
async fn closed_receiver_surfaces_as_sink_error() {
    let (_in_tx, in_rx) = mpsc::channel::<Result<Message, _>>(4);
    let (out_tx, out_rx) = mpsc::channel::<Message>(2);
    drop(out_rx);
    let dummy_driver = AbortOnDrop::new(tokio::spawn(async {
        std::future::pending::<()>().await;
    }));
    let mut stream =
        XhttpStream::from_channels(in_rx, out_tx, dummy_driver, XhttpSubmode::PacketUp);

    let err = stream
        .send(Message::Binary(Bytes::from_static(&[1])))
        .await
        .expect_err("send must fail when the receiver is gone");
    assert!(err.to_string().contains("xhttp outgoing closed"));
}
