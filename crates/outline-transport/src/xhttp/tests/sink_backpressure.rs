//! Regression: `XhttpStream`'s Sink must apply real back-pressure when its
//! outbound queue is full instead of failing fast — and the queue must be
//! bounded by BYTES, not by frame count.
//!
//! The first implementation reported `Poll::Ready(Ok(()))` from `poll_ready`
//! unconditionally and used `try_send` in `start_send`, so a bulk upload
//! stalled fatally once the channel filled. The second bounded the channel at
//! 256 frames — real back-pressure, but the SS/VLESS writers coalesce up to
//! `FRAME_SOFT_CAP` (256 KiB) per frame, so that admitted ~64 MiB per session
//! on a congested carrier. Now the queue is byte-budgeted
//! (`crate::carrier_queue`): sends pend once the budget is exhausted and
//! resume as the driver drains it.

use std::time::Duration;

use bytes::Bytes;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::carrier_queue::{CARRIER_QUEUE_BYTES, CARRIER_QUEUE_SLOTS, FRAME_SOFT_CAP};
use crate::guards::AbortOnDrop;
use crate::xhttp::{XhttpStream, XhttpSubmode, inbound_channel, outbound_channel};

fn dummy_driver() -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async {
        std::future::pending::<()>().await;
    }))
}

fn big_frame() -> Message {
    Message::Binary(Bytes::from(vec![0u8; FRAME_SOFT_CAP]))
}

#[tokio::test]
async fn full_outbound_queue_pends_instead_of_erroring() {
    let (_in_tx, in_rx) = inbound_channel();
    let (out_tx, mut out_rx) = outbound_channel();
    let mut stream =
        XhttpStream::from_channels(in_rx, out_tx, dummy_driver(), XhttpSubmode::PacketUp, false);

    // Fill the byte budget with writer-sized frames.
    let admitted = CARRIER_QUEUE_BYTES / FRAME_SOFT_CAP;
    for _ in 0..admitted {
        stream.send(big_frame()).await.expect("driver alive");
    }
    assert!(
        admitted < CARRIER_QUEUE_SLOTS,
        "the byte budget must bind before the slot cap — otherwise the queue \
         would hold {CARRIER_QUEUE_SLOTS} x {FRAME_SOFT_CAP} bytes",
    );

    let pending = tokio::time::timeout(Duration::from_millis(50), stream.send(big_frame())).await;
    assert!(pending.is_err(), "Sink::send must pend on a full outbound queue");

    // Drain the queue: every permit goes back to the budget. (The frame whose
    // send timed out above is still staged in the Sink — it is admitted by the
    // next poll, ahead of any new frame.)
    let mut drained = 0;
    while let Ok(queued) = out_rx.try_recv() {
        let (msg, permit) = queued.into_parts();
        match msg {
            Message::Binary(payload) => assert_eq!(payload.len(), FRAME_SOFT_CAP),
            other => panic!("unexpected queued message: {other:?}"),
        }
        drop(permit);
        drained += 1;
    }
    assert_eq!(drained, admitted);

    tokio::time::timeout(Duration::from_millis(500), stream.send(big_frame()))
        .await
        .expect("send must complete once budget is freed")
        .expect("send must succeed once budget is freed");

    let mut after = 0;
    while out_rx.try_recv().is_ok() {
        after += 1;
    }
    assert_eq!(after, 2, "the frame staged while full, plus the new one");
}

#[tokio::test]
async fn small_frames_are_not_throttled_by_the_byte_budget() {
    let (_in_tx, in_rx) = inbound_channel();
    let (out_tx, mut out_rx) = outbound_channel();
    let mut stream =
        XhttpStream::from_channels(in_rx, out_tx, dummy_driver(), XhttpSubmode::PacketUp, false);

    // Datagram-sized frames keep the full slot window — the byte bound must not
    // cost packet rate on SS-UDP / VLESS-UDP over XHTTP.
    for i in 0..CARRIER_QUEUE_SLOTS {
        tokio::time::timeout(
            Duration::from_millis(50),
            stream.send(Message::Binary(Bytes::from(vec![0u8; 1_400]))),
        )
        .await
        .unwrap_or_else(|_| panic!("datagram {i} must not block below the slot cap"))
        .expect("driver alive");
    }

    let mut drained = 0;
    while out_rx.try_recv().is_ok() {
        drained += 1;
    }
    assert_eq!(drained, CARRIER_QUEUE_SLOTS);
}

#[tokio::test]
async fn closed_receiver_surfaces_as_sink_error() {
    let (_in_tx, in_rx) = inbound_channel();
    let (out_tx, out_rx) = outbound_channel();
    drop(out_rx);
    let mut stream =
        XhttpStream::from_channels(in_rx, out_tx, dummy_driver(), XhttpSubmode::PacketUp, false);

    let err = stream
        .send(Message::Binary(Bytes::from_static(&[1])))
        .await
        .expect_err("send must fail when the receiver is gone");
    assert!(err.to_string().contains("xhttp outgoing closed"));
}
