//! The carrier queues must be bounded by BYTES, not by frame count.
//!
//! Regression: the queues used to be bounded at 256 frames while the SS and
//! VLESS writers coalesce up to `FRAME_SOFT_CAP` (256 KiB) per frame, so a
//! back-pressured carrier could hold ~64 MiB per queue per session. These
//! tests pin the byte ceiling, the datagram-sized burst window (which must NOT
//! shrink — that would cost throughput), and that a bulk transfer still drains
//! end-to-end once the consumer keeps up.

use std::future::poll_fn;
use std::time::Duration;

use tokio::sync::mpsc;

use super::{
    BudgetedSink, CARRIER_QUEUE_BYTES, CARRIER_QUEUE_SLOTS, FRAME_SOFT_CAP, Queued, channel,
    sink_channel,
};

/// Frames the size the SS / VLESS writers actually emit under bulk load.
const BIG_FRAME: usize = FRAME_SOFT_CAP;
/// A datagram-sized frame (SS-UDP / VLESS-UDP ride the same queue).
const SMALL_FRAME: usize = 1_400;
/// How many big frames the byte budget admits at once.
const BIG_FRAMES_PER_BUDGET: usize = CARRIER_QUEUE_BYTES / BIG_FRAME;

/// A full slot-cap burst of datagrams must fit inside the byte budget, or the
/// byte bound would start costing packet rate on the UDP carriers.
const _: () = assert!(CARRIER_QUEUE_SLOTS * SMALL_FRAME < CARRIER_QUEUE_BYTES);

/// Drains `rx`, returning how many frames were sitting in it. Dropping each
/// `Queued` releases its permit, exactly as a consumer does once the frame is
/// on the wire.
fn drain<T>(rx: &mut mpsc::Receiver<Queued<T>>) -> usize {
    let mut drained = 0;
    while rx.try_recv().is_ok() {
        drained += 1;
    }
    drained
}

/// Drives the `Sink` half the way `XhttpStream`'s `Sink` impl does:
/// `poll_ready` (flush whatever is staged) → `start_send` → `poll_flush`.
async fn sink_send<T: Send + 'static>(
    sink: &mut BudgetedSink<T>,
    item: T,
    bytes: usize,
) -> Result<(), ()> {
    poll_fn(|cx| sink.poll_flush_queue(cx)).await.map_err(|_| ())?;
    sink.stage(item, bytes);
    poll_fn(|cx| sink.poll_flush_queue(cx)).await.map_err(|_| ())
}

#[tokio::test]
async fn big_frames_are_bounded_by_bytes_not_by_slot_count() {
    let (tx, mut rx) = channel::<Vec<u8>>();

    // Push big frames until the producer blocks. Under the old slot-only bound
    // this would have accepted CARRIER_QUEUE_SLOTS (256) frames = 64 MiB.
    let mut admitted = 0usize;
    loop {
        let frame = vec![0u8; BIG_FRAME];
        match tokio::time::timeout(Duration::from_millis(50), tx.send(frame, BIG_FRAME)).await {
            Ok(Ok(())) => admitted += 1,
            Ok(Err(_)) => panic!("receiver alive, send must not fail"),
            Err(_) => break, // producer parked: the queue is full
        }
        assert!(admitted <= CARRIER_QUEUE_SLOTS, "slot cap must still hold");
    }

    let queued_bytes = admitted * BIG_FRAME;
    assert!(
        queued_bytes <= CARRIER_QUEUE_BYTES,
        "queue admitted {queued_bytes} bytes, over the {CARRIER_QUEUE_BYTES}-byte budget",
    );
    assert_eq!(admitted, BIG_FRAMES_PER_BUDGET);
    assert!(
        admitted < CARRIER_QUEUE_SLOTS,
        "the byte budget must bind before the slot cap for {BIG_FRAME}-byte frames",
    );

    // Draining returns the permits, so the producer proceeds again.
    assert_eq!(drain(&mut rx), admitted);
    tokio::time::timeout(Duration::from_millis(200), tx.send(vec![0u8; BIG_FRAME], BIG_FRAME))
        .await
        .expect("send must resume once the consumer frees budget")
        .expect("receiver still alive");
}

#[tokio::test]
async fn small_frames_keep_the_full_burst_window() {
    let (tx, mut rx) = channel::<Vec<u8>>();

    // Datagram-sized frames must still get the historical 256-frame burst
    // window: sizing the queue by a frame count derived from the big-frame
    // case would throttle packet rate long before it bounded memory.
    for i in 0..CARRIER_QUEUE_SLOTS {
        tokio::time::timeout(
            Duration::from_millis(50),
            tx.send(vec![0u8; SMALL_FRAME], SMALL_FRAME),
        )
        .await
        .unwrap_or_else(|_| panic!("small frame {i} must not block below the slot cap"))
        .expect("receiver still alive");
    }

    // The next one blocks on the slot cap — the byte budget is nowhere near
    // full, which is exactly the property that keeps datagram throughput.
    let over = tokio::time::timeout(
        Duration::from_millis(50),
        tx.send(vec![0u8; SMALL_FRAME], SMALL_FRAME),
    )
    .await;
    assert!(over.is_err(), "slot cap must bound a flood of tiny frames");
    assert_eq!(drain(&mut rx), CARRIER_QUEUE_SLOTS);
}

#[tokio::test]
async fn control_frames_bypass_a_full_budget() {
    let (tx, mut rx) = channel::<Vec<u8>>();

    for _ in 0..BIG_FRAMES_PER_BUDGET {
        tx.send(vec![0u8; BIG_FRAME], BIG_FRAME)
            .await
            .expect("receiver alive");
    }

    // A Close must still enqueue: a teardown that cannot propagate because the
    // uplink is congested is exactly the stall this path must avoid.
    tokio::time::timeout(Duration::from_millis(200), tx.send_control(Vec::new()))
        .await
        .expect("control frame must not wait on the byte budget")
        .expect("receiver still alive");

    assert_eq!(drain(&mut rx), BIG_FRAMES_PER_BUDGET + 1);
}

#[tokio::test]
async fn bulk_transfer_drains_end_to_end_without_stalling() {
    let (tx, mut rx) = channel::<Vec<u8>>();

    // A consumer that keeps up — the writer task draining into the socket.
    let consumer = tokio::spawn(async move {
        let mut total = 0usize;
        while let Some(queued) = rx.recv().await {
            let (frame, permit) = queued.into_parts();
            total += frame.len();
            // Released only once the frame is "on the wire".
            drop(permit);
        }
        total
    });

    // 64 MiB of bulk uplink — 16x the byte budget, so it only completes if
    // permits are recycled as the consumer drains.
    let frames = 256;
    for _ in 0..frames {
        tx.send(vec![0u8; BIG_FRAME], BIG_FRAME)
            .await
            .expect("consumer alive");
    }
    drop(tx);

    let moved = tokio::time::timeout(Duration::from_secs(10), consumer)
        .await
        .expect("bulk transfer must not stall")
        .expect("consumer task panicked");
    assert_eq!(moved, frames * BIG_FRAME);
}

#[tokio::test]
async fn sink_half_pends_on_the_byte_budget_and_resumes_after_draining() {
    let (mut sink, mut rx) = sink_channel::<Vec<u8>>();

    // The XHTTP uplink produces through `Sink`, so the byte bound has to land
    // in `poll_ready`/`poll_flush` rather than in an `async fn send`.
    for _ in 0..BIG_FRAMES_PER_BUDGET {
        tokio::time::timeout(
            Duration::from_millis(50),
            sink_send(&mut sink, vec![0u8; BIG_FRAME], BIG_FRAME),
        )
        .await
        .expect("send must not block below the byte budget")
        .expect("receiver alive");
    }

    let over = tokio::time::timeout(
        Duration::from_millis(50),
        sink_send(&mut sink, vec![0u8; BIG_FRAME], BIG_FRAME),
    )
    .await;
    assert!(over.is_err(), "the Sink half must pend once the byte budget is exhausted");

    // The staged frame is admitted as soon as the consumer frees budget — and
    // exactly once: a re-poll must not charge the budget twice.
    assert_eq!(drain(&mut rx), BIG_FRAMES_PER_BUDGET);
    tokio::time::timeout(
        Duration::from_millis(200),
        sink_send(&mut sink, vec![0u8; BIG_FRAME], BIG_FRAME),
    )
    .await
    .expect("send must resume once the consumer frees budget")
    .expect("receiver alive");
    assert_eq!(drain(&mut rx), 2, "the frame staged while full, plus the new one");
}

#[tokio::test]
async fn sink_half_surfaces_a_dropped_consumer() {
    let (mut sink, rx) = sink_channel::<Vec<u8>>();
    drop(rx);

    let result = sink_send(&mut sink, vec![0u8; SMALL_FRAME], SMALL_FRAME).await;
    assert!(result.is_err(), "a dropped consumer must surface as an error");
    assert!(sink.is_closed());
}
