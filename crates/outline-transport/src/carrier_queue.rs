//! Byte-aware bounds for the per-session carrier queues.
//!
//! Every carrier hands its data frames to a background task through a bounded
//! mpsc: the SS and VLESS WebSocket writers, the XHTTP uplink driver, and the
//! XHTTP downlink drain. Bounding those queues by *message count* alone is not
//! a memory bound. The SS (`TcpShadowsocksWriter::send_chunks`) and VLESS
//! (`VlessTcpWriter::send_chunks`) writers coalesce a whole pump batch into a
//! single message capped at [`FRAME_SOFT_CAP`], so a 256-slot queue admits up
//! to 64 MiB per queue per session the moment the carrier back-pressures —
//! 16x what the old "~4 MB at the 16 KB chunk boundary" comments assumed, and
//! it materialises exactly when the uplink is congested. Datagram carriers sit
//! at the opposite extreme: one ~1.5 KiB message per slot, where a small slot
//! count would throttle packet rate long before it bounded anything.
//!
//! So the queues are bounded by bytes, with the slot count kept as a cheap
//! secondary guard against a flood of tiny frames. A producer acquires one
//! permit per byte from a per-queue [`Semaphore`] before enqueuing, and the
//! consumer releases them once the frame has been handed to the wire. Large
//! frames are therefore admitted few-at-a-time and small ones many-at-a-time;
//! either way a queue's resident payload stays under [`CARRIER_QUEUE_BYTES`]
//! (plus at most one in-flight frame, which is bounded by [`FRAME_SOFT_CAP`]
//! plus one AEAD record).
//!
//! Producers come in two shapes and both are served here:
//!   * `async fn send` — the WS writers and the XHTTP drains, via
//!     [`BudgetedSender`].
//!   * `Sink` — the XHTTP uplink, which is driven through `TransportStream`'s
//!     `Sink<Message>` and so cannot `await` inside `start_send`. [`BudgetedSink`]
//!     parks the item in `start_send` and acquires its permits in `poll_flush`,
//!     which `SinkExt::send` always drives.

use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::sync::mpsc::error::SendError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::{PollSemaphore, PollSender};

/// Soft cap on a coalesced data frame built by the SS and VLESS writers'
/// `send_chunks`. A single pump batch can span a full uplink receive window
/// (multiple MiB); flushing the frame once it passes this bound keeps the
/// writer's peak allocation (and the carrier message size) small instead of
/// building one window-sized buffer. Readers reassemble bytes across frames,
/// so splitting is transparent on the wire.
///
/// Single definition for both writers — the two used to carry their own copy
/// of this constant, which is how the queue sizing drifted out of sync with
/// the real frame size in the first place.
pub(crate) const FRAME_SOFT_CAP: usize = 256 * 1024;

/// Byte ceiling for one carrier queue (one direction of one session).
///
/// Sized well above the bandwidth-delay product a single session can keep in
/// flight — 4 MiB is ~320 ms of a 100 Mbit/s uplink, and the carrier's own
/// flow control (h2/h3 windows, the TLS/TCP socket buffer) is the real limit
/// long before this one binds. It exists to cap the *pathological* case: a
/// congested carrier with a producer that keeps coalescing 256 KiB frames.
pub(crate) const CARRIER_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Slot ceiling for one carrier queue. Unchanged from the historical value:
/// it still gives datagram carriers (~1.5 KiB per message) the burst window
/// they had before, while [`CARRIER_QUEUE_BYTES`] is what actually bounds
/// memory. A queue is full when *either* limit is reached.
pub(crate) const CARRIER_QUEUE_SLOTS: usize = 256;

/// Permits to charge for a frame of `bytes`.
///
/// Clamped to [`CARRIER_QUEUE_BYTES`] so a frame larger than the whole budget
/// (impossible for the coalescing writers, but a datagram carrier takes what
/// it is handed) cannot deadlock on permits that will never exist. Charged a
/// minimum of one so an empty frame still consumes a slot's worth of budget.
fn permits_for(bytes: usize) -> u32 {
    bytes.clamp(1, CARRIER_QUEUE_BYTES) as u32
}

/// A queued frame plus the byte permits it holds.
///
/// The consumer must keep `permit` alive until the frame has actually been
/// handed to the wire — dropping it earlier hands the budget back while the
/// bytes are still resident, which is exactly the accounting hole this module
/// exists to close.
pub(crate) struct Queued<T> {
    item: T,
    permit: Option<OwnedSemaphorePermit>,
}

impl<T> Queued<T> {
    /// Borrows the payload without giving up the permit — for consumers that
    /// need to look at the frame before deciding how to forward it.
    pub(crate) fn item(&self) -> &T {
        &self.item
    }

    /// Splits the payload from its budget permit. Hold the permit for as long
    /// as the payload's bytes are still resident.
    pub(crate) fn into_parts(self) -> (T, Option<OwnedSemaphorePermit>) {
        (self.item, self.permit)
    }

    /// Re-wraps the payload, carrying the same permit over. Used where a frame
    /// is forwarded from one queue to the next (the XHTTP stream-one driver
    /// moving a message onto the request-body channel) so both hops share a
    /// single charge against the budget instead of double-counting it.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Queued<U> {
        Queued { item: f(self.item), permit: self.permit }
    }
}

/// `async fn send` producer half of a byte-budgeted queue.
pub(crate) struct BudgetedSender<T> {
    tx: mpsc::Sender<Queued<T>>,
    budget: Arc<Semaphore>,
}

// Manual impl: `#[derive(Clone)]` would demand `T: Clone`, which the payloads
// (WS messages, hyper frames) do not need to be — only the handles are cloned.
impl<T> Clone for BudgetedSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            budget: Arc::clone(&self.budget),
        }
    }
}

impl<T> BudgetedSender<T> {
    /// Enqueues `item`, charging `bytes` against the queue's budget. Pends
    /// while the queue is full — by bytes or by slots — so the producer feels
    /// real back-pressure instead of growing the queue without bound.
    pub(crate) async fn send(&self, item: T, bytes: usize) -> Result<(), SendError<T>> {
        // `acquire_many_owned` only fails on a closed semaphore, which we never
        // do — but if it ever were, falling through unbudgeted is strictly
        // safer than dropping the frame: the slot cap still bounds the queue.
        let permit = Arc::clone(&self.budget)
            .acquire_many_owned(permits_for(bytes))
            .await
            .ok();
        self.tx
            .send(Queued { item, permit })
            .await
            .map_err(|e| SendError(e.0.item))
    }

    /// Enqueues a control frame (Close, an error notification) without charging
    /// the budget. These are tiny, rare, and must not be blocked by a queue
    /// that is full of data — a Close that cannot enqueue is a teardown that
    /// cannot propagate.
    pub(crate) async fn send_control(&self, item: T) -> Result<(), SendError<T>> {
        self.tx
            .send(Queued { item, permit: None })
            .await
            .map_err(|e| SendError(e.0.item))
    }
}

/// Builds a byte-budgeted queue with an `async fn send` producer half.
pub(crate) fn channel<T>() -> (BudgetedSender<T>, mpsc::Receiver<Queued<T>>) {
    let (tx, rx) = mpsc::channel(CARRIER_QUEUE_SLOTS);
    let budget = Arc::new(Semaphore::new(CARRIER_QUEUE_BYTES));
    (BudgetedSender { tx, budget }, rx)
}

/// The queue's consumer is gone. Surfaces to `Sink` callers, which map it onto
/// their own error type.
pub(crate) struct QueueClosed;

/// `Sink` producer half of a byte-budgeted queue.
///
/// `Sink::start_send` is synchronous, so the byte permits cannot be acquired
/// there. Instead [`Self::stage`] parks the item and [`Self::poll_flush_queue`]
/// acquires its permits and a channel slot — `SinkExt::send` drives `poll_flush`
/// after every `start_send`, so back-pressure lands on the producer exactly as
/// it does on the `async fn send` half. At most one staged frame sits outside
/// the budget at a time.
pub(crate) struct BudgetedSink<T: Send + 'static> {
    tx: PollSender<Queued<T>>,
    budget: PollSemaphore,
    /// Staged by `start_send`, drained by `poll_flush_queue`.
    pending: Option<(T, u32)>,
    /// Permits already acquired for `pending` while we wait for a channel slot.
    /// Kept across polls so a re-poll does not charge the budget twice.
    permit: Option<OwnedSemaphorePermit>,
}

impl<T: Send + 'static> BudgetedSink<T> {
    /// Stages `item` for the next [`Self::poll_flush_queue`]. Callers must have
    /// observed `Ready` from [`Self::poll_flush_queue`] first (the `Sink`
    /// contract), so nothing is overwritten.
    pub(crate) fn stage(&mut self, item: T, bytes: usize) {
        debug_assert!(self.pending.is_none(), "start_send without a preceding poll_ready");
        self.pending = Some((item, permits_for(bytes)));
    }

    /// Drives the staged frame into the queue: byte permits first, then a
    /// channel slot. `Ready(Ok(()))` once nothing is staged.
    pub(crate) fn poll_flush_queue(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), QueueClosed>> {
        let Some((_, permits)) = self.pending.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        if self.permit.is_none() {
            // Budget before slot: reserving a slot we then park on would pin it
            // for the whole wait and shrink the queue for everyone else.
            match ready!(self.budget.poll_acquire_many(cx, *permits)) {
                Some(permit) => self.permit = Some(permit),
                None => return Poll::Ready(Err(QueueClosed)),
            }
        }
        if ready!(self.tx.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(QueueClosed));
        }
        let (item, _) = self.pending.take().expect("pending checked above");
        let permit = self.permit.take();
        self.tx.send_item(Queued { item, permit }).map_err(|_| QueueClosed)?;
        Poll::Ready(Ok(()))
    }

    /// Closes the producer half. The consumer sees `None` and tears down.
    pub(crate) fn close(&mut self) {
        self.pending = None;
        self.permit = None;
        self.tx.close();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Builds a byte-budgeted queue with a `Sink` producer half.
pub(crate) fn sink_channel<T: Send + 'static>() -> (BudgetedSink<T>, mpsc::Receiver<Queued<T>>) {
    let (tx, rx) = mpsc::channel(CARRIER_QUEUE_SLOTS);
    let budget = Arc::new(Semaphore::new(CARRIER_QUEUE_BYTES));
    (
        BudgetedSink {
            tx: PollSender::new(tx),
            budget: PollSemaphore::new(budget),
            pending: None,
            permit: None,
        },
        rx,
    )
}

#[cfg(test)]
#[path = "tests/carrier_queue.rs"]
mod tests;
