//! A response header held back for the first downlink message of a session
//! whose downlink has several concurrent writers.
//!
//! The VLESS `[VERSION, 0x00]` response header is two bytes — 21 once padded —
//! and a fixed-size message of its own is a marker a record-size classifier
//! keys on. A single-writer relay simply keeps it in a local and prepends it to
//! the first data it reads. A VLESS-mux session cannot: every sub-connection's
//! reader task, and the frame handler's `End` replies, write into the same
//! carrier channel, and any of them may be first. This type is the shared
//! version of that local: whichever writer sends first carries the header, and
//! no writer's message can reach the channel ahead of it.

use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Bytes, BytesMut};
use outline_wire::padding::PaddingScheme;
use tokio::sync::{Mutex, mpsc};

use super::carrier_padding;

pub(in crate::server::transport) struct HeldResponseHeader {
    /// Set (Release) only once the message carrying the header is in the
    /// channel, so a writer that sees it (Acquire) queues behind that message.
    sent: AtomicBool,
    /// The header, until the send that carries it succeeds. Held across that
    /// send, which is what keeps a concurrent writer from overtaking it.
    slot: Mutex<Option<Bytes>>,
    len: usize,
}

impl HeldResponseHeader {
    pub(in crate::server::transport) fn new(header: Bytes) -> Self {
        let len = header.len();
        Self {
            sent: AtomicBool::new(false),
            slot: Mutex::new(Some(header)),
            len,
        }
    }

    /// Bytes the next message may still have to carry in front of its frame:
    /// the header length until it has gone out, then 0. A reader sizing its
    /// read to an h2 cap subtracts this, so the header-carrying message still
    /// fits. Monotonic: once 0 it stays 0, and while it is non-zero no message
    /// has carried the header yet.
    pub(in crate::server::transport) fn pending_len(&self) -> usize {
        if self.sent.load(Ordering::Acquire) { 0 } else { self.len }
    }
}

/// Queues one downlink `frame`, framed for `padding`, with the held header in
/// front of it when this is the session's first downlink message. `header` is
/// `None` when the session owes no header (it was sent already, or a relayed
/// mux on the home, whose edge sends its own).
///
/// Cancel-safe: the header leaves its slot only after the send that carries it
/// succeeded, and `mpsc::Sender::send` queues nothing when dropped, so a
/// cancelled call leaves the header for the next writer.
pub(in crate::server::transport) async fn send_downlink<Msg>(
    header: Option<&HeldResponseHeader>,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    padding: PaddingScheme,
    frame: Bytes,
) -> Result<(), mpsc::error::SendError<Msg>> {
    if let Some(held) = header
        && !held.sent.load(Ordering::Acquire)
    {
        let mut slot = held.slot.lock().await;
        if let Some(h) = slot.as_ref() {
            let mut joined = BytesMut::with_capacity(h.len() + frame.len());
            joined.extend_from_slice(h);
            joined.extend_from_slice(&frame);
            let message = carrier_padding::frame_downlink_message(padding, joined.freeze());
            tx.send(make_binary(message)).await?;
            *slot = None;
            held.sent.store(true, Ordering::Release);
            return Ok(());
        }
    }
    tx.send(make_binary(carrier_padding::frame_downlink_message(padding, frame)))
        .await
}

#[cfg(test)]
#[path = "tests/held_header.rs"]
mod tests;
