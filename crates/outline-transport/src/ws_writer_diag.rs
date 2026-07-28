//! Shared diagnostics for the WebSocket writer tasks.
//!
//! Both WS writer tasks — `tcp_transport::writer::transport` (SS-over-WS) and
//! `frame_io_ws` (VLESS byte-chunk and datagram pipes) — terminate as soon as a
//! sink write fails. The overwhelming majority of those failures are not faults
//! at all: the carrier was already gone (peer closed it, our own `close()` ran
//! first, the H3 stream ended) and the queued frame simply had nowhere to go.
//! Logging that at `warn!` made one line account for 92 % of all warnings on a
//! production client (3830 of them in 48 h on a single node), which buries the
//! writes that really did fail.
//!
//! So the classification here is the gate: an expected close is `debug` plus a
//! counter, anything else keeps its `warn!`. The predicate mirrors
//! `is_expected_h3_close` / `is_expected_h2_close` in the shared-connection
//! caches — same idea (a small table of close-shaped substrings, plus the typed
//! variants where the error type gives us one), just applied to the write side.

use std::io;

use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, warn};

use crate::error_classify::contains_any;

/// `writer` label values. Two writers × two reasons = 4 series; both label sets
/// are closed and compile-time constant, so cardinality cannot grow.
pub(crate) const WRITER_SS: &str = "ss";
pub(crate) const WRITER_FRAME: &str = "frame";

/// `reason` label values.
const REASON_PEER_CLOSED: &str = "peer_closed";
const REASON_ERROR: &str = "error";

/// Which select arm produced the frame. A log field only — never a metric
/// label, so it costs no cardinality.
pub(crate) const KIND_DATA: &str = "data";
pub(crate) const KIND_CTRL: &str = "ctrl";
pub(crate) const KIND_COVER: &str = "cover";

/// Substrings that identify an already-closed carrier in an error whose type no
/// longer carries that information — most importantly the H3 bridge, which maps
/// every sockudo-ws error into `WsError::Io(io::Error::other(text))`, so a
/// perfectly normal `Error::ConnectionClosed` reaches us as the opaque string
/// `IO error: Connection closed`. Matched against a lowercased haystack.
///
/// Deliberately narrow: a stream reset, a protocol violation, or a TLS fault is
/// a genuine failure and must keep its `warn!`.
const EXPECTED_WS_CLOSE_STRINGS: &[&str] = &[
    // sockudo-ws `ConnectionClosed` / `Closed(_)`, tungstenite `ConnectionClosed`.
    "connection closed",
    // tungstenite `AlreadyClosed`.
    "trying to work with closed connection",
    // tungstenite `ProtocolError::SendAfterClosing`.
    "sending after closing is not allowed",
    "broken pipe",
    // Tokio / std EOF wording for a peer that hung up mid-write.
    "early eof",
    "unexpected end of file",
];

/// How a failed WS write is reported: the routine end of a carrier is `debug`
/// plus a counter, a genuine fault keeps `warn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriterStop {
    /// The carrier was already closed — nothing went wrong on our side.
    PeerClosed,
    /// The write itself failed. Stays visible at `warn!`.
    Failed,
}

impl WriterStop {
    /// `reason` label for `outline_ws_carrier_writer_terminations_total`.
    fn reason(self) -> &'static str {
        match self {
            Self::PeerClosed => REASON_PEER_CLOSED,
            Self::Failed => REASON_ERROR,
        }
    }
}

/// Decide how to report a failed WS write. Pure, so the split between "noise"
/// and "real failure" is unit-testable without a subscriber.
pub(crate) fn classify_send_failure(error: &WsError) -> WriterStop {
    if is_expected_ws_close(error) {
        WriterStop::PeerClosed
    } else {
        WriterStop::Failed
    }
}

/// `true` when a failed WS write means "the connection was already finished"
/// rather than "the write itself went wrong".
fn is_expected_ws_close(error: &WsError) -> bool {
    match error {
        // Both are closes by definition: the first is the normal end of the
        // WebSocket close handshake, the second is a write racing it.
        WsError::ConnectionClosed | WsError::AlreadyClosed => true,
        WsError::Protocol(ProtocolError::SendAfterClosing) => true,
        WsError::Io(e) => is_expected_io_close(e),
        other => contains_any(&other.to_string().to_ascii_lowercase(), EXPECTED_WS_CLOSE_STRINGS),
    }
}

fn is_expected_io_close(error: &io::Error) -> bool {
    // A reset (`ConnectionReset` / `ConnectionAborted`) is intentionally *not*
    // here: an abruptly killed carrier is a real signal and stays at `warn!`.
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected | io::ErrorKind::UnexpectedEof
    ) || contains_any(&error.to_string().to_ascii_lowercase(), EXPECTED_WS_CLOSE_STRINGS)
}

/// Report a WS writer task shutting down because a sink write failed.
///
/// `writer` is [`WRITER_SS`] or [`WRITER_FRAME`]; `kind` is which arm of the
/// writer's select produced the frame (`"data"`, `"ctrl"`, `"cover"`). Every
/// termination is counted either way, so demoting the routine ones to `debug`
/// costs no observability — the rate stays on
/// `outline_ws_carrier_writer_terminations_total`.
pub(crate) fn report_send_failure(writer: &'static str, kind: &'static str, error: &WsError) {
    let stop = classify_send_failure(error);
    outline_metrics::record_carrier_writer_termination(writer, stop.reason());
    match stop {
        WriterStop::PeerClosed => {
            debug!(%error, writer, kind, "ws writer stopping: carrier already closed")
        },
        WriterStop::Failed => {
            warn!(%error, writer, kind, "ws writer send failed, terminating writer task")
        },
    }
}

/// Convenience wrapper for the `send`-then-report pattern both writer tasks
/// use. Returns `false` when the write failed and the caller must terminate.
pub(crate) async fn send_or_report<S>(
    sink: &mut S,
    message: Message,
    writer: &'static str,
    kind: &'static str,
) -> bool
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    use futures_util::SinkExt;
    match sink.send(message).await {
        Ok(()) => true,
        Err(error) => {
            report_send_failure(writer, kind, &error);
            false
        },
    }
}

#[cfg(test)]
#[path = "tests/ws_writer_diag.rs"]
mod tests;
