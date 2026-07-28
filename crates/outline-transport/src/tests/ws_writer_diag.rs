use std::io;

use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::{CapacityError, ProtocolError};

use super::{WriterStop, classify_send_failure};

/// `PeerClosed` is the debug-and-count branch, `Failed` the `warn!` one — see
/// `report_send_failure`.
#[track_caller]
fn assert_quiet(error: WsError) {
    assert_eq!(
        classify_send_failure(&error),
        WriterStop::PeerClosed,
        "`{error}` is an ordinary carrier close and must not warn"
    );
}

#[track_caller]
fn assert_warns(error: WsError) {
    assert_eq!(
        classify_send_failure(&error),
        WriterStop::Failed,
        "`{error}` is a genuine write failure and must stay visible"
    );
}

/// The line that made up 92 % of all client warnings: the H3 bridge maps every
/// sockudo-ws error into `WsError::Io(io::Error::other(text))`, so a perfectly
/// normal `ConnectionClosed` arrives as the opaque string `IO error: Connection
/// closed`. It must classify as an ordinary close, not as a write failure.
#[test]
fn h3_bridged_connection_closed_does_not_warn() {
    assert_quiet(WsError::Io(io::Error::other("Connection closed")));
    // sockudo-ws also renders a close frame with its code and reason.
    assert_quiet(WsError::Io(io::Error::other("Connection closed: 1000 (bye)")));
}

/// Typed tungstenite closes (the h1 / h2 carriers) need no string matching.
#[test]
fn typed_tungstenite_closes_do_not_warn() {
    assert_quiet(WsError::ConnectionClosed);
    assert_quiet(WsError::AlreadyClosed);
    assert_quiet(WsError::Protocol(ProtocolError::SendAfterClosing));
}

/// A peer that hung up mid-write surfaces as an ordinary io error; those kinds
/// are a close, not a fault.
#[test]
fn peer_hangup_io_kinds_do_not_warn() {
    for kind in
        [io::ErrorKind::BrokenPipe, io::ErrorKind::NotConnected, io::ErrorKind::UnexpectedEof]
    {
        assert_quiet(WsError::Io(io::Error::new(kind, "gone")));
    }
}

/// The whole point of the classification is that real failures keep their
/// `warn!`. A reset carrier, a protocol violation, a capacity overflow, and an
/// attack attempt are all genuine and must not be demoted.
#[test]
fn genuine_write_failures_still_warn() {
    assert_warns(WsError::Io(io::Error::new(
        io::ErrorKind::ConnectionReset,
        "connection reset by peer",
    )));
    assert_warns(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake));
    assert_warns(WsError::Protocol(ProtocolError::InvalidOpcode(9)));
    assert_warns(WsError::Capacity(CapacityError::MessageTooLong { size: 2, max_size: 1 }));
    assert_warns(WsError::AttackAttempt);
    // A QUIC-level stream reset bridged through the H3 adapter is a carrier
    // fault, not an orderly close.
    assert_warns(WsError::Io(io::Error::other("Stream was reset by peer")));
}
