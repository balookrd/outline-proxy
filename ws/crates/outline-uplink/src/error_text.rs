use std::fmt;
use std::io::{self, ErrorKind};

use anyhow::Error;
use outline_transport::WebSocketClosed;

/// Typed marker placed in the error chain by the warm-standby maintenance
/// code for errors that are routine (connection went stale, server closed
/// the WebSocket, underlying shared connection was recycled).  Classifiers
/// match this via downcast instead of pattern-matching formatted strings.
#[derive(Debug)]
pub(crate) struct StandbyProbeExpected;

impl fmt::Display for StandbyProbeExpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected standby probe failure")
    }
}

impl std::error::Error for StandbyProbeExpected {}

fn find_io_error_kind(error: &Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>())
        .map(|e| e.kind())
}

fn is_transport_level_disconnect(error: &Error) -> bool {
    if let Some(kind) = find_io_error_kind(error) {
        return matches!(
            kind,
            ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
                | ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionAborted
        );
    }
    contains_any(&lower_error(error), TRANSPORT_DISCONNECT_STRINGS)
}

const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    "early eof",
];

fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

/// Return true if a warm-standby probe failure is expected (the connection
/// was stale or the server closed it).  Expected failures are logged at
/// DEBUG instead of WARN.
pub(crate) fn is_expected_standby_probe_failure(error: &Error) -> bool {
    // Typed marker: our own code tagged this as expected.
    if error.chain().any(|e| e.downcast_ref::<StandbyProbeExpected>().is_some()) {
        return true;
    }
    // Typed WebSocket close from outline-transport.
    if error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some()) {
        return true;
    }
    // Transport-level disconnect via io::ErrorKind (covers "timed out" on ping
    // send, connection reset, etc.).
    if is_transport_level_disconnect(error) {
        return true;
    }
    // Fallback for errors that bake the message into a formatted string.
    let lower = lower_error(error);
    contains_any(&lower, &["timed out", "timeout", "connection lost"])
}

/// Classify the broad failure cause for a runtime uplink failure.
/// Uses typed chain walking first; falls back to string matching for errors
/// that originate from external libraries.
pub(crate) fn classify_runtime_failure_cause(error: &Error) -> &'static str {
    // Typed: WebSocket close frame.
    if error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some()) {
        return "closed";
    }
    // Typed: transport-level disconnect via io::ErrorKind.
    if let Some(kind) = find_io_error_kind(error) {
        if matches!(kind, ErrorKind::TimedOut) {
            return "timeout";
        }
        if matches!(
            kind,
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
        ) {
            return "reset";
        }
        if matches!(kind, ErrorKind::UnexpectedEof) {
            return "closed";
        }
        if matches!(kind, ErrorKind::ConnectionRefused | ErrorKind::NotConnected) {
            return "connect";
        }
    }
    // String fallback for external-library errors.
    let lower = lower_error(error);
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connection lost")
        || lower.contains("stream reset")
    {
        "reset"
    } else if lower.contains("websocket closed")
        || lower.contains("stream ended")
        || lower.contains("eof")
        || lower.contains("closed by server")
    {
        "closed"
    } else if lower.contains("failed to connect")
        || lower.contains("connection refused")
        || lower.contains("dns resolution")
        || lower.contains("resolve")
    {
        "connect"
    } else if lower.contains("decrypt")
        || lower.contains("encrypt")
        || lower.contains("aead")
        || lower.contains("salt")
        || lower.contains("nonce")
        || lower.contains("ss2022")
    {
        "crypto"
    } else {
        "other"
    }
}

/// Classify the specific failure signature for a runtime uplink failure.
/// Uses typed chain walking first; falls back to string matching for errors
/// that originate from external libraries.
pub(crate) fn classify_runtime_failure_signature(error: &Error) -> &'static str {
    // Typed: WebSocket closed cleanly.
    if error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some()) {
        return "ws_closed";
    }
    // Typed: transport-level disconnect.
    if let Some(kind) = find_io_error_kind(error) {
        match kind {
            ErrorKind::ConnectionReset => return "connection_reset",
            ErrorKind::BrokenPipe => return "broken_pipe",
            ErrorKind::TimedOut => return "timeout",
            ErrorKind::ConnectionRefused => return "connect_failed",
            _ => {},
        }
    }
    // String fallback for everything else.
    let lower = lower_error(error);
    if lower.contains("failed to read") {
        "read_failed"
    } else if lower.contains("failed to send") || lower.contains("failed to write") {
        "write_failed"
    } else if lower.contains("websocket read failed") {
        "ws_read_failed"
    } else if lower.contains("control connection read failed") {
        "control_read_failed"
    } else if lower.contains("udp relay receive failed") {
        "udp_relay_receive_failed"
    } else if lower.contains("socket shutdown failed") {
        "socket_shutdown_failed"
    } else if lower.contains("invalid ss2022") {
        "invalid_ss2022"
    } else if lower.contains("duplicate or out-of-order") {
        "udp_out_of_order"
    } else if lower.contains("request salt mismatch") {
        "request_salt_mismatch"
    } else if lower.contains("oversized udp") {
        "oversized_udp"
    } else if lower.contains("failed to connect") {
        "connect_failed"
    } else if lower.contains("dns resolution returned no addresses") {
        "dns_no_addresses"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("connection reset") {
        "connection_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("connection lost") {
        "connection_lost"
    } else if lower.contains("stream reset") {
        "stream_reset"
    } else if lower.contains("application closed") {
        "application_closed"
    } else if lower.contains("transport error") {
        "transport_error"
    } else if lower.contains("decrypt") {
        "decrypt_failed"
    } else if lower.contains("encrypt") {
        "encrypt_failed"
    } else {
        "other"
    }
}
