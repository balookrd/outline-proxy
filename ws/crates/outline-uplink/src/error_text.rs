use std::fmt;
use std::io::ErrorKind;

use anyhow::Error;
use outline_ss2022::Ss2022Error;
use outline_transport::{
    OversizedUdpDatagram, TransportOperation, WsClosed, contains_any, find_io_error_kind,
    find_typed, is_transport_level_disconnect, lower_error,
};
use shadowsocks_crypto::CryptoError;

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

/// Return true if a warm-standby probe failure is expected (the connection
/// was stale or the server closed it).  Expected failures are logged at
/// DEBUG instead of WARN.
pub(crate) fn is_expected_standby_probe_failure(error: &Error) -> bool {
    // Typed marker: our own code tagged this as expected.
    if find_typed::<StandbyProbeExpected>(error).is_some() {
        return true;
    }
    // Typed WebSocket close from outline-transport.
    if find_typed::<WsClosed>(error).is_some() {
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
    if find_typed::<WsClosed>(error).is_some() {
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
    // Typed: explicit connect / DNS failure marker.
    if matches!(
        find_typed::<TransportOperation>(error),
        Some(TransportOperation::Connect { .. } | TransportOperation::DnsResolveNoAddresses { .. })
    ) {
        return "connect";
    }
    // Typed: any ss2022/crypto error → crypto cause.
    if find_typed::<CryptoError>(error).is_some() || find_typed::<Ss2022Error>(error).is_some() {
        return "crypto";
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
    if find_typed::<WsClosed>(error).is_some() {
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
    // Typed: high-level transport operation context.
    if let Some(op) = find_typed::<TransportOperation>(error) {
        return match op {
            TransportOperation::WebSocketRead => "ws_read_failed",
            TransportOperation::WebSocketSend => "ws_send_failed",
            TransportOperation::SocketShutdown => "socket_shutdown_failed",
            TransportOperation::Connect { .. } => "connect_failed",
            TransportOperation::DnsResolveNoAddresses { .. } => "dns_no_addresses",
        };
    }
    if find_typed::<OversizedUdpDatagram>(error).is_some() {
        return "oversized_udp";
    }
    // Typed: ss2022 framing/replay errors.
    if let Some(ss) = find_typed::<Ss2022Error>(error) {
        return match ss {
            Ss2022Error::InvalidResponseHeaderLength(_)
            | Ss2022Error::InvalidResponseHeaderType(_)
            | Ss2022Error::InvalidInitialTargetHeader => "invalid_ss2022",
            Ss2022Error::RequestSaltMismatch => "request_salt_mismatch",
            Ss2022Error::DuplicateOrOutOfOrderUdpPacket => "udp_out_of_order",
            Ss2022Error::OversizedUdpUplink => "oversized_udp",
        };
    }
    // Typed: crypto primitive failures (decrypt/encrypt/nonce).
    //
    // `Protocol(&'static str)` deliberately falls through to the string
    // fallback below: it's a catch-all for ss2022 framing messages
    // (see shadowsocks_crypto::CryptoError docs), and the string branch
    // already distinguishes them via the stable internal constants.
    if let Some(crypto) = find_typed::<CryptoError>(error) {
        match crypto {
            CryptoError::DecryptFailed { .. } => return "decrypt_failed",
            CryptoError::EncryptFailed { .. } | CryptoError::NonceOverflow => {
                return "encrypt_failed";
            },
            _ => {}, // fall through
        }
    }
    // String fallback for everything else.
    let lower = lower_error(error);
    if lower.contains("failed to read") {
        "read_failed"
    } else if lower.contains("failed to send") || lower.contains("failed to write") {
        "write_failed"
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

#[cfg(test)]
#[path = "tests/error_text.rs"]
mod tests;
