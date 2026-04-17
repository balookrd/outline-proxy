use std::io::{self, ErrorKind};

use anyhow::Error;

/// Walk the anyhow error chain looking for a `std::io::Error`.
/// Returns the `ErrorKind` of the first one found, if any.
///
/// This is the type-safe companion to string-based "os error N" matching.
/// It works when errors are chained with `.context(...)` (which preserves
/// the original error as a `source()`), but not when they are formatted
/// into the message with `bail!("...: {e}")` or `format!`.
fn find_io_error_kind(error: &Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>())
        .map(|e| e.kind())
}

/// Return true if any `std::io::Error` in the chain indicates a TCP-level
/// disconnect: connection reset, broken pipe, unexpected EOF, or connection
/// aborted.
///
/// Prefers `io::ErrorKind` over string matching because it is platform-
/// independent (no "os error 104" vs "os error 54" across Linux/macOS) and
/// resilient to error-message wording changes in OS libc or Tokio.
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
    // Fallback for errors formatted into the message string rather than
    // preserved as a chain source (e.g. bail!("...: {e}")).
    contains_any(&lower_error(error), TRANSPORT_DISCONNECT_STRINGS)
}

const CLIENT_READ_FAILURES: &[&str] = &[
    "client read failed",
    "failed to read udp-in-tcp data length",
    "failed to read udp-in-tcp data length tail",
    "failed to read udp-in-tcp header length",
    "failed to read udp-in-tcp target address",
    "failed to read udp-in-tcp payload",
    // SOCKS5 negotiation aborts: client closed the TCP connection before
    // completing the handshake.  Common during reconnect storms when a TUN
    // interceptor (Sing-box, Clash, etc.) flushes its connection pool.
    "failed to read method negotiation header",
    "failed to read authentication methods",
    "failed to read request header",
];
const CLIENT_WRITE_FAILURES: &[&str] = &["client write failed"];
const CLIENT_IO_FAILURES: &[&str] = &[
    "client read failed",
    "client write failed",
    "failed to read udp-in-tcp data length",
    "failed to read udp-in-tcp data length tail",
    "failed to read udp-in-tcp header length",
    "failed to read udp-in-tcp target address",
    "failed to read udp-in-tcp payload",
    "failed to read method negotiation header",
    "failed to read authentication methods",
    "failed to read request header",
];
const WEBSOCKET_CLOSES: &[&str] = &[
    "websocket closed",
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];
/// String-match fallback for transport disconnects.
///
/// Used only when the `io::Error` was formatted into the message string
/// rather than preserved as a chain source.  The OS error code variants
/// ("os error 104", "os error 54", "os error 32") are intentionally omitted
/// here: they are handled type-safely by `is_transport_level_disconnect` via
/// `io::ErrorKind`.  Keeping them would be harmless but is unnecessary.
const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    // Tokio's UnexpectedEof message produced by read_exact when the remote side
    // closes the connection before the full buffer is filled.
    "early eof",
];
/// String patterns that indicate an expected standby-probe failure.
///
/// OS-error-code strings ("os error 104/54/32") are deliberately absent:
/// the `is_expected_standby_probe_failure` function handles those through
/// `is_transport_level_disconnect` → `io::ErrorKind` instead.
const STANDBY_PROBE_FAILURE_STRINGS: &[&str] = &[
    "websocket probe received close frame",
    "websocket probe stream closed before pong",
    "connection reset by peer",
    "broken pipe",
    "websocket ping/pong timed out",
    "timed out",
    // Quinn surfaces QUIC idle timeout as the bare word "Timeout" (not "timed out").
    "timeout",
    "application closed",
    "connection lost",
    "stream reset",
    "transport error",
    // QUIC APPLICATION_CLOSE codes from the server (H3_NO_ERROR, H3_INTERNAL_ERROR,
    // H3_REQUEST_REJECTED, etc.).  These surface as "applicationclose" in the lowered
    // error chain.  The standby slot is simply discarded (same as any other drop), and
    // the runtime failure path on the session side already records the event and
    // triggers the H3→H2 downgrade — a duplicate WARN from standby adds no signal.
    "applicationclose",
];

fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

pub(crate) fn is_expected_client_disconnect(error: &Error) -> bool {
    contains_any(&lower_error(error), CLIENT_READ_FAILURES) && is_transport_level_disconnect(error)
}

pub(crate) fn is_client_write_disconnect(error: &Error) -> bool {
    contains_any(&lower_error(error), CLIENT_WRITE_FAILURES) && is_transport_level_disconnect(error)
}

pub(crate) fn is_websocket_closed(error: &Error) -> bool {
    contains_any(&lower_error(error), WEBSOCKET_CLOSES)
}

pub(crate) fn is_upstream_runtime_failure(error: &Error) -> bool {
    let lower = lower_error(error);
    !contains_any(&lower, CLIENT_IO_FAILURES)
        && !lower.contains("active uplink switched")
        && !contains_any(&lower, WEBSOCKET_CLOSES)
}

pub(crate) fn is_expected_standby_probe_failure(error: &Error) -> bool {
    is_transport_level_disconnect(error)
        || contains_any(&lower_error(error), STANDBY_PROBE_FAILURE_STRINGS)
}

#[cfg(feature = "tun")]
pub(crate) fn classify_tun_udp_forward_error(error: &Error) -> &'static str {
    let lower = lower_error(error);
    if lower.contains("all udp uplinks failed") {
        "all_uplinks_failed"
    } else if lower.contains("failed to send udp websocket frame")
        || lower.contains("websocket read failed")
    {
        "transport_error"
    } else if lower.contains("failed to connect to") {
        "connect_failed"
    } else {
        "other"
    }
}

pub(crate) fn classify_runtime_failure_cause(error_text: &str) -> &'static str {
    let lower = error_text.to_ascii_lowercase();
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

pub(crate) fn classify_runtime_failure_signature(error_text: &str) -> &'static str {
    let lower = error_text.to_ascii_lowercase();
    if lower.contains("failed to read") {
        "read_failed"
    } else if lower.contains("failed to send") || lower.contains("failed to write") {
        "write_failed"
    } else if lower.contains("websocket read failed") {
        "ws_read_failed"
    } else if lower.contains("websocket closed") {
        "ws_closed"
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

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::{
        is_client_write_disconnect, is_expected_client_disconnect, is_upstream_runtime_failure,
        is_websocket_closed,
    };

    #[test]
    fn abrupt_websocket_reset_is_treated_as_closed() {
        let error = anyhow!(
            "websocket read failed: WebSocket protocol error: Connection reset without closing handshake"
        );
        assert!(is_websocket_closed(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn tls_close_notify_missing_is_treated_as_closed() {
        let error = anyhow!(
            "websocket read failed: IO error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
        );
        assert!(is_websocket_closed(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn udp_in_tcp_client_reset_is_treated_as_expected_disconnect() {
        let error = anyhow!(
            "failed to read UDP-in-TCP data length: Connection reset by peer (os error 104)"
        );
        assert!(is_expected_client_disconnect(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn client_write_reset_is_not_hidden_as_expected_disconnect() {
        let error = anyhow!("client write failed: Connection reset by peer (os error 54)");
        assert!(!is_expected_client_disconnect(&error));
        assert!(is_client_write_disconnect(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    /// io::ErrorKind::ConnectionReset is detected even when the OS code is
    /// platform-specific (104 on Linux, 54 on macOS).  The typed path must
    /// fire regardless of which numeric code the kernel used.
    #[test]
    fn typed_io_error_connection_reset_detected_regardless_of_os_code() {
        use std::io;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(io_err).context("client read failed");
        assert!(is_expected_client_disconnect(&error));
    }

    /// io::ErrorKind::BrokenPipe is detected via the typed path.
    #[test]
    fn typed_io_error_broken_pipe_detected() {
        use std::io;
        let io_err = io::Error::from(io::ErrorKind::BrokenPipe);
        let error = anyhow::Error::from(io_err).context("client write failed");
        assert!(is_client_write_disconnect(&error));
    }

    /// An error that carries no io::Error in its chain but whose formatted
    /// message contains the expected strings still passes string-fallback.
    #[test]
    fn string_fallback_still_works_for_formatted_messages() {
        let error = anyhow!("client read failed: early eof");
        assert!(is_expected_client_disconnect(&error));
    }
}
