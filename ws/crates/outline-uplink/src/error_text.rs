use std::fmt;
use std::io::ErrorKind;

use anyhow::Error;
use outline_ss2022::Ss2022Error;
use outline_transport::{
    TransportOperation, WsClosed, contains_any, find_io_error_kind, find_typed,
    is_transport_level_disconnect, lower_error,
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
mod tests {
    use super::*;

    fn classify(err: Ss2022Error) -> &'static str {
        let wrapped = Error::from(err).context("ss2022 framing failed in some outer layer");
        classify_runtime_failure_signature(&wrapped)
    }

    #[test]
    fn context_on_result_preserves_typed_marker() {
        // Canonical call-site shape: `Result<_, StdError>.context(TypedMarker)`.
        // The typed marker is stored as an anyhow context layer — found via
        // `anyhow::Error::downcast_ref` (or `find_typed`), NOT via walking
        // the std `source()` chain.
        use anyhow::Context;
        let tungstenite_like: Result<(), std::io::Error> =
            Err(std::io::Error::other("tungstenite protocol error"));
        let err = tungstenite_like
            .context(TransportOperation::WebSocketRead)
            .unwrap_err();
        assert!(
            find_typed::<TransportOperation>(&err).is_some(),
            "find_typed must locate typed context marker"
        );
        assert_eq!(classify_runtime_failure_signature(&err), "ws_read_failed");
    }

    #[test]
    fn typed_transport_operation_classified_when_no_io_kind() {
        // Construct as root typed error + outer string context (matches the
        // shape produced by `.with_context(|| TransportOperation::…)` at real
        // call-sites, where the typed value becomes the error's root type and
        // the underlying library error becomes a `source()` layer).
        let err = Error::new(TransportOperation::WebSocketRead).context("outer call frame");
        assert_eq!(classify_runtime_failure_signature(&err), "ws_read_failed");

        let err = Error::new(TransportOperation::SocketShutdown).context("outer call frame");
        assert_eq!(classify_runtime_failure_signature(&err), "socket_shutdown_failed");
    }

    #[test]
    fn io_kind_wins_over_transport_operation_marker() {
        // When an io::Error with ConnectionReset is the *source* of a typed
        // TransportOperation, io::ErrorKind classification takes priority
        // over the operation marker (preserves the existing fallback
        // ordering established before the typed marker was added).
        let io_err = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let err: Error = anyhow::Error::from(io_err).context(TransportOperation::WebSocketRead);
        assert_eq!(classify_runtime_failure_signature(&err), "connection_reset");
    }

    #[test]
    fn typed_crypto_errors_are_classified() {
        use shadowsocks_crypto::CryptoError;

        let err = Error::new(CryptoError::DecryptFailed { cipher: "aes-256-gcm" });
        assert_eq!(classify_runtime_failure_signature(&err), "decrypt_failed");
        assert_eq!(classify_runtime_failure_cause(&err), "crypto");

        let err = Error::new(CryptoError::EncryptFailed { cipher: "chacha20-poly1305" });
        assert_eq!(classify_runtime_failure_signature(&err), "encrypt_failed");
        assert_eq!(classify_runtime_failure_cause(&err), "crypto");

        let err = Error::new(CryptoError::NonceOverflow);
        assert_eq!(classify_runtime_failure_signature(&err), "encrypt_failed");
        assert_eq!(classify_runtime_failure_cause(&err), "crypto");

        // Protocol variant falls through to string fallback (catch-all design).
        let err = Error::new(CryptoError::Protocol("invalid ss2022 UDP server packet type"));
        assert_eq!(classify_runtime_failure_signature(&err), "invalid_ss2022");
        assert_eq!(classify_runtime_failure_cause(&err), "crypto");
    }

    #[test]
    fn typed_marker_survives_nested_context_wrapping() {
        // If a call-site's .with_context(|| Typed) is later wrapped with an
        // additional .context("outer label") by a caller, the typed marker
        // must still be findable.
        use anyhow::Context;
        let io_err: std::io::Result<()> = Err(std::io::Error::other("x"));
        let err = io_err
            .with_context(|| TransportOperation::Connect { target: "to X".into() })
            .context("outer caller frame")
            .unwrap_err();
        assert!(
            err.downcast_ref::<TransportOperation>().is_some(),
            "typed marker must survive outer .context() wrapping"
        );
    }

    #[test]
    fn connect_with_context_at_call_site_is_classified() {
        use anyhow::Context;
        let io_err: std::io::Result<()> = Err(std::io::Error::other("network unreachable"));
        let err = io_err
            .with_context(|| TransportOperation::Connect {
                target: "TCP socket to 1.2.3.4:443".into(),
            })
            .unwrap_err();
        // anyhow::Error has a direct .downcast_ref() that inspects the context
        // layer (distinct from chain() walking via source()).
        assert!(
            err.downcast_ref::<TransportOperation>().is_some(),
            "anyhow::Error::downcast_ref() must find typed context marker"
        );
        assert_eq!(classify_runtime_failure_signature(&err), "connect_failed");
    }

    #[test]
    fn typed_connect_and_dns_failures_are_classified() {
        let err = Error::new(TransportOperation::Connect { target: "TCP socket to 1.2.3.4:443".into() });
        assert_eq!(classify_runtime_failure_signature(&err), "connect_failed");
        assert_eq!(classify_runtime_failure_cause(&err), "connect");

        let err = Error::new(TransportOperation::DnsResolveNoAddresses { host: "example.com:443".into() });
        assert_eq!(classify_runtime_failure_signature(&err), "dns_no_addresses");
        assert_eq!(classify_runtime_failure_cause(&err), "connect");
    }

    #[test]
    fn typed_connect_survives_outer_context_wrapping() {
        let inner = Error::new(TransportOperation::Connect { target: "to wss://host".into() });
        let wrapped = inner.context("probe_http");
        assert_eq!(classify_runtime_failure_signature(&wrapped), "connect_failed");
    }

    #[test]
    fn typed_ss2022_errors_are_classified_by_variant() {
        assert_eq!(classify(Ss2022Error::InvalidResponseHeaderLength(42)), "invalid_ss2022");
        assert_eq!(classify(Ss2022Error::InvalidResponseHeaderType(9)), "invalid_ss2022");
        assert_eq!(classify(Ss2022Error::InvalidInitialTargetHeader), "invalid_ss2022");
        assert_eq!(classify(Ss2022Error::RequestSaltMismatch), "request_salt_mismatch");
        assert_eq!(classify(Ss2022Error::DuplicateOrOutOfOrderUdpPacket), "udp_out_of_order");
        assert_eq!(classify(Ss2022Error::OversizedUdpUplink), "oversized_udp");
    }
}
