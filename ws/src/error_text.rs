use std::io::{self, ErrorKind};

use anyhow::Error;
use socks5_proto::Socks5Error;

use crate::client_io::ClientIo;
use outline_transport::WebSocketClosed;

/// Walk the anyhow error chain looking for a `std::io::Error`.
/// Returns the `ErrorKind` of the first one found, if any.
fn find_io_error_kind(error: &Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>())
        .map(|e| e.kind())
}

/// Return true if any `std::io::Error` in the chain indicates a TCP-level
/// disconnect: connection reset, broken pipe, unexpected EOF, or connection
/// aborted.
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
    // Fallback for errors whose io::Error was formatted into the message
    // string (e.g. via `anyhow!("...: {e}")`).
    contains_any(&lower_error(error), TRANSPORT_DISCONNECT_STRINGS)
}

/// Return true if the error originated from a client-side read operation.
///
/// Covers:
/// - `ClientIo::ReadFailed` attached by `proxy/tcp/connect.rs` during the
///   active TCP data loop.
/// - `Socks5Error::Io` produced by `socks5_proto::negotiate` or
///   `read_udp_tcp_packet` — all IO operations in those functions are reads
///   from the client socket (write contexts start with "writing").
fn is_client_read_failure(error: &Error) -> bool {
    error.chain().any(|e| {
        if e.downcast_ref::<ClientIo>().is_some_and(|c| c.is_read()) {
            return true;
        }
        // Socks5Error::Io context strings for reads all start with "reading".
        matches!(
            e.downcast_ref::<Socks5Error>(),
            Some(Socks5Error::Io { context, .. }) if context.starts_with("reading")
                || context.starts_with("reading UDP-in-TCP")
        )
    })
}

fn is_client_write_failure(error: &Error) -> bool {
    error.chain().any(|e| e.downcast_ref::<ClientIo>().is_some_and(|c| c.is_write()))
}

/// String-match fallback for transport disconnects.
///
/// Used only when the `io::Error` was formatted into the message string
/// rather than preserved as a chain source.  The OS error code variants
/// ("os error 104", "os error 54", "os error 32") are intentionally omitted
/// here: they are handled type-safely by `is_transport_level_disconnect` via
/// `io::ErrorKind`.
const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    // Tokio's UnexpectedEof message produced by read_exact when the remote
    // side closes the connection before the full buffer is filled.
    "early eof",
];

/// External-library WebSocket close strings that cannot be replaced with a
/// typed marker (they originate from tungstenite / rustls).
const EXTERNAL_WEBSOCKET_CLOSE_STRINGS: &[&str] = &[
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];

fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

pub(crate) fn is_expected_client_disconnect(error: &Error) -> bool {
    is_client_read_failure(error) && is_transport_level_disconnect(error)
}

pub(crate) fn is_client_write_disconnect(error: &Error) -> bool {
    is_client_write_failure(error) && is_transport_level_disconnect(error)
}

pub(crate) fn is_websocket_closed(error: &Error) -> bool {
    // Prefer typed downcast; fall back to external-library strings.
    error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some())
        || contains_any(&lower_error(error), EXTERNAL_WEBSOCKET_CLOSE_STRINGS)
}

pub(crate) fn is_upstream_runtime_failure(error: &Error) -> bool {
    !is_client_read_failure(error)
        && !is_client_write_failure(error)
        && !is_websocket_closed(error)
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
    fn typed_websocket_closed_is_detected() {
        use outline_transport::WebSocketClosed;
        let error = anyhow::Error::from(WebSocketClosed).context("websocket read failed");
        assert!(is_websocket_closed(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn typed_io_error_connection_reset_detected_regardless_of_os_code() {
        use std::io;
        use crate::client_io::ClientIo;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(ClientIo::ReadFailed(io_err));
        assert!(is_expected_client_disconnect(&error));
    }

    #[test]
    fn typed_io_error_broken_pipe_detected() {
        use std::io;
        use crate::client_io::ClientIo;
        let io_err = io::Error::from(io::ErrorKind::BrokenPipe);
        let error = anyhow::Error::from(ClientIo::WriteFailed(io_err));
        assert!(is_client_write_disconnect(&error));
    }

    #[test]
    fn client_write_reset_is_not_hidden_as_expected_disconnect() {
        use std::io;
        use crate::client_io::ClientIo;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(ClientIo::WriteFailed(io_err));
        assert!(!is_expected_client_disconnect(&error));
        assert!(is_client_write_disconnect(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn socks5_negotiation_reset_is_expected_client_disconnect() {
        use std::io;
        use socks5_proto::Socks5Error;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(Socks5Error::Io {
            context: "reading method negotiation header",
            source: io_err,
        });
        assert!(is_expected_client_disconnect(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn socks5_write_failure_is_not_expected_client_disconnect() {
        use std::io;
        use socks5_proto::Socks5Error;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(Socks5Error::Io {
            context: "writing method selection",
            source: io_err,
        });
        assert!(!is_expected_client_disconnect(&error));
    }

    #[test]
    fn string_fallback_still_works_for_external_websocket_strings() {
        let error = anyhow!("websocket read failed: early eof");
        // No ClientIo/WebSocketClosed in chain, but transport disconnect string matches
        // and there's no client-read marker → not an expected client disconnect
        assert!(!is_expected_client_disconnect(&error));
        // And not a websocket close either
        assert!(!is_websocket_closed(&error));
        // But IS a runtime failure (no typed markers filtering it out)
        assert!(is_upstream_runtime_failure(&error));
    }
}
