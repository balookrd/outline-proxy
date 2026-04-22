use anyhow::Error;
use socks5_proto::Socks5Error;

use crate::client_io::ClientIo;
use outline_transport::{WsClosed, contains_any, find_typed, is_transport_level_disconnect, lower_error};

/// Return true if the error originated from a client-side read operation.
///
/// Covers:
/// - `ClientIo::ReadFailed` attached by `proxy/tcp/connect.rs` during the
///   active TCP data loop.
/// - `Socks5Error::Io` produced by `socks5_proto::negotiate` or
///   `read_udp_tcp_packet` — all IO operations in those functions are reads
///   from the client socket (write contexts start with "writing").
fn is_client_read_failure(error: &Error) -> bool {
    if find_typed::<ClientIo>(error).is_some_and(|c| c.is_read()) {
        return true;
    }
    // Socks5Error::Io context strings for reads all start with "reading".
    matches!(
        find_typed::<Socks5Error>(error),
        Some(Socks5Error::Io { context, .. }) if context.starts_with("reading")
            || context.starts_with("reading UDP-in-TCP")
    )
}

fn is_client_write_failure(error: &Error) -> bool {
    find_typed::<ClientIo>(error).is_some_and(|c| c.is_write())
}

/// External-library WebSocket close strings that cannot be replaced with a
/// typed marker (they originate from tungstenite / rustls).
const EXTERNAL_WS_CLOSE_STRINGS: &[&str] = &[
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];

pub(crate) fn is_expected_client_disconnect(error: &Error) -> bool {
    is_client_read_failure(error) && is_transport_level_disconnect(error)
}

pub(crate) fn is_client_write_disconnect(error: &Error) -> bool {
    is_client_write_failure(error) && is_transport_level_disconnect(error)
}

pub(crate) fn is_ws_closed(error: &Error) -> bool {
    // Prefer typed downcast; fall back to external-library strings.
    find_typed::<WsClosed>(error).is_some()
        || contains_any(&lower_error(error), EXTERNAL_WS_CLOSE_STRINGS)
}

pub(crate) fn is_upstream_runtime_failure(error: &Error) -> bool {
    !is_client_read_failure(error)
        && !is_client_write_failure(error)
        && !is_ws_closed(error)
}


#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::{
        is_client_write_disconnect, is_expected_client_disconnect, is_upstream_runtime_failure,
        is_ws_closed,
    };

    #[test]
    fn abrupt_websocket_reset_is_treated_as_closed() {
        let error = anyhow!(
            "websocket read failed: WebSocket protocol error: Connection reset without closing handshake"
        );
        assert!(is_ws_closed(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn tls_close_notify_missing_is_treated_as_closed() {
        let error = anyhow!(
            "websocket read failed: IO error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
        );
        assert!(is_ws_closed(&error));
        assert!(!is_upstream_runtime_failure(&error));
    }

    #[test]
    fn typed_websocket_closed_is_detected() {
        use outline_transport::WsClosed;
        let error = anyhow::Error::from(WsClosed).context("websocket read failed");
        assert!(is_ws_closed(&error));
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
    fn udp_relay_recv_reset_is_expected_client_disconnect() {
        // Regression: previously the UDP relay recv_from was wrapped with
        // `.context("UDP relay receive failed")`, producing a typed-less error
        // that `is_client_read_failure` could not detect — so a legitimate
        // client-closed-socket event was misclassified as an upstream runtime
        // failure. Now wrapped as `ClientIo::ReadFailed`.
        use std::io;
        use crate::client_io::ClientIo;
        let io_err = io::Error::from(io::ErrorKind::ConnectionReset);
        let error = anyhow::Error::from(ClientIo::ReadFailed(io_err));
        assert!(is_expected_client_disconnect(&error));
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
        // No ClientIo/WsClosed in chain, but transport disconnect string matches
        // and there's no client-read marker → not an expected client disconnect
        assert!(!is_expected_client_disconnect(&error));
        // And not a websocket close either
        assert!(!is_ws_closed(&error));
        // But IS a runtime failure (no typed markers filtering it out)
        assert!(is_upstream_runtime_failure(&error));
    }
}
