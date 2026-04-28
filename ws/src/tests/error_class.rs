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
