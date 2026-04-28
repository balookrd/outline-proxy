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
#[path = "tests/error_class.rs"]
mod tests;
