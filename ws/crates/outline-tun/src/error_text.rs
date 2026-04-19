use std::io::{self, ErrorKind};

use anyhow::Error;
use outline_transport::WebSocketClosed;

use crate::udp::AllUdpUplinksFailed;

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
    let lower = format!("{error:#}").to_ascii_lowercase();
    ["connection reset by peer", "broken pipe", "early eof"]
        .iter()
        .any(|s| lower.contains(s))
}

/// External-library WebSocket close strings that cannot be replaced with a
/// typed marker (they originate from tungstenite / rustls).
const EXTERNAL_WEBSOCKET_CLOSE_STRINGS: &[&str] = &[
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];

pub(crate) fn is_websocket_closed(error: &Error) -> bool {
    error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some())
        || is_transport_level_disconnect(error)
        || {
            let lower = format!("{error:#}").to_ascii_lowercase();
            EXTERNAL_WEBSOCKET_CLOSE_STRINGS.iter().any(|s| lower.contains(s))
        }
}

pub(crate) fn classify_tun_udp_forward_error(error: &Error) -> &'static str {
    if error.chain().any(|e| e.downcast_ref::<AllUdpUplinksFailed>().is_some()) {
        return "all_uplinks_failed";
    }
    // Transport errors: WebSocketClosed or typed transport disconnect
    if error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some())
        || is_transport_level_disconnect(error)
    {
        return "transport_error";
    }
    // "websocket read failed" context string is still needed: the underlying
    // tungstenite error is preserved in the chain but has no stable typed API.
    let lower = format!("{error:#}").to_ascii_lowercase();
    if lower.contains("websocket read failed") || lower.contains("failed to send udp websocket frame") {
        return "transport_error";
    }
    if lower.contains("failed to connect to") {
        return "connect_failed";
    }
    "other"
}
