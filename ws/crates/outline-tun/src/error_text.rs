use std::io::{self, ErrorKind};

use anyhow::Error;
use outline_transport::{TransportOperation, WebSocketClosed, find_typed};

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
    find_typed::<WebSocketClosed>(error).is_some()
        || is_transport_level_disconnect(error)
        || {
            let lower = format!("{error:#}").to_ascii_lowercase();
            EXTERNAL_WEBSOCKET_CLOSE_STRINGS.iter().any(|s| lower.contains(s))
        }
}

pub(crate) fn classify_tun_udp_forward_error(error: &Error) -> &'static str {
    if find_typed::<AllUdpUplinksFailed>(error).is_some() {
        return "all_uplinks_failed";
    }
    // Transport errors: WebSocketClosed or typed transport disconnect.
    if find_typed::<WebSocketClosed>(error).is_some() || is_transport_level_disconnect(error) {
        return "transport_error";
    }
    // Typed: high-level transport operation marker attached at the failure
    // site (preferred over substring matching on Display output).
    if let Some(op) = find_typed::<TransportOperation>(error) {
        return match op {
            TransportOperation::WebSocketRead
            | TransportOperation::WebSocketSend
            | TransportOperation::SocketShutdown => "transport_error",
            TransportOperation::Connect { .. } | TransportOperation::DnsResolveNoAddresses { .. } => {
                "connect_failed"
            },
        };
    }
    "other"
}
