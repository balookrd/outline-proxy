use anyhow::Error;
use outline_transport::{
    TransportOperation, WsClosed, contains_any, find_typed, is_transport_level_disconnect,
    lower_error,
};

use crate::udp::AllUdpUplinksFailed;

const EXTERNAL_WS_CLOSE_STRINGS: &[&str] = &[
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];

pub(crate) fn is_ws_closed(error: &Error) -> bool {
    find_typed::<WsClosed>(error).is_some()
        || is_transport_level_disconnect(error)
        || contains_any(&lower_error(error), EXTERNAL_WS_CLOSE_STRINGS)
}

pub(crate) fn classify_tun_udp_forward_error(error: &Error) -> &'static str {
    if find_typed::<AllUdpUplinksFailed>(error).is_some() {
        return "all_uplinks_failed";
    }
    // Transport errors: WsClosed or typed transport disconnect.
    if find_typed::<WsClosed>(error).is_some() || is_transport_level_disconnect(error) {
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
