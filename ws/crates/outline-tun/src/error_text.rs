use std::io::{self, ErrorKind};

use anyhow::Error;

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

const WEBSOCKET_CLOSES: &[&str] = &[
    "websocket closed",
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];

fn lower(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

pub(crate) fn is_websocket_closed(error: &Error) -> bool {
    let l = lower(error);
    WEBSOCKET_CLOSES.iter().any(|s| l.contains(s))
        || is_transport_level_disconnect(error)
}

pub(crate) fn classify_tun_udp_forward_error(error: &Error) -> &'static str {
    let lower = lower(error);
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
