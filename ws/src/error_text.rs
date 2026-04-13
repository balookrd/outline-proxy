use anyhow::Error;

const CLIENT_IO_FAILURES: &[&str] = &["client read failed", "client write failed"];
const WEBSOCKET_CLOSES: &[&str] = &[
    "websocket closed",
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
];
const TRANSPORT_DISCONNECTS: &[&str] =
    &["connection reset by peer", "broken pipe", "os error 104", "os error 54", "os error 32"];
const STANDBY_PROBE_FAILURES: &[&str] = &[
    "websocket probe received close frame",
    "websocket probe stream closed before pong",
    "connection reset by peer",
    "broken pipe",
    "os error 104",
    "os error 54",
    "os error 32",
    "websocket ping/pong timed out",
    "timed out",
    "application closed",
    "connection lost",
    "stream reset",
    "transport error",
];

fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

pub(crate) fn is_expected_client_disconnect(error: &Error) -> bool {
    let lower = lower_error(error);
    contains_any(&lower, CLIENT_IO_FAILURES) && contains_any(&lower, TRANSPORT_DISCONNECTS)
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
    contains_any(&lower_error(error), STANDBY_PROBE_FAILURES)
}

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

    use super::{is_upstream_runtime_failure, is_websocket_closed};

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
}
