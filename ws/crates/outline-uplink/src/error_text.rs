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
    contains_any(&lower_error(error), TRANSPORT_DISCONNECT_STRINGS)
}

const STANDBY_PROBE_FAILURE_STRINGS: &[&str] = &[
    "websocket probe received close frame",
    "websocket probe stream closed before pong",
    "connection reset by peer",
    "broken pipe",
    "websocket ping/pong timed out",
    "timed out",
    "timeout",
    "application closed",
    "connection lost",
    "stream reset",
    "transport error",
    "applicationclose",
];

const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    "early eof",
];

fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}

pub(crate) fn is_expected_standby_probe_failure(error: &Error) -> bool {
    is_transport_level_disconnect(error)
        || contains_any(&lower_error(error), STANDBY_PROBE_FAILURE_STRINGS)
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
