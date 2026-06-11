use std::io::{self, ErrorKind};

use anyhow::Error;

const TRANSPORT_DISCONNECT_STRINGS: &[&str] = &[
    "connection reset by peer",
    "broken pipe",
    // Tokio's UnexpectedEof message when the remote side closes before the
    // full buffer is filled.
    "early eof",
];

pub fn find_io_error_kind(error: &Error) -> Option<ErrorKind> {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>())
        .map(|e| e.kind())
}

pub fn is_transport_level_disconnect(error: &Error) -> bool {
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

pub fn lower_error(error: &Error) -> String {
    format!("{error:#}").to_ascii_lowercase()
}

pub fn contains_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| text.contains(pattern))
}
