use std::fmt;
use std::io;

/// Typed error wrapping `io::Error` from client-side read/write operations.
/// Used as the **root** error (via `map_err`) rather than as an anyhow context
/// (via `.context()`), so that classifiers can find it with `downcast_ref`
/// while `find_io_error_kind` still reaches the inner `io::Error` via `source()`.
#[derive(Debug)]
pub(crate) enum ClientIo {
    ReadFailed(io::Error),
    WriteFailed(io::Error),
}

impl ClientIo {
    pub(crate) fn is_read(&self) -> bool {
        matches!(self, Self::ReadFailed(_))
    }

    pub(crate) fn is_write(&self) -> bool {
        matches!(self, Self::WriteFailed(_))
    }
}

impl fmt::Display for ClientIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFailed(_) => write!(f, "client read failed"),
            Self::WriteFailed(_) => write!(f, "client write failed"),
        }
    }
}

impl std::error::Error for ClientIo {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFailed(e) | Self::WriteFailed(e) => Some(e),
        }
    }
}
