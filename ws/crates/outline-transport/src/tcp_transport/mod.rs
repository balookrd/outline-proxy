mod reader;
mod writer;

pub use reader::{SocketTcpReader, TcpShadowsocksReader, WsReadDiag, WsTcpReader};
pub use writer::{SocketTcpWriter, TcpShadowsocksWriter, WsTcpWriter};

use anyhow::Result;

// ---------------------------------------------------------------------------
// Enum wrappers for mixed-transport storage
// ---------------------------------------------------------------------------

/// Owns either a WebSocket or a plain-socket Shadowsocks writer.
/// Use the concrete aliases (`WsTcpWriter` / `SocketTcpWriter`) when the
/// transport kind is statically known at the call site.
pub enum TcpWriter {
    Ws(WsTcpWriter),
    Socket(SocketTcpWriter),
}

impl TcpWriter {
    pub fn request_salt(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ws(w) => w.request_salt(),
            Self::Socket(w) => w.request_salt(),
        }
    }

    pub fn supports_half_close(&self) -> bool {
        match self {
            Self::Ws(w) => w.supports_half_close(),
            Self::Socket(w) => w.supports_half_close(),
        }
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_chunk(payload).await,
            Self::Socket(w) => w.send_chunk(payload).await,
        }
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_keepalive().await,
            Self::Socket(w) => w.send_keepalive().await,
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.close().await,
            Self::Socket(w) => w.close().await,
        }
    }
}

/// Owns either a WebSocket or a plain-socket Shadowsocks reader.
pub enum TcpReader {
    Ws(WsTcpReader),
    Socket(SocketTcpReader),
}

impl TcpReader {
    pub fn with_request_salt(self, salt: Option<[u8; 32]>) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_request_salt(salt)),
            Self::Socket(r) => Self::Socket(r.with_request_salt(salt)),
        }
    }

    /// Attach diagnostic context to a WebSocket reader; no-op for socket readers.
    pub fn with_diag(self, diag: WsReadDiag) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_diag(diag)),
            other => other,
        }
    }

    pub fn closed_cleanly(&self) -> bool {
        match self {
            Self::Ws(r) => r.closed_cleanly,
            Self::Socket(r) => r.closed_cleanly,
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Ws(r) => r.read_chunk().await,
            Self::Socket(r) => r.read_chunk().await,
        }
    }
}
