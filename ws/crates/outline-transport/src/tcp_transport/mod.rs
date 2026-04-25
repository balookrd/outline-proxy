mod reader;
mod writer;

pub use reader::{SocketTcpReader, TcpShadowsocksReader, WsReadDiag, WsTcpReader};
pub use writer::{SocketTcpWriter, TcpShadowsocksWriter, WsTcpWriter};
#[cfg(feature = "quic")]
pub use reader::QuicTcpReader;
#[cfg(feature = "quic")]
pub use writer::QuicTcpWriter;

use crate::vless::{VlessTcpReader, VlessTcpWriter};

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
    Vless(VlessTcpWriter),
    /// Shadowsocks over a raw QUIC bidi stream.
    #[cfg(feature = "quic")]
    QuicSs(QuicTcpWriter),
}

impl TcpWriter {
    pub fn request_salt(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ws(w) => w.request_salt(),
            Self::Socket(w) => w.request_salt(),
            Self::Vless(_) => None,
            #[cfg(feature = "quic")]
            Self::QuicSs(w) => w.request_salt(),
        }
    }

    pub fn supports_half_close(&self) -> bool {
        match self {
            Self::Ws(w) => w.supports_half_close(),
            Self::Socket(w) => w.supports_half_close(),
            Self::Vless(w) => w.supports_half_close(),
            #[cfg(feature = "quic")]
            Self::QuicSs(w) => w.supports_half_close(),
        }
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_chunk(payload).await,
            Self::Socket(w) => w.send_chunk(payload).await,
            Self::Vless(w) => w.send_chunk(payload).await,
            #[cfg(feature = "quic")]
            Self::QuicSs(w) => w.send_chunk(payload).await,
        }
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_keepalive().await,
            Self::Socket(w) => w.send_keepalive().await,
            Self::Vless(w) => w.send_keepalive().await,
            #[cfg(feature = "quic")]
            Self::QuicSs(w) => w.send_keepalive().await,
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.close().await,
            Self::Socket(w) => w.close().await,
            Self::Vless(w) => w.close().await,
            #[cfg(feature = "quic")]
            Self::QuicSs(w) => w.close().await,
        }
    }
}

/// Owns either a WebSocket or a plain-socket Shadowsocks reader.
pub enum TcpReader {
    Ws(WsTcpReader),
    Socket(SocketTcpReader),
    Vless(VlessTcpReader),
    /// Shadowsocks over a raw QUIC bidi stream.
    #[cfg(feature = "quic")]
    QuicSs(QuicTcpReader),
}

impl TcpReader {
    pub fn with_request_salt(self, salt: Option<[u8; 32]>) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_request_salt(salt)),
            Self::Socket(r) => Self::Socket(r.with_request_salt(salt)),
            Self::Vless(r) => Self::Vless(r),
            #[cfg(feature = "quic")]
            Self::QuicSs(r) => Self::QuicSs(r.with_request_salt(salt)),
        }
    }

    /// Attach diagnostic context to a WebSocket reader; no-op for socket readers.
    /// VLESS reader takes its diag at construction (in `vless_tcp_pair_from_ws`),
    /// so this is a no-op for `Vless` here.
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
            Self::Vless(r) => r.closed_cleanly(),
            #[cfg(feature = "quic")]
            Self::QuicSs(r) => r.closed_cleanly,
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Ws(r) => r.read_chunk().await,
            Self::Socket(r) => r.read_chunk().await,
            Self::Vless(r) => r.read_chunk().await,
            #[cfg(feature = "quic")]
            Self::QuicSs(r) => r.read_chunk().await,
        }
    }
}
