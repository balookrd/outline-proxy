mod reader;
mod writer;

#[cfg(feature = "quic")]
pub use reader::QuicTcpReader;
pub use reader::{SocketTcpReader, TcpShadowsocksReader, WsReadDiag, WsTcpReader};
#[cfg(feature = "quic")]
pub use writer::QuicTcpWriter;
pub use writer::{SocketTcpWriter, TcpShadowsocksWriter, WsTcpWriter};

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

    /// Tells the inner reader to expect a v1 Ack-Prefix control
    /// frame as the very first payload bytes after handshake.
    /// Forwarded to the WS (SS-WS) and VLESS variants — the
    /// Socket / raw-QUIC variants ignore the call so callers can
    /// wire it unconditionally regardless of negotiation outcome.
    pub fn with_expect_ack_prefix(self, expect: bool) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_expect_ack_prefix(expect)),
            Self::Vless(r) => Self::Vless(r.with_expect_ack_prefix(expect)),
            other => other,
        }
    }

    /// Tells the reader to expect a v2 Symmetric Downlink Replay
    /// frame after the v1 control frame on a resume hit. Forwarded
    /// to the WS / VLESS variants; Socket / raw-QUIC ignore it.
    pub fn with_expect_downlink_replay(self, expect: bool) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_expect_downlink_replay(expect)),
            Self::Vless(r) => Self::Vless(r.with_expect_downlink_replay(expect)),
            other => other,
        }
    }

    /// Returns the server-reported `up_acked` byte offset parsed from
    /// the v1 Ack-Prefix control frame. `None` for non-negotiating
    /// variants (Socket / raw-QUIC) and for negotiating variants
    /// where the prefix has not yet been parsed.
    pub fn upstream_acked_offset(&self) -> Option<u64> {
        match self {
            Self::Ws(r) => r.upstream_acked_offset(),
            Self::Vless(r) => r.upstream_acked_offset(),
            Self::Socket(_) => None,
            #[cfg(feature = "quic")]
            Self::QuicSs(_) => None,
        }
    }

    /// Drives the v1 Ack-Prefix control frame consume up-front,
    /// bounded by `timeout`. On success the parsed offset is parked
    /// on the inner reader and returned; subsequent
    /// [`Self::upstream_acked_offset`] calls observe the same value.
    /// `Ok(None)` on no-op (protocol not negotiated, prefix already
    /// consumed, or the reader is a non-negotiating variant).
    ///
    /// Forwarded to the WS (SS-WS) and VLESS variants. Socket /
    /// raw-QUIC variants return `Ok(None)` without touching the
    /// network.
    pub async fn consume_ack_prefix_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Option<u64>> {
        match self {
            Self::Ws(r) => r.consume_ack_prefix_with_timeout(timeout).await,
            Self::Vless(r) => r.consume_ack_prefix_with_timeout(timeout).await,
            Self::Socket(_) => Ok(None),
            #[cfg(feature = "quic")]
            Self::QuicSs(_) => Ok(None),
        }
    }

    /// Drives the v2 Symmetric Downlink Replay frame consume,
    /// bounded by `timeout` and capped by `max_bytes`. Surfaces the
    /// outcome (`Replay(payload)` / `Truncated`) to the caller, or
    /// `Ok(None)` when v2 is not engaged on this reader / variant.
    pub async fn consume_downlink_replay_with_timeout(
        &mut self,
        timeout: std::time::Duration,
        max_bytes: usize,
    ) -> anyhow::Result<Option<crate::downlink_replay::DownlinkReplayOutcome>> {
        match self {
            Self::Ws(r) => r.consume_downlink_replay_with_timeout(timeout, max_bytes).await,
            Self::Vless(r) => r.consume_downlink_replay_with_timeout(timeout, max_bytes).await,
            Self::Socket(_) => Ok(None),
            #[cfg(feature = "quic")]
            Self::QuicSs(_) => Ok(None),
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
