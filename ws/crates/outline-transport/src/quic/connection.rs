//! Shared QUIC connection — one `quinn::Connection` shared across many
//! VLESS / Shadowsocks sessions to the same uplink. Mirrors
//! [`crate::h3::shared::SharedH3Connection`] but without the HTTP/3 layer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use tokio::sync::OnceCell;

use super::vless_udp::VlessUdpDemuxer;

/// One QUIC connection per `(server_name, port, fwmark)` cache key.
/// Bidi streams are opened on demand (`open_bidi_stream`) for TCP-like
/// VLESS / SS sessions; QUIC datagrams (`send_datagram` / `read_datagram`)
/// are used for UDP sessions and shared by all callers on the connection.
pub struct SharedQuicConnection {
    pub(super) id: u64,
    /// Held to prevent the endpoint from getting GC'd while connections
    /// are alive.
    #[allow(dead_code)]
    pub(super) endpoint: quinn::Endpoint,
    pub(super) connection: quinn::Connection,
    /// Soft-close flag: any failure opening a new stream / sending a
    /// datagram flips this so concurrent callers race to the
    /// invalidate-cache path instead of blocking on a sick connection.
    pub(super) closed: AtomicBool,
    /// Diagnostic counter — increments per stream / datagram session so
    /// we can correlate `session_death` bursts with a single underlying
    /// connection's lifetime.
    pub(super) sessions_opened: Arc<AtomicU64>,
    /// Connection-level VLESS-UDP demuxer, lazy-spawned on the first
    /// VLESS-UDP session opened on this connection. Reads incoming
    /// `session_id || payload` datagrams and routes them to the
    /// per-session mpsc. Only used when this connection's ALPN is
    /// `vless` and at least one UDP session is active.
    pub(super) vless_udp_demuxer: OnceCell<Arc<VlessUdpDemuxer>>,
    pub(super) _driver_task: crate::AbortOnDrop,
}

impl SharedQuicConnection {
    pub fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.connection.close_reason().is_none()
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Open a fresh bidirectional stream for a TCP-like session
    /// (VLESS-TCP / SS-TCP). Failure flips the soft-close flag — the
    /// caller is expected to invalidate the cache entry and retry on a
    /// fresh connection.
    pub async fn open_bidi_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        if !self.is_open() {
            bail!("shared quic connection is already closed");
        }
        match self.connection.open_bi().await {
            Ok(pair) => {
                self.sessions_opened.fetch_add(1, Ordering::Relaxed);
                Ok(pair)
            }
            Err(error) => {
                self.closed.store(true, Ordering::Relaxed);
                Err(error).context("failed to open quic bidi stream")
            }
        }
    }

    /// Send a single QUIC datagram (RFC 9221). Length is bounded by the
    /// negotiated `max_datagram_size` — typically ~1200 bytes on the
    /// public Internet. Larger payloads must be rejected by the caller
    /// before reaching this point.
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<()> {
        if !self.is_open() {
            bail!("shared quic connection is already closed");
        }
        self.connection
            .send_datagram(data)
            .context("failed to send quic datagram")
    }

    /// Receive the next inbound datagram. Returns `None` when the
    /// connection closes.
    pub async fn recv_datagram(&self) -> Result<Option<bytes::Bytes>> {
        match self.connection.read_datagram().await {
            Ok(b) => Ok(Some(b)),
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed) => Ok(None),
            Err(e) => Err(e).context("failed to read quic datagram"),
        }
    }

    /// Maximum datagram payload size negotiated for this connection,
    /// or `None` if datagrams are not supported by the peer.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Get or lazy-spawn the connection-level VLESS-UDP demuxer. The
    /// first call spawns the reader task that pulls datagrams off the
    /// connection and dispatches them to per-session channels by the
    /// 4-byte session_id prefix. Subsequent calls reuse the same
    /// demuxer. Caller must hold `Arc<SharedQuicConnection>` so the
    /// connection outlives the demuxer.
    pub(crate) async fn vless_udp_demuxer(self: &Arc<Self>) -> &Arc<VlessUdpDemuxer> {
        self.vless_udp_demuxer
            .get_or_init(|| async { VlessUdpDemuxer::spawn(Arc::clone(self)) })
            .await
    }

    /// Underlying connection — used by the VLESS-UDP demuxer to call
    /// `read_datagram`. `pub(crate)` because exposing the raw
    /// `quinn::Connection` would let callers bypass the soft-close
    /// flag.
    pub(crate) fn raw_connection(&self) -> &quinn::Connection {
        &self.connection
    }
}

impl crate::SharedConnectionHealth for SharedQuicConnection {
    fn is_open(&self) -> bool {
        self.is_open()
    }

    fn conn_id(&self) -> u64 {
        self.id
    }

    fn mode(&self) -> &'static str {
        "quic"
    }
}

impl crate::shared_cache::CachedEntry for SharedQuicConnection {
    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_open(&self) -> bool {
        self.is_open()
    }
}
