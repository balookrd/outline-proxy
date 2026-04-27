//! Shared QUIC connection — one `quinn::Connection` shared across many
//! VLESS / Shadowsocks sessions to the same uplink. Mirrors
//! [`crate::h3::shared::SharedH3Connection`] but without the HTTP/3 layer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use tokio::sync::OnceCell;

use super::oversize::OversizeStream;
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
    /// ALPN negotiated during the TLS handshake. Used by callers to
    /// branch between MTU-aware variants (`vless-mtu`, `ss-mtu`) and
    /// the legacy single-ALPN behaviour. Empty if the peer did not
    /// negotiate any ALPN, which is unexpected for our deployments
    /// but tolerated to keep the field infallible.
    pub(super) negotiated_alpn: Vec<u8>,
    /// Connection-level oversize-record bidi stream, lazy-opened on
    /// first use. Carries UDP payloads that exceed the negotiated
    /// `max_datagram_size`. `None` when the negotiated ALPN is one of
    /// the legacy non-MTU variants (e.g. plain `vless` / `ss`); the
    /// per-session send paths fall back to `OversizedUdpDatagram`
    /// errors in that case so the TUN UDP engine drops the packet.
    pub(super) oversize_stream: OnceCell<Arc<OversizeStream>>,
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

    /// ALPN negotiated during the TLS handshake. Empty bytes if no
    /// ALPN was negotiated (unexpected for outline deployments).
    pub fn negotiated_alpn(&self) -> &[u8] {
        &self.negotiated_alpn
    }

    /// `true` when the negotiated ALPN supports the oversize-record
    /// stream fallback (one of [`super::ALPN_VLESS_MTU`] /
    /// [`super::ALPN_SS_MTU`]).
    pub fn supports_oversize_stream(&self) -> bool {
        super::alpn_supports_oversize(&self.negotiated_alpn)
    }

    /// Get or lazy-open the connection-level oversize-record bidi
    /// stream. Returns `Err` if the negotiated ALPN does not advertise
    /// oversize-stream support, or if the underlying `open_bi` fails.
    /// Subsequent calls reuse the same stream regardless of how it was
    /// opened (locally on first send, or accepted from the peer if it
    /// opens first).
    pub async fn ensure_oversize_stream(self: &Arc<Self>) -> Result<Arc<OversizeStream>> {
        if !self.supports_oversize_stream() {
            bail!("oversize-stream not supported on this connection's negotiated ALPN");
        }
        let stream = self
            .oversize_stream
            .get_or_try_init(|| async {
                let (send, recv) = self.open_bidi_stream().await?;
                Ok::<_, anyhow::Error>(OversizeStream::from_local_open(send, recv))
            })
            .await?;
        Ok(Arc::clone(stream))
    }

    /// Install an oversize-stream that was accepted from the peer (the
    /// peer opened it first). Idempotent: if a local-opened stream is
    /// already cached, returns the existing one; otherwise installs and
    /// returns the supplied one.
    pub fn install_accepted_oversize_stream(
        &self,
        stream: Arc<OversizeStream>,
    ) -> Arc<OversizeStream> {
        // OnceCell::set returns Err with the original value when full.
        match self.oversize_stream.set(Arc::clone(&stream)) {
            Ok(()) => stream,
            Err(_) => Arc::clone(self.oversize_stream.get().expect("set returned Err so a value is present")),
        }
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

impl Drop for SharedQuicConnection {
    fn drop(&mut self) {
        // Send CONNECTION_CLOSE so peer-side state — and the demuxer's
        // parked `read_datagram` / `accept_bi` tasks (which now hold
        // only `Weak` back-refs) — wake immediately, instead of waiting
        // out the 30 s idle timeout configured in
        // `quic_client_config`. No-op if the connection is already
        // closed by the peer or by an earlier call.
        self.connection.close(0u32.into(), b"shared connection dropped");
    }
}
