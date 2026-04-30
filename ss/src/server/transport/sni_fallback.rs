//! L4 SNI-routed fallback. Sister of the L7 [`super::fallback`] —
//! same camouflage idea, different OSI layer.
//!
//! When `[sni_fallback]` is set and the inbound TCP listener
//! terminates TLS, every accepted stream is peeked for a parseable
//! ClientHello. If the SNI matches `match_sni`, the connection is
//! handed off to the local TLS terminator exactly as before. If the
//! SNI is missing (and `allow_no_sni = false`) or does not match, the
//! raw TCP stream — including the captured ClientHello bytes — is
//! spliced to an upstream backend that handles foreign SNIs with its
//! own cert. From a passive observer's point of view the listener now
//! looks like an SNI-routed haproxy frontend.
//!
//! Implementation outline:
//! - Pre-read into a small buffer until [`rustls::server::Acceptor`]
//!   reports a complete ClientHello (or until we exceed
//!   `max_client_hello_bytes`, in which case the connection is
//!   closed — junk bytes do not get forwarded to the backend so
//!   they cannot poison its logs).
//! - The Acceptor we use here is throw-away: it only parses the
//!   ClientHello so we can read the SNI. The buffered bytes feed
//!   either into the *real* TLS handshake (via [`PrependStream`]) or
//!   into the backend splice — they are never re-read from the wire.
//! - On splice we open a fresh TCP connection to `backend`, optionally
//!   prepend a HAProxy PROXY-protocol header so the upstream still
//!   logs the real client IP, write the captured ClientHello, then
//!   bidirectionally copy until either side closes.

use std::{io, net::SocketAddr, pin::Pin, sync::Arc, task::{Context, Poll}};

use anyhow::{Context as _, Result, anyhow};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tracing::{debug, warn};

use crate::config::SniFallbackConfig;

use super::proxy_protocol::{PpTransport, encode_proxy_protocol};

/// Per-process state for the SNI fallback. Built once at startup and
/// shared by every accepted TLS-listener connection.
#[derive(Clone)]
pub(in crate::server) struct SniFallbackContext {
    pub(in crate::server) config: Arc<SniFallbackConfig>,
    /// Inbound listener bind addr — used as the destination for
    /// PROXY-protocol headers. `0.0.0.0` / `[::]` degrade to UNSPEC
    /// (v2) / UNKNOWN (v1) since we don't currently learn the
    /// per-connection local addr.
    pub(in crate::server) inbound_listen: SocketAddr,
}

/// Outcome of [`peek_sni`]. Carries the bytes we already consumed off
/// the wire so the caller can either replay them into the local TLS
/// handshake or write them to the backend splice — without ever
/// re-reading them from the socket (we cannot, the kernel buffer has
/// already given them to us).
pub(in crate::server) struct PeekedClientHello {
    /// Lowercased SNI when the client sent one. `None` for `server_name`
    /// extension absent.
    pub sni: Option<String>,
    /// Every byte we read from the inbound socket while waiting for
    /// the Acceptor to deliver the ClientHello.
    pub buffered: Vec<u8>,
}

/// Pre-reads the inbound socket until [`rustls::server::Acceptor`]
/// hands us a parsed ClientHello (or `max_bytes` is reached, in which
/// case we treat the data as malformed and bail).
pub(in crate::server) async fn peek_sni(
    stream: &mut TcpStream,
    max_bytes: usize,
) -> Result<PeekedClientHello> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut buffered = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .context("inbound TLS socket read failed during SNI peek")?;
        if n == 0 {
            anyhow::bail!("inbound socket closed before TLS ClientHello");
        }
        buffered.extend_from_slice(&chunk[..n]);
        if buffered.len() > max_bytes {
            anyhow::bail!(
                "TLS ClientHello exceeded max_client_hello_bytes ({max_bytes})"
            );
        }

        // `Acceptor::read_tls` consumes from the cursor, advancing
        // its internal state machine; we feed only the new bytes
        // each round so the codec doesn't see duplicates.
        let mut cursor = std::io::Cursor::new(&chunk[..n]);
        if let Err(error) = acceptor.read_tls(&mut cursor) {
            return Err(anyhow!(error)).context("rustls Acceptor rejected ClientHello bytes");
        }

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let ch = accepted.client_hello();
                let sni = ch.server_name().map(|s| s.to_ascii_lowercase());
                return Ok(PeekedClientHello { sni, buffered });
            },
            Ok(None) => continue,
            Err((error, _)) => {
                return Err(anyhow!(error)).context("invalid TLS ClientHello");
            },
        }
    }
}

/// `true` when `sni` matches any whitelist entry. Caller passes a
/// lowercase SNI (or `None` and the function honours
/// `config.allow_no_sni`).
pub(in crate::server) fn sni_matches_ours(
    config: &SniFallbackConfig,
    sni: Option<&str>,
) -> bool {
    match sni {
        None => config.allow_no_sni,
        Some(name) => config.match_sni.iter().any(|m| m.matches(name)),
    }
}

/// Splice the inbound TCP stream to `backend`, prepending the
/// already-buffered ClientHello bytes (so the backend sees a complete
/// TLS handshake) and optionally a HAProxy PROXY-protocol header.
pub(in crate::server) async fn splice_to_backend(
    ctx: &SniFallbackContext,
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
    buffered: Vec<u8>,
) -> Result<()> {
    let mut backend = TcpStream::connect(ctx.config.backend_authority.as_str())
        .await
        .with_context(|| {
            format!(
                "failed to connect to sni_fallback backend {}",
                ctx.config.backend_authority,
            )
        })?;

    if let Some(version) = ctx.config.proxy_protocol {
        let mut header = Vec::with_capacity(64);
        encode_proxy_protocol(
            &mut header,
            version,
            peer_addr,
            ctx.inbound_listen,
            PpTransport::Stream,
        );
        backend
            .write_all(&header)
            .await
            .context("failed to write PROXY-protocol header to sni_fallback backend")?;
    }

    backend
        .write_all(&buffered)
        .await
        .context("failed to forward ClientHello to sni_fallback backend")?;

    // copy_bidirectional closes naturally when either side hits EOF,
    // which is exactly what we want for a TLS pass-through. Errors
    // are demoted to debug — the inbound peer may walk away mid-flight
    // (e.g. probe scanners) and that is not noteworthy.
    match tokio::io::copy_bidirectional(&mut inbound, &mut backend).await {
        Ok((bytes_in, bytes_out)) => {
            debug!(
                ?peer_addr,
                bytes_in,
                bytes_out,
                "sni_fallback splice closed cleanly",
            );
        },
        Err(error) => {
            debug!(?peer_addr, ?error, "sni_fallback splice ended with error");
        },
    }
    Ok(())
}

/// `AsyncRead`/`AsyncWrite` wrapper that drains a pre-read buffer
/// before falling through to the underlying stream. Used to feed the
/// ClientHello bytes back into the real TLS handshake when the SNI
/// belongs to us — `tokio_rustls::TlsAcceptor` would otherwise wait
/// forever for bytes that are already sitting in our `Vec`.
pub(in crate::server) struct PrependStream<S> {
    /// Bytes drained on every `poll_read` until empty; then `inner`
    /// takes over. We track the read offset rather than draining a
    /// `VecDeque` because the buffer is small (a few KiB) and the
    /// tail copy in `Vec::drain` is wasteful for that pattern.
    pub(in crate::server) buf: Vec<u8>,
    pub(in crate::server) read_pos: usize,
    pub(in crate::server) inner: S,
}

impl<S> PrependStream<S> {
    pub(in crate::server) fn new(buf: Vec<u8>, inner: S) -> Self {
        Self { buf, read_pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.buf.len() {
            let remaining = &self.buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            // Drop the buffer once it is fully drained so subsequent
            // reads skip the prefix branch entirely. Holding a few
            // KiB per connection forever is fine but pointless.
            if self.read_pos == self.buf.len() {
                self.buf = Vec::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Top-level dispatch helper. Called by the TLS listener for every
/// accepted stream when `[sni_fallback]` is configured. Returns
/// `Ok(Some(stream))` to continue with the local TLS terminator, or
/// `Ok(None)` if the stream was spliced to the backend (caller stops
/// processing it). Errors are fatal for this stream only.
pub(in crate::server) async fn dispatch_sni(
    ctx: &SniFallbackContext,
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
) -> Result<Option<PrependStream<TcpStream>>> {
    let peeked = match peek_sni(&mut inbound, ctx.config.max_client_hello_bytes).await {
        Ok(p) => p,
        Err(error) => {
            warn!(?peer_addr, ?error, "sni_fallback could not parse ClientHello");
            return Err(error);
        },
    };

    if sni_matches_ours(&ctx.config, peeked.sni.as_deref()) {
        Ok(Some(PrependStream::new(peeked.buffered, inbound)))
    } else {
        debug!(?peer_addr, sni = ?peeked.sni, "splicing foreign SNI to backend");
        splice_to_backend(ctx, inbound, peer_addr, peeked.buffered).await?;
        Ok(None)
    }
}
