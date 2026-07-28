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

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result, anyhow};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tracing::{debug, warn};

use crate::config::{SniBackend, SniFallbackConfig, SniMatcher};
use crate::metrics::Metrics;

use super::proxy_protocol::{PpTransport, encode_proxy_protocol};

/// Per-process state for the SNI fallback. Built once at startup and
/// shared by every accepted TLS-listener connection.
#[derive(Clone)]
pub(in crate::server) struct SniFallbackContext {
    pub(in crate::server) config: Arc<SniFallbackConfig>,
    /// Precomputed routing table derived from `config`: exact matches
    /// resolve in O(1) via a hashmap; wildcards fall back to a linear
    /// scan only when the exact lookup misses.
    pub(in crate::server) lookup: Arc<SniLookup>,
    /// Inbound listener bind addr — used as the destination for
    /// PROXY-protocol headers. `0.0.0.0` / `[::]` degrade to UNSPEC
    /// (v2) / UNKNOWN (v1) since we don't currently learn the
    /// per-connection local addr.
    pub(in crate::server) inbound_listen: SocketAddr,
}

impl SniFallbackContext {
    pub(in crate::server) fn new(
        config: Arc<SniFallbackConfig>,
        inbound_listen: SocketAddr,
    ) -> Self {
        let lookup = Arc::new(SniLookup::build(&config));
        Self { config, lookup, inbound_listen }
    }
}

/// Where a peeked SNI should land. `Local` keeps the connection on the
/// inbound TLS terminator; `Backend(idx)` indexes into
/// [`SniFallbackConfig::backends`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum SniRoute {
    Local,
    Backend(usize),
}

/// Routing table built once from a [`SniFallbackConfig`]. Hot path is
/// the exact-match `HashMap`; wildcards and the catch-all backend run
/// only when the hashmap misses.
///
/// Priority on collision: local entries are inserted before backend
/// entries, so an exact SNI claimed by both wins for `Local`. Backends
/// are inserted in declaration order, mirroring the previous linear
/// `find_backend` scan. Note this changes one corner: an exact match
/// declared anywhere in the table now beats a wildcard declared earlier
/// — by design, since exact configuration is more specific intent than
/// a wildcard that happens to subsume it.
#[derive(Debug)]
pub(in crate::server) struct SniLookup {
    exact: HashMap<String, SniRoute>,
    wildcards: Vec<(SniMatcher, SniRoute)>,
    /// Index of the catch-all backend (empty `match_sni`), if any.
    /// Validation guarantees there is at most one and it is the last
    /// backend, so a `usize` is sufficient.
    catch_all: Option<usize>,
    allow_no_sni: bool,
}

impl SniLookup {
    pub(in crate::server) fn build(config: &SniFallbackConfig) -> Self {
        let mut exact: HashMap<String, SniRoute> = HashMap::new();
        let mut wildcards: Vec<(SniMatcher, SniRoute)> = Vec::new();

        for matcher in &config.match_sni {
            insert_matcher(&mut exact, &mut wildcards, matcher, SniRoute::Local);
        }

        let mut catch_all = None;
        for (idx, backend) in config.backends.iter().enumerate() {
            if backend.match_sni.is_empty() {
                catch_all = Some(idx);
                continue;
            }
            for matcher in &backend.match_sni {
                insert_matcher(&mut exact, &mut wildcards, matcher, SniRoute::Backend(idx));
            }
        }

        Self {
            exact,
            wildcards,
            catch_all,
            allow_no_sni: config.allow_no_sni,
        }
    }

    /// Resolve a peeked SNI. `sni` must already be lowercased (peek
    /// path does this). `None` means the ClientHello had no
    /// `server_name` extension.
    pub(in crate::server) fn lookup(&self, sni: Option<&str>) -> Option<SniRoute> {
        match sni {
            None => {
                if self.allow_no_sni {
                    Some(SniRoute::Local)
                } else {
                    self.catch_all.map(SniRoute::Backend)
                }
            },
            Some(name) => {
                if let Some(route) = self.exact.get(name) {
                    return Some(*route);
                }
                for (matcher, route) in &self.wildcards {
                    if matcher.matches(name) {
                        return Some(*route);
                    }
                }
                self.catch_all.map(SniRoute::Backend)
            },
        }
    }
}

fn insert_matcher(
    exact: &mut HashMap<String, SniRoute>,
    wildcards: &mut Vec<(SniMatcher, SniRoute)>,
    matcher: &SniMatcher,
    route: SniRoute,
) {
    match matcher {
        SniMatcher::Exact(name) => {
            // First writer wins: local is inserted before backends, and
            // backends are inserted in declaration order, so this
            // preserves the historical priority on duplicates.
            exact.entry(name.clone()).or_insert(route);
        },
        SniMatcher::Wildcard { .. } => {
            wildcards.push((matcher.clone(), route));
        },
    }
}

/// Why [`peek_sni`] gave up on an inbound stream. Drives both the log
/// level and the `reason` label on
/// `outline_ss_sni_peek_failed_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum SniPeekFailure {
    /// The peer went away (FIN/EOF/RST) before a complete ClientHello
    /// arrived. This is the ordinary shape of a TCP liveness probe, a
    /// port scanner, or a client that changed its mind — a listener on
    /// a public port sees it continuously and there is nothing an
    /// operator can act on, so it must not cost a `warn` line each
    /// time. The counter keeps the volume observable.
    PeerClosed,
    /// The inbound socket read failed for a reason other than the peer
    /// closing. Rare, and worth a look when it happens.
    ReadFailed,
    /// Bytes kept arriving but never formed a ClientHello within
    /// `max_client_hello_bytes` — a peer speaking something that is not
    /// TLS at all, or a deliberately oversized handshake.
    Oversized,
    /// The bytes were a TLS handshake and rustls rejected them. The
    /// signal this whole path exists to surface — always `warn`.
    Malformed,
}

impl SniPeekFailure {
    pub(in crate::server) fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::ReadFailed => "read_failed",
            Self::Oversized => "oversized",
            Self::Malformed => "malformed",
        }
    }

    /// Whether an operator should see a log line per occurrence.
    /// `PeerClosed` is the only routine bucket; everything else says
    /// something reached us that we could not make sense of.
    pub(in crate::server) fn is_noteworthy(self) -> bool {
        !matches!(self, Self::PeerClosed)
    }
}

/// A failed [`peek_sni`], classified for logging and metrics while
/// keeping the original error for the caller's context chain.
pub(in crate::server) struct SniPeekError {
    pub(in crate::server) failure: SniPeekFailure,
    pub(in crate::server) source: anyhow::Error,
}

impl SniPeekError {
    fn new(failure: SniPeekFailure, source: anyhow::Error) -> Self {
        Self { failure, source }
    }
}

/// Whether an inbound read error means "the peer is gone" rather than
/// "something went wrong on our side". Mirrors the classification the
/// TLS listener applies to handshake errors, so a connection aborted
/// mid-peek and one aborted mid-handshake land in the same bucket.
fn is_peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
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
) -> std::result::Result<PeekedClientHello, SniPeekError> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut buffered = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];

    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(error) => {
                let failure = if is_peer_gone(&error) {
                    SniPeekFailure::PeerClosed
                } else {
                    SniPeekFailure::ReadFailed
                };
                return Err(SniPeekError::new(
                    failure,
                    anyhow!(error).context("inbound TLS socket read failed during SNI peek"),
                ));
            },
        };
        if n == 0 {
            return Err(SniPeekError::new(
                SniPeekFailure::PeerClosed,
                anyhow!("inbound socket closed before TLS ClientHello"),
            ));
        }
        buffered.extend_from_slice(&chunk[..n]);
        if buffered.len() > max_bytes {
            return Err(SniPeekError::new(
                SniPeekFailure::Oversized,
                anyhow!("TLS ClientHello exceeded max_client_hello_bytes ({max_bytes})"),
            ));
        }

        // `Acceptor::read_tls` consumes from the cursor, advancing
        // its internal state machine; we feed only the new bytes
        // each round so the codec doesn't see duplicates.
        let mut cursor = std::io::Cursor::new(&chunk[..n]);
        if let Err(error) = acceptor.read_tls(&mut cursor) {
            return Err(SniPeekError::new(
                SniPeekFailure::Malformed,
                anyhow!(error).context("rustls Acceptor rejected ClientHello bytes"),
            ));
        }

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let ch = accepted.client_hello();
                let sni = ch.server_name().map(|s| s.to_ascii_lowercase());
                return Ok(PeekedClientHello { sni, buffered });
            },
            Ok(None) => continue,
            Err((error, _)) => {
                return Err(SniPeekError::new(
                    SniPeekFailure::Malformed,
                    anyhow!(error).context("invalid TLS ClientHello"),
                ));
            },
        }
    }
}

/// Splice the inbound TCP stream to `backend`, prepending the
/// already-buffered ClientHello bytes (so the backend sees a complete
/// TLS handshake) and optionally a HAProxy PROXY-protocol header.
pub(in crate::server) async fn splice_to_backend(
    backend: &SniBackend,
    inbound_listen: SocketAddr,
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
    buffered: Vec<u8>,
) -> Result<()> {
    let mut upstream = TcpStream::connect(backend.authority.as_str())
        .await
        .with_context(|| {
            format!("failed to connect to sni_fallback backend {}", backend.authority)
        })?;

    if let Some(version) = backend.proxy_protocol {
        let mut header = Vec::with_capacity(64);
        encode_proxy_protocol(&mut header, version, peer_addr, inbound_listen, PpTransport::Stream);
        upstream
            .write_all(&header)
            .await
            .context("failed to write PROXY-protocol header to sni_fallback backend")?;
    }

    upstream
        .write_all(&buffered)
        .await
        .context("failed to forward ClientHello to sni_fallback backend")?;

    // copy_bidirectional closes naturally when either side hits EOF,
    // which is exactly what we want for a TLS pass-through. Errors
    // are demoted to debug — the inbound peer may walk away mid-flight
    // (e.g. probe scanners) and that is not noteworthy.
    match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
        Ok((bytes_in, bytes_out)) => {
            debug!(?peer_addr, bytes_in, bytes_out, "sni_fallback splice closed cleanly",);
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

/// Outcome of [`dispatch_sni`] when the connection is staying for the
/// local TLS terminator. The SNI is carried alongside the stream so the
/// TLS listener can attach it to handshake-failure logs and metrics
/// (otherwise rustls swallows it before we get a chance).
pub(in crate::server) struct LocalTlsAccepted {
    pub stream: PrependStream<TcpStream>,
    pub sni: Option<String>,
}

/// Top-level dispatch helper. Called by the TLS listener for every
/// accepted stream when `[sni_fallback]` is configured. Returns
/// `Ok(Some(accepted))` to continue with the local TLS terminator, or
/// `Ok(None)` if the stream was spliced to a backend (caller stops
/// processing it). Errors are fatal for this stream only.
pub(in crate::server) async fn dispatch_sni(
    ctx: &SniFallbackContext,
    metrics: &Metrics,
    mut inbound: TcpStream,
    peer_addr: SocketAddr,
) -> Result<Option<LocalTlsAccepted>> {
    let peeked = match peek_sni(&mut inbound, ctx.config.max_client_hello_bytes).await {
        Ok(p) => p,
        Err(SniPeekError { failure, source }) => {
            metrics.record_sni_peek_failed(failure.as_str());
            // A connection that closes before its ClientHello is a normal
            // event on a public port — liveness probes and scanners produce
            // a steady stream of them, and our own clients' bare-TCP uplink
            // checks alone were measured at ~1 400/hour per server. Left at
            // `warn` it drowned the journal; the counter keeps it visible
            // without one line per connect. Anything we could not parse
            // still warns.
            if failure.is_noteworthy() {
                warn!(
                    ?peer_addr,
                    error = ?source,
                    reason = failure.as_str(),
                    "sni_fallback could not parse ClientHello",
                );
            } else {
                debug!(
                    ?peer_addr,
                    error = ?source,
                    reason = failure.as_str(),
                    "sni_fallback peek ended before a ClientHello arrived",
                );
            }
            return Err(source);
        },
    };

    match ctx.lookup.lookup(peeked.sni.as_deref()) {
        Some(SniRoute::Local) => Ok(Some(LocalTlsAccepted {
            stream: PrependStream::new(peeked.buffered, inbound),
            sni: peeked.sni,
        })),
        Some(SniRoute::Backend(idx)) => {
            let backend = &ctx.config.backends[idx];
            debug!(
                ?peer_addr,
                sni = ?peeked.sni,
                backend = %backend.authority,
                "splicing foreign SNI to backend",
            );
            splice_to_backend(backend, ctx.inbound_listen, inbound, peer_addr, peeked.buffered)
                .await?;
            Ok(None)
        },
        None => {
            warn!(
                ?peer_addr,
                sni = ?peeked.sni,
                "sni_fallback: no backend matched, dropping connection",
            );
            Ok(None)
        },
    }
}
