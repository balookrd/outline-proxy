//! Client-side XHTTP packet-up transport.
//!
//! Mirror image of the server's `outline-ss-rust` module of the same
//! name. Multiplexes a long-lived GET (downlink) and a sequence of
//! short POSTs (uplink) over a single shared HTTP/2 connection. The
//! GET and POST share the same URL `<base>/<session-id>`, where
//! `session-id` is a random per-connection token chosen by us.
//!
//! Why h2 only in this MVP:
//! * h2 mux'es every request into the same TCP+TLS connection, so a
//!   long-lived GET and a stream of POSTs cost one TCP socket and
//!   one TLS handshake.
//! * h3 (raw QUIC) needs a separate dial path through `quinn` and
//!   manual h3 client setup; we add it once h2 is proven.
//!
//! Why pipelined POSTs (not strictly serial):
//! * Forcing one-at-a-time uplink would halve effective TX bandwidth
//!   and make every `Sink::start_send` await an HTTP round-trip.
//! * The server's reorder buffer already absorbs out-of-order seqs,
//!   so we can fire the next POST before the previous one returns.
//!
//! Failure modes:
//! * GET drop: driver completes the `incoming` channel; the stream
//!   surfaces as `None`. Callers retry by dialing a new session.
//! * POST 4xx/5xx: driver records it on a flag; the next outbound
//!   send sees a closed channel and `Sink::poll_ready` returns the
//!   recorded error. We do not attempt cross-session retry — that
//!   belongs at the uplink-manager layer.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::{Method, Request, Version};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngCore;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, warn};
use url::Url;

use crate::config::TransportMode;
use crate::dns::resolve_host_with_preference;
use crate::dns_cache::DnsCache;
use crate::guards::AbortOnDrop;
use crate::resumption::SessionId;
use crate::{TransportOperation, connect_tcp_socket};

#[cfg(feature = "h3")]
mod h3;

#[cfg(test)]
#[path = "tests/packet_up.rs"]
mod tests_packet_up;

/// Lower-cased name of the request header carrying the in-order
/// sequence number for an uplink POST. Mirrors the server constant.
/// `pub(super)` so the h3 sibling module can reuse the same wire
/// constant without a copy that could drift out of sync.
pub(super) const SEQ_HEADER: &str = "x-xhttp-seq";

/// Cross-transport session resumption: client → server. Mirrors the
/// header used by the WS-upgrade path so a single token works for
/// any resumption-aware client/server pair.
pub(super) const RESUME_REQUEST_HEADER: &str = "x-outline-resume";

/// Cross-transport session resumption: client capability flag. The
/// server only mints a fresh token when this is `1` (or when
/// `RESUME_REQUEST_HEADER` is present), so non-resumption clients
/// pay nothing.
pub(super) const RESUME_CAPABLE_HEADER: &str = "x-outline-resume-capable";

/// Cross-transport session resumption: server → client.
pub(super) const SESSION_RESPONSE_HEADER: &str = "x-outline-session";

/// Bounds for the random session id used in `<base>/<id>`. The id is
/// opaque to the server; we just need it to be wide enough to avoid
/// per-session collision and narrow enough to fit inside one URL
/// path segment without bloating logs.
const SESSION_ID_BYTES: usize = 16;

/// Cap for the per-session inbound (downlink) channel. Frames in
/// flight are already capped by h2 flow control on the wire; this
/// is a small in-memory buffer that smooths the gap between the
/// driver task drain and `Stream::poll_next`. `pub(super)` so the
/// h3 sibling module reuses the same sizing.
pub(super) const INBOUND_CHANNEL_CAPACITY: usize = 32;

/// Cap for the per-session outbound (uplink) channel. Sized small —
/// `start_send` simply queues into here, the driver task spawns a
/// POST per item and h2 enforces flow control end-to-end.
/// `pub(super)` for the same reason as the inbound cap.
pub(super) const OUTBOUND_CHANNEL_CAPACITY: usize = 32;

/// Time budget for the initial dial: TCP + TLS + h2 handshake +
/// first POST/GET ack. Matches the bound used by the WS h2 dial
/// in `h2/shared.rs` for parity with manager-level retry windows.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS config (h2 ALPN) cached lazily — built once per process.
static XHTTP_H2_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn h2_tls_config() -> Arc<rustls::ClientConfig> {
    Arc::clone(XHTTP_H2_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"h2"])))
}

/// Outbound stream returned by [`connect_xhttp`]. Implements the
/// same `Stream<Item = Result<Message, WsError>>` + `Sink<Message>`
/// surface as the WebSocket adapters so it slots into existing
/// dispatch without bespoke handling.
pub(crate) struct XhttpStream {
    incoming: mpsc::Receiver<Result<Message, WsError>>,
    outgoing: mpsc::Sender<Message>,
    closed: bool,
    // The driver task owns the h2 SendRequest, the GET reader
    // sub-task and the POST fan-out sub-tasks. Dropping the stream
    // aborts the driver, which cancels every sub-task and frees the
    // h2 connection.
    _driver: AbortOnDrop,
}

impl XhttpStream {
    /// Returns true while the underlying h2 connection is still
    /// believed healthy. Cheap proxy for `Sink` health that the
    /// uplink manager polls between sends; once the driver task
    /// has closed the outbound channel we surface that as `false`.
    pub fn is_healthy(&self) -> bool {
        !self.outgoing.is_closed()
    }

    /// Constructor used by the h3 sibling module: it builds the
    /// driver task and the channel pair on its own and hands the
    /// finished triple here. Keeps the field-level details of
    /// `XhttpStream` (closed flag, channel typing) private to this
    /// module while giving carrier modules a single way in.
    pub(super) fn from_channels(
        incoming: mpsc::Receiver<Result<Message, WsError>>,
        outgoing: mpsc::Sender<Message>,
        driver: AbortOnDrop,
    ) -> Self {
        Self { incoming, outgoing, closed: false, _driver: driver }
    }
}

impl Stream for XhttpStream {
    type Item = Result<Message, WsError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

impl Sink<Message> for XhttpStream {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.closed || self.outgoing.is_closed() {
            return Poll::Ready(Err(io_ws_err("xhttp outgoing closed")));
        }
        // tokio mpsc has no public `poll_reserve` on stable; the
        // capacity is small and we expect bursty sends, so reporting
        // ready unconditionally is fine — `start_send` falls back to
        // try_send and propagates the rare-case Full as an error.
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if self.closed {
            return Err(io_ws_err("xhttp stream already closed"));
        }
        match self.outgoing.try_send(item) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.closed = true;
                Err(io_ws_err("xhttp outgoing closed"))
            },
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The driver task is behind. Treat this as a
                // transient health failure rather than a hard error
                // — caller will retry on the next select tick.
                Err(io_ws_err("xhttp outgoing buffer full"))
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // We have no application-level buffer; h2 flow control and
        // the channel itself are the only flushing layers and they
        // self-drain.
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.closed = true;
        // Drop the sender by replacing it with a closed one. The
        // driver task observes this through `outbound.recv()`
        // returning None and exits, which aborts the GET sub-task.
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        self.outgoing = closed_tx;
        Poll::Ready(Ok(()))
    }
}

pub(super) fn io_ws_err(msg: &'static str) -> WsError {
    WsError::Io(std::io::Error::other(msg))
}

/// Dials an XHTTP packet-up session against `url`. The host and
/// port come from `url`; the **path component** of `url` is used
/// as the XHTTP base — the server registers `<base>/<id>` and we
/// generate `<id>` randomly.
pub(crate) async fn connect_xhttp(
    cache: &DnsCache,
    url: &Url,
    mode: TransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    resume_request: Option<SessionId>,
) -> Result<(XhttpStream, Option<SessionId>)> {
    match mode {
        TransportMode::XhttpH2 => {},
        #[cfg(feature = "h3")]
        TransportMode::XhttpH3 => {
            // h3 carrier lives in the sibling module so the
            // quinn / h3 dependencies stay behind the `h3`
            // feature gate. Returns a fully-wired `XhttpStream`.
            return h3::connect_xhttp_h3(cache, url, fwmark, ipv6_first, resume_request).await;
        },
        #[cfg(not(feature = "h3"))]
        TransportMode::XhttpH3 => {
            bail!("xhttp_h3 requires the `h3` feature at build time");
        },
        other => bail!("connect_xhttp called with non-xhttp mode {other}"),
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("xhttp url missing host: {url}"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("xhttp url missing port and no scheme default: {url}"))?;
    let base_path = url.path().trim_end_matches('/').to_owned();
    if base_path.is_empty() {
        bail!("xhttp url path must be a non-empty base (e.g. /xh): {url}");
    }
    let use_tls = matches!(url.scheme(), "https" | "wss");

    let dial = async {
        let addrs =
            resolve_host_with_preference(cache, &host, port, "failed to resolve xhttp host", ipv6_first)
                .await?;
        let server_addr = *addrs.first().ok_or_else(|| {
            anyhow::Error::new(TransportOperation::DnsResolveNoAddresses { host: host.clone() })
        })?;
        let send_request = h2_handshake(server_addr, &host, use_tls, fwmark).await?;
        let session_id = generate_session_id()?;

        let (in_tx, in_rx) = mpsc::channel::<Result<Message, WsError>>(INBOUND_CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);

        let authority = if port == default_port_for(use_tls) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let scheme = if use_tls { "https" } else { "http" };
        let target = Arc::new(XhttpTarget {
            scheme: scheme.into(),
            authority,
            base_path: base_path.into(),
            session_id: session_id.clone(),
        });

        // Open the GET synchronously so the resume-id round-trip
        // (X-Outline-Resume on the way out, X-Outline-Session on the
        // way back) completes before we hand the stream to the
        // caller. The body drain is then spawned as a sub-task.
        let (issued_session_id, body) =
            open_h2_get(send_request.clone(), &target, resume_request).await?;

        let driver = tokio::spawn(driver_loop_h2(
            send_request,
            target,
            in_tx,
            out_rx,
            body,
        ));

        debug!(
            %url, %session_id, mode = "xhttp_h2",
            ?issued_session_id, ?resume_request,
            "xhttp packet-up session opened"
        );
        Ok::<_, anyhow::Error>((
            XhttpStream {
                incoming: in_rx,
                outgoing: out_tx,
                closed: false,
                _driver: AbortOnDrop::new(driver),
            },
            issued_session_id,
        ))
    };

    timeout(FRESH_CONNECT_TIMEOUT, dial)
        .await
        .with_context(|| format!("xhttp dial to {url} timed out"))?
        .with_context(|| format!("xhttp dial to {url} failed"))
}

/// Issues the long-lived GET, awaits response headers, and pulls
/// out the optional `X-Outline-Session` resume token. The body is
/// returned for the caller to drain in its own sub-task. Surfacing
/// the issued id synchronously (rather than via a side channel) is
/// what lets the dial path stash the token in the resume cache
/// before any data flows.
async fn open_h2_get(
    mut send: http2::SendRequest<Full<Bytes>>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
) -> Result<(Option<SessionId>, hyper::body::Incoming)> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target.full_uri())
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .header(RESUME_CAPABLE_HEADER, "1");
    if let Some(id) = resume_request {
        builder = builder.header(RESUME_REQUEST_HEADER, id.to_hex());
    }
    let req = builder
        .body(Full::<Bytes>::new(Bytes::new()))
        .context("failed to build xhttp GET request")?;
    send.ready().await.context("xhttp h2 not ready for GET")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp GET send_request failed")?;
    if !resp.status().is_success() {
        bail!("xhttp GET returned {}", resp.status());
    }
    let issued = parse_session_response(resp.headers());
    Ok((issued, resp.into_body()))
}

fn parse_session_response(headers: &http::HeaderMap) -> Option<SessionId> {
    headers
        .get(SESSION_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex)
}

fn default_port_for(use_tls: bool) -> u16 {
    if use_tls { 443 } else { 80 }
}

pub(super) struct XhttpTarget {
    pub(super) scheme: String,
    pub(super) authority: String,
    pub(super) base_path: String,
    pub(super) session_id: String,
}

impl XhttpTarget {
    pub(super) fn full_uri(&self) -> String {
        format!(
            "{}://{}{}/{}",
            self.scheme, self.authority, self.base_path, self.session_id,
        )
    }
}

async fn h2_handshake(
    addr: SocketAddr,
    host: &str,
    use_tls: bool,
    fwmark: Option<u32>,
) -> Result<http2::SendRequest<Full<Bytes>>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;
    if use_tls {
        let connector = TlsConnector::from(h2_tls_config());
        let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("invalid TLS server name for xhttp: {host}"))?
        };
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake for xhttp failed")?;
        spawn_h2(TokioIo::new(BoxedIo::Tls(tls))).await
    } else {
        // Plain h2 over TCP — used by tests and trusted-network
        // deployments. Production callers should run TLS.
        spawn_h2(TokioIo::new(BoxedIo::Plain(tcp))).await
    }
}

async fn spawn_h2<T>(io: TokioIo<T>) -> Result<http2::SendRequest<Full<Bytes>>>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .context("xhttp h2 handshake failed")?;
    // Hyper's connection future drives the multiplexer; without this
    // background task the whole mux freezes after the handshake.
    tokio::spawn(async move {
        if let Err(error) = conn.await {
            debug!(?error, "xhttp h2 connection ended");
        }
    });
    Ok(send_request)
}

// Simple AsyncRead+Write wrapper so we can hold either a plain TCP
// stream or a TLS stream behind a single TokioIo without an enum
// in the type signature of `spawn_h2`.
enum BoxedIo {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for BoxedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Safety: project via `get_mut` since the inner enum holds
        // owned streams; `Pin::new` on the inner is sound because
        // both `TcpStream` and `TlsStream` are `Unpin`.
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            BoxedIo::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
            BoxedIo::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_flush(cx),
            BoxedIo::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            BoxedIo::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn driver_loop_h2(
    send_request: http2::SendRequest<Full<Bytes>>,
    target: Arc<XhttpTarget>,
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
) {
    // GET drain sub-task. The GET request and response headers were
    // already exchanged synchronously in `connect_xhttp`; this task
    // just pulls body chunks until EOF and forwards them to the
    // inbound channel.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_h2_body(body, &drain_in_tx).await {
            debug!(?error, "xhttp GET reader exited");
            let _ = drain_in_tx.send(Err(io_ws_err("xhttp downlink ended"))).await;
        } else {
            // Clean EOF on the response body — surface a Close so
            // upstream sees a recognisable shutdown rather than a
            // silent stop.
            let _ = drain_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

    // POST loop: pop messages, send them with monotonically-
    // increasing seq. Pipelined — we spawn the actual hyper send
    // as a sub-task so successive POSTs can overlap on the wire.
    let mut next_seq: u64 = 0;
    loop {
        let msg = match out_rx.recv().await {
            Some(msg) => msg,
            None => break,
        };
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx.send(Err(io_ws_err("xhttp does not carry text"))).await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        };
        let seq = next_seq;
        next_seq = next_seq.saturating_add(1);
        let mut send = send_request.clone();
        let target = Arc::clone(&target);
        let in_tx_for_err = in_tx.clone();
        // Hyper requires `ready().await` before issuing a new
        // stream; doing it inline serialises POSTs against
        // _hyper's_ flow-control state but does not serialise
        // against the actual wire — once the request is queued the
        // POST runs to completion concurrently.
        if let Err(error) = send.ready().await {
            warn!(?error, "xhttp h2 connection lost while waiting for capacity");
            let _ = in_tx
                .send(Err(io_ws_err("xhttp h2 stream not ready")))
                .await;
            break;
        }
        tokio::spawn(async move {
            if let Err(error) = post_one(send, target.as_ref(), seq, bytes).await {
                warn!(?error, seq, "xhttp POST failed");
                let _ = in_tx_for_err
                    .send(Err(io_ws_err("xhttp uplink POST failed")))
                    .await;
            }
        });
    }
    debug!("xhttp driver exiting");
}

async fn drain_h2_body(
    mut body: hyper::body::Incoming,
    in_tx: &mpsc::Sender<Result<Message, WsError>>,
) -> Result<()> {
    while let Some(frame) = body.frame().await {
        let frame = frame.context("xhttp GET body frame error")?;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
            && in_tx.send(Ok(Message::Binary(data))).await.is_err()
        {
            // Consumer gave up — exit cleanly.
            return Ok(());
        }
    }
    Ok(())
}

async fn post_one(
    mut send: http2::SendRequest<Full<Bytes>>,
    target: &XhttpTarget,
    seq: u64,
    payload: Bytes,
) -> Result<()> {
    let req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri())
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .header(SEQ_HEADER, seq.to_string())
        .body(Full::new(payload))
        .context("failed to build xhttp POST request")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp POST send_request failed")?;
    let status = resp.status();
    // Drain the (small) response body so hyper releases the stream.
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        bail!("xhttp POST seq={seq} returned {status}");
    }
    Ok(())
}

pub(super) fn generate_session_id() -> Result<String> {
    let mut raw = [0_u8; SESSION_ID_BYTES];
    rand::thread_rng().fill_bytes(&mut raw);
    // URL-safe alphanumeric. Bias from `% 62` is negligible at
    // these lengths and gives a strict subset of `is_valid_session_id`
    // on the server side.
    const ALPHABET: &[u8; 62] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let id: String = raw
        .iter()
        .map(|byte| char::from(ALPHABET[(*byte as usize) % ALPHABET.len()]))
        .collect();
    Ok(id)
}
