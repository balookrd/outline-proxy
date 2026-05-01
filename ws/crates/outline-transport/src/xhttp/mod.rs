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
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngCore;
use std::convert::Infallible;
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

mod h1;
#[cfg(feature = "h3")]
mod h3;

#[cfg(test)]
#[path = "tests/packet_up.rs"]
mod tests_packet_up;

#[cfg(test)]
#[path = "tests/packet_up_h1.rs"]
mod tests_packet_up_h1;

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

/// Submode selector. Picked from the dial URL's query string
/// (`?mode=stream-one` selects stream-one; anything else, including
/// no query, means packet-up). The mode is not threaded through
/// the dial-dispatcher signature — instead `connect_xhttp` reads it
/// off the URL each call, which keeps the caller config minimal:
/// you write the URL you want and the carrier follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpSubmode {
    #[default]
    PacketUp,
    StreamOne,
}

impl std::fmt::Display for XhttpSubmode {
    /// Renders the dashed spelling the server's `?mode=` query
    /// expects, so the same string can be echoed back on dashboards
    /// and logs without re-mapping. Stable wire shape, do not change.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PacketUp => "packet-up",
            Self::StreamOne => "stream-one",
        })
    }
}

impl XhttpSubmode {
    /// Extracts the submode from a `?mode=...` query parameter on
    /// the dial URL. Accepts both dashed (`stream-one`) and
    /// underscored (`stream_one`) spellings to match what the server
    /// accepts. Anything else (or absence) → packet-up.
    pub fn from_url(url: &Url) -> Self {
        let Some(query) = url.query() else {
            return Self::PacketUp;
        };
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("mode=") {
                return match value {
                    "stream-one" | "stream_one" => Self::StreamOne,
                    _ => Self::PacketUp,
                };
            }
        }
        Self::PacketUp
    }

    fn append_to_query(&self, base: &str) -> String {
        match self {
            Self::PacketUp => base.to_owned(),
            Self::StreamOne => {
                if base.contains('?') {
                    format!("{base}&mode=stream-one")
                } else {
                    format!("{base}?mode=stream-one")
                }
            },
        }
    }
}

/// Pick the submode the dialer will actually use for a given carrier.
/// Two clamps stack on top of the URL-derived value:
///   1. The h1 carrier supports packet-up only (it cannot multiplex a
///      streaming GET against a streaming POST on a single keep-alive
///      socket), so callers asking for stream-one over h1 are silently
///      coerced. Without the clamp the inner `connect_xhttp_h1` bails,
///      which would propagate as a hard dial failure even though
///      packet-up is a safe substitute.
///   2. The per-host stream-one block — see [`crate::xhttp_submode_cache`] —
///      clamps stream-one to packet-up for `DOWNGRADE_TTL` after a
///      recent stream-one failure on this `host:port`. This avoids
///      re-paying the doomed handshake on every dial when the network
///      path between the client and server cannot carry stream-one
///      (CDN buffering, middlebox idle-timeout, etc.).
async fn resolve_effective_submode(url: &Url, mode: TransportMode) -> XhttpSubmode {
    let mut submode = XhttpSubmode::from_url(url);
    if matches!(mode, TransportMode::XhttpH1) {
        submode = XhttpSubmode::PacketUp;
    }
    crate::xhttp_submode_cache::effective_submode(url, submode).await
}

/// Boxed body type used by every XHTTP request the client issues.
/// Hyper's `SendRequest<B>` is monomorphic in `B`, so we pick a
/// single `BoxBody` shape that fits the empty-GET / Full-POST /
/// streaming-POST cases all at once.
pub(super) type RequestBody = BoxBody<Bytes, Infallible>;

pub(super) fn empty_request_body() -> RequestBody {
    Empty::<Bytes>::new().boxed()
}

pub(super) fn full_request_body(payload: Bytes) -> RequestBody {
    Full::new(payload).boxed()
}

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
    // `build_client_config` consults the test override slot itself, so
    // a `OnceLock` here is fine: the first call captures whichever
    // root store is current, and tests that need the override install
    // it before the first dial.
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
    /// Submode the dialer landed on. Differs from the URL-requested
    /// submode when the inline stream-one→packet-up retry kicked in,
    /// so the uplink layer can surface the actual carrier shape on
    /// dashboards instead of the originally-requested one.
    active_submode: XhttpSubmode,
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

    /// The XHTTP submode this stream is actually carrying (after any
    /// inline stream-one→packet-up fallback at dial time). The h-version
    /// is reflected separately by the surrounding `TransportMode` —
    /// this method only tells you whether the carrier is `stream-one`
    /// or `packet-up`.
    pub fn active_submode(&self) -> XhttpSubmode {
        self.active_submode
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
        active_submode: XhttpSubmode,
    ) -> Self {
        Self { incoming, outgoing, closed: false, active_submode, _driver: driver }
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
    let submode = resolve_effective_submode(url, mode).await;
    match mode {
        TransportMode::XhttpH2 => {},
        TransportMode::XhttpH1 => {
            return h1::connect_xhttp_h1(cache, url, submode, fwmark, ipv6_first, resume_request)
                .await;
        },
        #[cfg(feature = "h3")]
        TransportMode::XhttpH3 => {
            return h3::connect_xhttp_h3(cache, url, submode, fwmark, ipv6_first, resume_request)
                .await;
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
    // Profile picked once per dial — every GET / POST in this h2
    // session shares the same browser identity so an observer never
    // sees a single peer split across two fingerprints. `Option` is
    // a `Copy` reference into the static pool, so we pass it freely
    // into spawned sub-tasks below.
    let profile = crate::fingerprint_profile::select(url);

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

        let (issued_session_id, driver, active_submode) = match submode {
            XhttpSubmode::PacketUp => {
                // Open the GET synchronously so the resume-id
                // round-trip completes before we hand the stream to
                // the caller. The body drain is spawned as a
                // sub-task; POSTs are pipelined per `start_send`.
                let (issued, body) =
                    open_h2_get(send_request.clone(), &target, resume_request, profile).await?;
                let driver = tokio::spawn(driver_loop_h2(
                    send_request,
                    target.clone(),
                    in_tx,
                    out_rx,
                    body,
                    profile,
                ));
                (issued, driver, XhttpSubmode::PacketUp)
            },
            XhttpSubmode::StreamOne => {
                // Stream-one is a single bidirectional POST: open
                // it synchronously to read response headers, then
                // hand the response body and the request-body
                // sender to the driver. On dial-time failure we
                // retry packet-up on the same h2 connection — the
                // TCP/TLS/h2 cost is sunk and the failure is most
                // likely middlebox-shaped (the CDN refused to
                // forward the streaming request body), so trying
                // the simpler carrier on the surviving connection
                // recovers without burning a fresh handshake.
                match open_h2_stream_one(send_request.clone(), &target, resume_request, profile)
                    .await
                {
                    Ok((issued, body, frame_tx)) => {
                        let driver = tokio::spawn(driver_loop_h2_stream_one(
                            in_tx, out_rx, body, frame_tx,
                        ));
                        crate::xhttp_submode_cache::record_success(url, XhttpSubmode::StreamOne)
                            .await;
                        (issued, driver, XhttpSubmode::StreamOne)
                    },
                    Err(stream_err) => {
                        warn!(
                            %url,
                            error = %format!("{stream_err:#}"),
                            "xhttp h2 stream-one failed, falling back to packet-up on same connection"
                        );
                        crate::xhttp_submode_cache::record_failure(url, XhttpSubmode::StreamOne)
                            .await;
                        let (issued, body) =
                            open_h2_get(send_request.clone(), &target, resume_request, profile)
                                .await?;
                        let driver = tokio::spawn(driver_loop_h2(
                            send_request,
                            target.clone(),
                            in_tx,
                            out_rx,
                            body,
                            profile,
                        ));
                        (issued, driver, XhttpSubmode::PacketUp)
                    },
                }
            },
        };

        debug!(
            %url, %session_id, mode = "xhttp_h2", ?submode, ?active_submode,
            ?issued_session_id, ?resume_request,
            "xhttp session opened"
        );
        Ok::<_, anyhow::Error>((
            XhttpStream {
                incoming: in_rx,
                outgoing: out_tx,
                closed: false,
                active_submode,
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
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
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
    let mut req = builder
        .body(empty_request_body())
        .context("failed to build xhttp GET request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
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

/// Stream-one carrier on h2: a single bidirectional POST whose
/// request body is the uplink and whose response body is the
/// downlink. The synchronously-built `frame_tx` lets the driver
/// task feed body chunks into the request stream, while the
/// returned `Incoming` is consumed by the downlink drain.
async fn open_h2_stream_one(
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(
    Option<SessionId>,
    hyper::body::Incoming,
    mpsc::Sender<hyper::body::Frame<Bytes>>,
)> {
    let (frame_tx, frame_rx) = mpsc::channel::<hyper::body::Frame<Bytes>>(8);
    let body_stream = futures_util::stream::unfold(frame_rx, |mut rx| async move {
        rx.recv().await.map(|frame| (Ok::<_, Infallible>(frame), rx))
    });
    let body: RequestBody = StreamBody::new(body_stream).boxed();

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_submode(XhttpSubmode::StreamOne))
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .header(RESUME_CAPABLE_HEADER, "1");
    if let Some(id) = resume_request {
        builder = builder.header(RESUME_REQUEST_HEADER, id.to_hex());
    }
    let mut req = builder
        .body(body)
        .context("failed to build xhttp stream-one request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
    send.ready().await.context("xhttp h2 not ready for stream-one")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp stream-one send_request failed")?;
    if !resp.status().is_success() {
        bail!("xhttp stream-one returned {}", resp.status());
    }
    let issued = parse_session_response(resp.headers());
    Ok((issued, resp.into_body(), frame_tx))
}

async fn driver_loop_h2_stream_one(
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
    frame_tx: mpsc::Sender<hyper::body::Frame<Bytes>>,
) {
    // Spawn the response-body drain as a sub-task so the uplink
    // pump below can run concurrently. The shape mirrors
    // `driver_loop_h2` for packet-up.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_hyper_body(body, &drain_in_tx).await {
            debug!(?error, "xhttp stream-one downlink reader exited");
            let _ = drain_in_tx
                .send(Err(io_ws_err("xhttp stream-one downlink ended")))
                .await;
        } else {
            let _ = drain_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

    // Uplink pump: every Message::Binary becomes a body frame on
    // the request stream. Closing `frame_tx` (we drop it on exit)
    // ends the request body and lets the server see EOF.
    while let Some(msg) = out_rx.recv().await {
        match msg {
            Message::Binary(b) => {
                if frame_tx
                    .send(hyper::body::Frame::data(b))
                    .await
                    .is_err()
                {
                    break;
                }
            },
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx
                    .send(Err(io_ws_err("xhttp does not carry text")))
                    .await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        }
    }
    drop(frame_tx);
    debug!("xhttp stream-one driver exiting");
}

pub(super) fn parse_session_response(headers: &http::HeaderMap) -> Option<SessionId> {
    headers
        .get(SESSION_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex)
}

pub(super) fn default_port_for(use_tls: bool) -> u16 {
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

    /// Packet-up uplink POST URL: appends the per-packet `seq` to
    /// the path, matching xray / sing-box's `PlacementPath` default
    /// (`<base>/<session>/<seq>`). The server still accepts the
    /// older header-based form (`X-Xhttp-Seq`) for backward
    /// compatibility, but this client now emits the path form so
    /// the wire shape is identical to what xray-family clients
    /// produce — the same byte stream in either ecosystem.
    pub(super) fn full_uri_with_seq(&self, seq: u64) -> String {
        format!(
            "{}://{}{}/{}/{seq}",
            self.scheme, self.authority, self.base_path, self.session_id,
        )
    }

    /// Same as [`Self::full_uri`] but with a `?mode=...` selector
    /// appended for the stream-one carrier. Packet-up sessions use
    /// the bare URI (the server defaults to packet-up when the
    /// query is absent or unrecognised).
    pub(super) fn full_uri_with_submode(&self, submode: XhttpSubmode) -> String {
        submode.append_to_query(&self.full_uri())
    }
}

async fn h2_handshake(
    addr: SocketAddr,
    host: &str,
    use_tls: bool,
    fwmark: Option<u32>,
) -> Result<http2::SendRequest<RequestBody>> {
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

async fn spawn_h2<T>(io: TokioIo<T>) -> Result<http2::SendRequest<RequestBody>>
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
// in the type signature of `spawn_h2`. `pub(super)` so the h1
// sibling module reuses the same wrapper for its own handshake.
pub(super) enum BoxedIo {
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
    send_request: http2::SendRequest<RequestBody>,
    target: Arc<XhttpTarget>,
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) {
    // GET drain sub-task. The GET request and response headers were
    // already exchanged synchronously in `connect_xhttp`; this task
    // just pulls body chunks until EOF and forwards them to the
    // inbound channel.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_hyper_body(body, &drain_in_tx).await {
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
            if let Err(error) = post_one(send, target.as_ref(), seq, bytes, profile).await {
                warn!(?error, seq, "xhttp POST failed");
                let _ = in_tx_for_err
                    .send(Err(io_ws_err("xhttp uplink POST failed")))
                    .await;
            }
        });
    }
    debug!("xhttp driver exiting");
}

/// Drain a hyper response body into the inbound channel as
/// `Message::Binary` frames. Used by the h1 and h2 packet-up GET
/// handlers, both of which produce `hyper::body::Incoming`. `pub(super)`
/// so the `h1` sibling reuses the same drain shape.
pub(super) async fn drain_hyper_body(
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
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    seq: u64,
    payload: Bytes,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<()> {
    // Path-based seq (`<base>/<session>/<seq>`) is xray / sing-box's
    // default placement; the server matches both shapes but emitting
    // path-based here keeps the wire byte-identical to what xray
    // produces, so an on-path observer cannot tell our client apart
    // from a vanilla xray one.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_seq(seq))
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .body(full_request_body(payload))
        .context("failed to build xhttp POST request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
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
