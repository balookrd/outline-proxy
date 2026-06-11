use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::config::TransportMode;
#[cfg(feature = "h3")]
use crate::h3::{
    H3WsStream, sockudo_to_tungstenite_message, sockudo_to_ws_error, tungstenite_to_sockudo_message,
};
use crate::resumption::SessionId;
use crate::xhttp::XhttpStream;

use super::h2::H2WsStream;

/// Trait for checking whether the shared multiplexed connection (H2 or H3)
/// underlying a websocket stream is still usable. Implemented by
/// `SharedH2Connection` and `SharedH3Connection`.
pub(crate) trait SharedConnectionHealth: Send + Sync {
    fn is_open(&self) -> bool;
    fn conn_id(&self) -> u64;
    fn mode(&self) -> &'static str;
}

pub(super) type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Maximum time an HTTP/1 WebSocket stream may sit idle (no frame in either
/// direction) before [`TransportStream::is_connection_alive`] starts
/// reporting `false`.  HTTP/1 has no shared multiplexed driver to notice a
/// silently-dropped TCP path, so the honest signal we have is "did we see
/// any frame recently?".  The standby pool's keepalive loop sends a Ping
/// every few seconds, so healthy pooled entries stay well inside this
/// threshold; stale ones (router NAT lost the mapping, middlebox dropped
/// the connection without a FIN) exceed it and are discarded at acquisition
/// time instead of being handed to a session as a zombie transport.
const H1_STALENESS_THRESHOLD: Duration = Duration::from_secs(60);

/// Tracks last-seen activity on an HTTP/1 WebSocket stream.  Cheap to clone
/// (internally an `Arc<AtomicU64>`) so split halves share a single counter.
/// Updated on any frame the [`Stream`] or [`Sink`] impl observes — data,
/// Ping, Pong, or Close all count as "the peer is still talking to us".
#[derive(Clone, Debug)]
pub(crate) struct H1Activity {
    last_activity_ms: Arc<AtomicU64>,
    baseline: Instant,
}

impl H1Activity {
    fn new() -> Self {
        let baseline = Instant::now();
        Self {
            last_activity_ms: Arc::new(AtomicU64::new(0)),
            baseline,
        }
    }

    fn touch(&self) {
        let ms = self.baseline.elapsed().as_millis() as u64;
        self.last_activity_ms.store(ms, Ordering::Relaxed);
    }

    fn is_fresh(&self, threshold: Duration) -> bool {
        let now_ms = self.baseline.elapsed().as_millis() as u64;
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last_ms) < threshold.as_millis() as u64
    }
}

// When the h3 feature is disabled, provide a zero-size never-constructable
// stub so that TransportStream::H3 remains a valid enum variant. The variant is
// unreachable at runtime because nothing in the non-h3 code path can create it.
#[cfg(not(feature = "h3"))]
pin_project! {
    struct H3WsStream { _never: std::convert::Infallible }
}

#[cfg(not(feature = "h3"))]
impl Stream for H3WsStream {
    type Item = Result<Message, WsError>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // SAFETY: Infallible can never be constructed, so this branch is unreachable.
        match *self.project()._never {}
    }
}

#[cfg(not(feature = "h3"))]
impl Sink<Message> for H3WsStream {
    type Error = WsError;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match *self.project()._never {}
    }
    fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
        match *self.project()._never {}
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match *self.project()._never {}
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match *self.project()._never {}
    }
}

pin_project! {
    /// A WebSocket stream parameterised over the underlying HTTP transport
    /// (HTTP/1, HTTP/2, or HTTP/3). Each variant wraps the transport-specific
    /// WebSocket implementation and exposes a unified `Stream` + `Sink<Message>`
    /// interface, so higher-level protocol code (the SOCKS proxy, the TCP/UDP
    /// Shadowsocks transports, the uplink standby pool) does not have to care
    /// which transport a given session is using.
    ///
    /// The `issued_session_id` slot carries the Session ID minted by the
    /// server in the `X-Outline-Session` response header on a successful
    /// WebSocket Upgrade — `None` if the server did not send one (most
    /// commonly because cross-transport session resumption is disabled
    /// at the server, or the client did not advertise `Resume-Capable`).
    /// Callers that participate in resumption stash this value before the
    /// stream is used and present it back via `X-Outline-Resume` on the
    /// next reconnect.
    ///
    /// The `ack_prefix_advertised_by_server` slot records whether the
    /// server echoed `X-Outline-Resume-Ack-Prefix: 1` on the upgrade
    /// response. When `true`, the first decoded SS-AEAD chunk on this
    /// stream is the v1 control frame defined in
    /// `docs/SESSION-RESUMPTION.md` (server repo) § Ack-Prefix Protocol —
    /// callers participating in mid-session retry must consume and parse
    /// it via [`crate::ack_prefix::parse_v1`] before treating any bytes
    /// as upstream payload.
    #[project = TransportStreamProj]
    pub enum TransportStream {
        Http1 {
            #[pin]
            inner: H1WsStream,
            activity: H1Activity,
            issued_session_id: Option<SessionId>,
            downgraded_from: Option<TransportMode>,
            ack_prefix_advertised_by_server: bool,
            // `true` when the server also echoed
            // `X-Outline-Resume-Symmetric-Replay: 1` on the upgrade
            // response, opting into the v2 Symmetric Downlink Replay
            // protocol. Spec gates v2 on v1, so this is `true` only
            // when `ack_prefix_advertised_by_server` is also `true`.
            // See `docs/SESSION-RESUMPTION.md` (server repo)
            // § Symmetric Downlink Replay (v2).
            symmetric_replay_advertised_by_server: bool,
        },
        H2 {
            #[pin]
            inner: H2WsStream,
            issued_session_id: Option<SessionId>,
            downgraded_from: Option<TransportMode>,
            ack_prefix_advertised_by_server: bool,
            // `true` when the server also echoed
            // `X-Outline-Resume-Symmetric-Replay: 1` on the upgrade
            // response, opting into the v2 Symmetric Downlink Replay
            // protocol. Spec gates v2 on v1, so this is `true` only
            // when `ack_prefix_advertised_by_server` is also `true`.
            // See `docs/SESSION-RESUMPTION.md` (server repo)
            // § Symmetric Downlink Replay (v2).
            symmetric_replay_advertised_by_server: bool,
        },
        H3 {
            #[pin]
            inner: H3WsStream,
            issued_session_id: Option<SessionId>,
            downgraded_from: Option<TransportMode>,
            ack_prefix_advertised_by_server: bool,
            // `true` when the server also echoed
            // `X-Outline-Resume-Symmetric-Replay: 1` on the upgrade
            // response, opting into the v2 Symmetric Downlink Replay
            // protocol. Spec gates v2 on v1, so this is `true` only
            // when `ack_prefix_advertised_by_server` is also `true`.
            // See `docs/SESSION-RESUMPTION.md` (server repo)
            // § Symmetric Downlink Replay (v2).
            symmetric_replay_advertised_by_server: bool,
        },
        /// VLESS-over-XHTTP packet-up. The inner stream multiplexes a
        /// long-lived GET (downlink) and a sequence of POSTs (uplink)
        /// onto a single h2 connection — see `crate::xhttp`.
        Xhttp {
            #[pin]
            inner: XhttpStream,
            issued_session_id: Option<SessionId>,
            downgraded_from: Option<TransportMode>,
            ack_prefix_advertised_by_server: bool,
            // `true` when the server also echoed
            // `X-Outline-Resume-Symmetric-Replay: 1` on the upgrade
            // response, opting into the v2 Symmetric Downlink Replay
            // protocol. Spec gates v2 on v1, so this is `true` only
            // when `ack_prefix_advertised_by_server` is also `true`.
            // See `docs/SESSION-RESUMPTION.md` (server repo)
            // § Symmetric Downlink Replay (v2).
            symmetric_replay_advertised_by_server: bool,
        },
    }
}

impl TransportStream {
    /// Wrap a raw HTTP/1 WebSocket stream, initialising activity tracking.
    /// The session-ID slot is left `None`; callers that did receive an
    /// `X-Outline-Session` header should use [`Self::new_http1_with_session`].
    pub fn new_http1(inner: H1WsStream) -> Self {
        Self::new_http1_with_session(inner, None)
    }

    /// Wrap a raw HTTP/1 WebSocket stream with the Session ID issued by
    /// the server during the upgrade. The server's `X-Outline-Session`
    /// header is observed in the upgrade response immediately above
    /// `client_async_tls`; that is the only place where we can read it
    /// before the connection becomes a generic `WebSocketStream`.
    pub fn new_http1_with_session(inner: H1WsStream, issued_session_id: Option<SessionId>) -> Self {
        let activity = H1Activity::new();
        // Mark the moment of birth as activity so a freshly-dialed stream is
        // not immediately reported stale before the first frame arrives.
        activity.touch();
        TransportStream::Http1 {
            inner,
            activity,
            issued_session_id,
            downgraded_from: None,
            ack_prefix_advertised_by_server: false,
            symmetric_replay_advertised_by_server: false,
        }
    }

    /// Returns the Session ID issued by the server in the upgrade
    /// response, or `None` when the server did not send one. Stable
    /// across the lifetime of the stream; reads are cheap (`Copy`).
    pub fn issued_session_id(&self) -> Option<SessionId> {
        match self {
            TransportStream::Http1 { issued_session_id, .. } => *issued_session_id,
            TransportStream::H2 { issued_session_id, .. } => *issued_session_id,
            TransportStream::H3 { issued_session_id, .. } => *issued_session_id,
            TransportStream::Xhttp { issued_session_id, .. } => *issued_session_id,
        }
    }

    /// Whether the server echoed `X-Outline-Resume-Ack-Prefix: 1` on the
    /// WebSocket upgrade response, confirming both peers will speak the
    /// Ack-Prefix Protocol v1 on this stream. When `true`, the first
    /// SS-AEAD chunk decoded from this stream is the 14-byte control
    /// frame — see [`crate::ack_prefix::parse_v1`].
    ///
    /// Always `false` for transports that do not yet implement the
    /// negotiation (callers below `connect_transport` that
    /// wrap raw streams via `new_http1` keep the default).
    pub fn ack_prefix_advertised_by_server(&self) -> bool {
        match self {
            TransportStream::Http1 { ack_prefix_advertised_by_server, .. }
            | TransportStream::H2 { ack_prefix_advertised_by_server, .. }
            | TransportStream::H3 { ack_prefix_advertised_by_server, .. }
            | TransportStream::Xhttp { ack_prefix_advertised_by_server, .. } => {
                *ack_prefix_advertised_by_server
            },
        }
    }

    /// Stamp whether the server echoed the Ack-Prefix capability on the
    /// upgrade response. Chainable; intended to be called inside
    /// `connect_transport` immediately after decoding the
    /// upgrade response, alongside `with_downgraded_from`.
    pub fn with_ack_prefix_advertised(mut self, advertised: bool) -> Self {
        match &mut self {
            TransportStream::Http1 { ack_prefix_advertised_by_server, .. }
            | TransportStream::H2 { ack_prefix_advertised_by_server, .. }
            | TransportStream::H3 { ack_prefix_advertised_by_server, .. }
            | TransportStream::Xhttp { ack_prefix_advertised_by_server, .. } => {
                *ack_prefix_advertised_by_server = advertised;
            },
        }
        self
    }

    /// Whether the server echoed `X-Outline-Resume-Symmetric-Replay: 1`
    /// on the upgrade response, confirming both peers will speak the
    /// v2 Symmetric Downlink Replay protocol. When `true`, after the
    /// v1 control frame is consumed the orchestrator must drive
    /// `consume_downlink_replay_with_timeout` on the reader before
    /// the relay loop resumes — the server has emitted (or will emit)
    /// the v2 `"ORDR"` frame as the next bytes on the wire.
    pub fn symmetric_replay_advertised_by_server(&self) -> bool {
        match self {
            TransportStream::Http1 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::H2 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::H3 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::Xhttp {
                symmetric_replay_advertised_by_server, ..
            } => *symmetric_replay_advertised_by_server,
        }
    }

    /// Stamp whether the server echoed the v2 capability on the
    /// upgrade response. Mirror of [`Self::with_ack_prefix_advertised`];
    /// chainable.
    pub fn with_symmetric_replay_advertised(mut self, advertised: bool) -> Self {
        match &mut self {
            TransportStream::Http1 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::H2 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::H3 {
                symmetric_replay_advertised_by_server, ..
            }
            | TransportStream::Xhttp {
                symmetric_replay_advertised_by_server, ..
            } => {
                *symmetric_replay_advertised_by_server = advertised;
            },
        }
        self
    }

    /// Wraps an [`XhttpStream`] freshly returned from `connect_xhttp`,
    /// tagging it with the resume token the server returned in
    /// `X-Outline-Session` (if any). The downgrade slot is filled
    /// later via `with_downgraded_from`.
    pub(crate) fn new_xhttp(inner: XhttpStream, issued_session_id: Option<SessionId>) -> Self {
        TransportStream::Xhttp {
            inner,
            issued_session_id,
            downgraded_from: None,
            ack_prefix_advertised_by_server: false,
            symmetric_replay_advertised_by_server: false,
        }
    }

    /// Returns the originally-requested `TransportMode` when this stream
    /// was produced by a transport-level fallback (clamp or inline retry),
    /// or `None` when the dial succeeded at the requested mode. Used by
    /// uplink-manager callsites to surface the downgrade in the per-uplink
    /// `mode_downgrade_until` window so routing/metrics see a consistent state.
    pub fn downgraded_from(&self) -> Option<TransportMode> {
        match self {
            TransportStream::Http1 { downgraded_from, .. } => *downgraded_from,
            TransportStream::H2 { downgraded_from, .. } => *downgraded_from,
            TransportStream::H3 { downgraded_from, .. } => *downgraded_from,
            TransportStream::Xhttp { downgraded_from, .. } => *downgraded_from,
        }
    }

    /// Whether the carrier is HTTP/3 — a WebSocket riding a QUIC stream.
    ///
    /// The QUIC connection underneath runs its own keep-alive and
    /// `max_idle_timeout` liveness check, so a UDP datagram channel on this
    /// carrier can skip the WS-level read-idle watchdog and the client
    /// keepalive Ping: not only are they redundant, the Ping is unsafe to
    /// rely on here. On a quiet H3 datagram channel the server cannot emit a
    /// reactive Pong without risking a connection-level `H3_INTERNAL_ERROR`,
    /// so proving liveness from inbound WS frames would spuriously tear down
    /// a healthy-but-quiet session. Callers trust the QUIC layer instead.
    pub fn is_h3(&self) -> bool {
        matches!(self, TransportStream::H3 { .. })
    }

    /// XHTTP submode the dialer actually landed on (after any inline
    /// `stream-one → packet-up` retry). `None` for non-XHTTP variants —
    /// the concept does not apply to WS or QUIC carriers. Used by the
    /// uplink layer to surface the effective carrier shape on the
    /// dashboard, distinct from the `TransportMode`'s h-version axis.
    pub fn xhttp_active_submode(&self) -> Option<crate::xhttp::XhttpSubmode> {
        match self {
            TransportStream::Xhttp { inner, .. } => Some(inner.active_submode()),
            _ => None,
        }
    }

    /// Stamp the originally-requested mode so the caller can detect that
    /// this stream is the result of a fallback. Chainable; intended to be
    /// called inside `connect_transport` immediately before
    /// returning the stream.
    pub fn with_downgraded_from(mut self, requested: Option<TransportMode>) -> Self {
        match &mut self {
            TransportStream::Http1 { downgraded_from, .. } => *downgraded_from = requested,
            TransportStream::H2 { downgraded_from, .. } => *downgraded_from = requested,
            TransportStream::H3 { downgraded_from, .. } => *downgraded_from = requested,
            TransportStream::Xhttp { downgraded_from, .. } => *downgraded_from = requested,
        }
        self
    }

    /// Returns `true` when the underlying shared connection (H2 / H3) is still
    /// usable.  For HTTP/1 — which has no shared driver — returns `true` while
    /// the stream has seen any frame (data, ping, pong, close) within the last
    /// `H1_STALENESS_THRESHOLD` (60 s), and `false` once that quiet period elapses.
    /// Used by the standby pool to discard zombie transports at acquisition
    /// time instead of handing them to a session that then hangs on the
    /// 5-minute idle watcher.
    pub fn is_connection_alive(&self) -> bool {
        match self {
            TransportStream::Http1 { activity, .. } => activity.is_fresh(H1_STALENESS_THRESHOLD),
            TransportStream::H2 { inner, .. } => inner.is_connection_alive(),
            #[cfg(feature = "h3")]
            TransportStream::H3 { inner, .. } => inner.is_connection_alive(),
            #[cfg(not(feature = "h3"))]
            TransportStream::H3 { .. } => true,
            TransportStream::Xhttp { inner, .. } => inner.is_healthy(),
        }
    }

    /// Returns `(conn_id, mode)` of the underlying shared multiplex connection,
    /// or `None` for Http1 streams which are 1:1 with their TCP socket.  Used by
    /// session diagnostics to correlate burst EOFs against a single shared H2/H3
    /// connection's lifecycle.
    pub fn shared_connection_info(&self) -> Option<(u64, &'static str)> {
        match self {
            TransportStream::Http1 { .. } => None,
            TransportStream::H2 { inner, .. } => Some(inner.shared_connection_info()),
            #[cfg(feature = "h3")]
            TransportStream::H3 { inner, .. } => Some(inner.shared_connection_info()),
            #[cfg(not(feature = "h3"))]
            TransportStream::H3 { .. } => None,
            // XHTTP rides its own private h2 connection per session;
            // there is no shared driver to label, so report None and
            // keep the conn-life diagnostic clean.
            TransportStream::Xhttp { .. } => None,
        }
    }
}

impl Stream for TransportStream {
    type Item = Result<Message, WsError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.project() {
            TransportStreamProj::Http1 { inner, activity, .. } => {
                let poll = inner.poll_next(cx);
                if let std::task::Poll::Ready(Some(_)) = &poll {
                    activity.touch();
                }
                poll
            },
            TransportStreamProj::H2 { inner, .. } => inner.poll_next(cx),
            #[cfg(feature = "h3")]
            TransportStreamProj::H3 { inner, .. } => match inner.poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(message))) => {
                    std::task::Poll::Ready(Some(Ok(sockudo_to_tungstenite_message(message))))
                },
                std::task::Poll::Ready(Some(Err(error))) => {
                    std::task::Poll::Ready(Some(Err(sockudo_to_ws_error(error))))
                },
                std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                std::task::Poll::Pending => std::task::Poll::Pending,
            },
            // Stub variant — Infallible inner field makes this branch unreachable.
            #[cfg(not(feature = "h3"))]
            TransportStreamProj::H3 { inner, .. } => inner.poll_next(cx),
            TransportStreamProj::Xhttp { inner, .. } => inner.poll_next(cx),
        }
    }
}

impl Sink<Message> for TransportStream {
    type Error = WsError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            TransportStreamProj::Http1 { inner, .. } => inner.poll_ready(cx),
            TransportStreamProj::H2 { inner, .. } => inner.poll_ready(cx),
            #[cfg(feature = "h3")]
            TransportStreamProj::H3 { inner, .. } => {
                inner.poll_ready(cx).map_err(sockudo_to_ws_error)
            },
            #[cfg(not(feature = "h3"))]
            TransportStreamProj::H3 { inner, .. } => inner.poll_ready(cx),
            TransportStreamProj::Xhttp { inner, .. } => inner.poll_ready(cx),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project() {
            TransportStreamProj::Http1 { inner, activity, .. } => {
                let result = inner.start_send(item);
                if result.is_ok() {
                    activity.touch();
                }
                result
            },
            TransportStreamProj::H2 { inner, .. } => inner.start_send(item),
            #[cfg(feature = "h3")]
            TransportStreamProj::H3 { inner, .. } => inner
                .start_send(tungstenite_to_sockudo_message(item)?)
                .map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            TransportStreamProj::H3 { inner, .. } => inner.start_send(item),
            TransportStreamProj::Xhttp { inner, .. } => inner.start_send(item),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            TransportStreamProj::Http1 { inner, .. } => inner.poll_flush(cx),
            TransportStreamProj::H2 { inner, .. } => inner.poll_flush(cx),
            #[cfg(feature = "h3")]
            TransportStreamProj::H3 { inner, .. } => {
                inner.poll_flush(cx).map_err(sockudo_to_ws_error)
            },
            #[cfg(not(feature = "h3"))]
            TransportStreamProj::H3 { inner, .. } => inner.poll_flush(cx),
            TransportStreamProj::Xhttp { inner, .. } => inner.poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            TransportStreamProj::Http1 { inner, .. } => inner.poll_close(cx),
            TransportStreamProj::H2 { inner, .. } => inner.poll_close(cx),
            #[cfg(feature = "h3")]
            TransportStreamProj::H3 { inner, .. } => {
                inner.poll_close(cx).map_err(sockudo_to_ws_error)
            },
            #[cfg(not(feature = "h3"))]
            TransportStreamProj::H3 { inner, .. } => inner.poll_close(cx),
            TransportStreamProj::Xhttp { inner, .. } => inner.poll_close(cx),
        }
    }
}
