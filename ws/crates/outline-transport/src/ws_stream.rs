use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

#[cfg(feature = "h3")]
use crate::h3::{
    H3WsStream, sockudo_to_tungstenite_message, sockudo_to_ws_error, tungstenite_to_sockudo_message,
};

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
/// direction) before [`WsTransportStream::is_connection_alive`] starts
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
// stub so that WsTransportStream::H3 remains a valid enum variant. The variant is
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
    #[project = WsTransportStreamProj]
    pub enum WsTransportStream {
        Http1 { #[pin] inner: H1WsStream, activity: H1Activity },
        H2 { #[pin] inner: H2WsStream },
        H3 { #[pin] inner: H3WsStream },
    }
}

impl WsTransportStream {
    /// Wrap a raw HTTP/1 WebSocket stream, initialising activity tracking.
    pub fn new_http1(inner: H1WsStream) -> Self {
        let activity = H1Activity::new();
        // Mark the moment of birth as activity so a freshly-dialed stream is
        // not immediately reported stale before the first frame arrives.
        activity.touch();
        WsTransportStream::Http1 { inner, activity }
    }

    /// Returns `true` when the underlying shared connection (H2 / H3) is still
    /// usable.  For HTTP/1 — which has no shared driver — returns `true` while
    /// the stream has seen any frame (data, ping, pong, close) within the last
    /// [`H1_STALENESS_THRESHOLD`], and `false` once that quiet period elapses.
    /// Used by the standby pool to discard zombie transports at acquisition
    /// time instead of handing them to a session that then hangs on the
    /// 5-minute idle watcher.
    pub fn is_connection_alive(&self) -> bool {
        match self {
            WsTransportStream::Http1 { activity, .. } => activity.is_fresh(H1_STALENESS_THRESHOLD),
            WsTransportStream::H2 { inner } => inner.is_connection_alive(),
            #[cfg(feature = "h3")]
            WsTransportStream::H3 { inner } => inner.is_connection_alive(),
            #[cfg(not(feature = "h3"))]
            WsTransportStream::H3 { .. } => true,
        }
    }

    /// Returns `(conn_id, mode)` of the underlying shared multiplex connection,
    /// or `None` for Http1 streams which are 1:1 with their TCP socket.  Used by
    /// session diagnostics to correlate burst EOFs against a single shared H2/H3
    /// connection's lifecycle.
    pub fn shared_connection_info(&self) -> Option<(u64, &'static str)> {
        match self {
            WsTransportStream::Http1 { .. } => None,
            WsTransportStream::H2 { inner } => Some(inner.shared_connection_info()),
            #[cfg(feature = "h3")]
            WsTransportStream::H3 { inner } => Some(inner.shared_connection_info()),
            #[cfg(not(feature = "h3"))]
            WsTransportStream::H3 { .. } => None,
        }
    }
}

impl Stream for WsTransportStream {
    type Item = Result<Message, WsError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner, activity } => {
                let poll = inner.poll_next(cx);
                if let std::task::Poll::Ready(Some(_)) = &poll {
                    activity.touch();
                }
                poll
            },
            WsTransportStreamProj::H2 { inner } => inner.poll_next(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => match inner.poll_next(cx) {
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
            WsTransportStreamProj::H3 { inner } => inner.poll_next(cx),
        }
    }
}

impl Sink<Message> for WsTransportStream {
    type Error = WsError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner, .. } => inner.poll_ready(cx),
            WsTransportStreamProj::H2 { inner } => inner.poll_ready(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner.poll_ready(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.poll_ready(cx),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner, activity } => {
                let result = inner.start_send(item);
                if result.is_ok() {
                    activity.touch();
                }
                result
            },
            WsTransportStreamProj::H2 { inner } => inner.start_send(item),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner
                .start_send(tungstenite_to_sockudo_message(item)?)
                .map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.start_send(item),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner, .. } => inner.poll_flush(cx),
            WsTransportStreamProj::H2 { inner } => inner.poll_flush(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner.poll_flush(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner, .. } => inner.poll_close(cx),
            WsTransportStreamProj::H2 { inner } => inner.poll_close(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner.poll_close(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.poll_close(cx),
        }
    }
}
