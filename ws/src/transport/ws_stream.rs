use futures_util::{Sink, Stream};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

#[cfg(feature = "h3")]
use crate::transport_h3::{
    H3WsStream, sockudo_to_tungstenite_message, sockudo_to_ws_error, tungstenite_to_sockudo_message,
};

/// Trait for checking whether the shared multiplexed connection (H2 or H3)
/// underlying a websocket stream is still usable. Implemented by
/// `SharedH2Connection` and `SharedH3Connection`.
pub(crate) trait SharedConnectionHealth: Send + Sync {
    fn is_open(&self) -> bool;
}

pub(super) type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type RawH2WsStream = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

pin_project! {
    pub(super) struct H2WsStream {
        #[pin]
        inner: RawH2WsStream,
        _shared_connection: Arc<dyn SharedConnectionHealth>,
    }
}

impl H2WsStream {
    pub(super) fn new_shared(
        inner: RawH2WsStream,
        shared_connection: Arc<dyn SharedConnectionHealth>,
    ) -> Self {
        Self {
            inner,
            _shared_connection: shared_connection,
        }
    }
}

impl Stream for H2WsStream {
    type Item = Result<Message, WsError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

impl Sink<Message> for H2WsStream {
    type Error = WsError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.project().inner.start_send(item)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

// When the h3 feature is disabled, provide a zero-size never-constructable
// stub so that AnyWsStream::H3 remains a valid enum variant. The variant is
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
    #[project = AnyWsStreamProj]
    pub enum AnyWsStream {
        Http1 { #[pin] inner: H1WsStream },
        H2 { #[pin] inner: H2WsStream },
        H3 { #[pin] inner: H3WsStream },
    }
}

impl AnyWsStream {
    /// Returns `true` when the underlying shared connection (H2 / H3) is still
    /// usable.  HTTP/1 streams always return `true` because they do not share a
    /// multiplexed connection.  Used by the standby pool to detect and discard
    /// websocket streams whose shared connection was marked broken (e.g. after
    /// an `open_websocket` timeout) — the 1ms peek alone cannot catch this
    /// because H2 keepalive may still succeed on the dying connection.
    pub fn is_connection_alive(&self) -> bool {
        match self {
            AnyWsStream::Http1 { .. } => true,
            AnyWsStream::H2 { inner } => inner._shared_connection.is_open(),
            #[cfg(feature = "h3")]
            AnyWsStream::H3 { inner } => inner.is_connection_alive(),
            #[cfg(not(feature = "h3"))]
            AnyWsStream::H3 { .. } => true,
        }
    }
}

impl Stream for AnyWsStream {
    type Item = Result<Message, WsError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_next(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_next(cx),
            #[cfg(feature = "h3")]
            AnyWsStreamProj::H3 { inner } => match inner.poll_next(cx) {
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
            AnyWsStreamProj::H3 { inner } => inner.poll_next(cx),
        }
    }
}

impl Sink<Message> for AnyWsStream {
    type Error = WsError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_ready(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_ready(cx),
            #[cfg(feature = "h3")]
            AnyWsStreamProj::H3 { inner } => inner.poll_ready(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            AnyWsStreamProj::H3 { inner } => inner.poll_ready(cx),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.start_send(item),
            AnyWsStreamProj::H2 { inner } => inner.start_send(item),
            #[cfg(feature = "h3")]
            AnyWsStreamProj::H3 { inner } => inner
                .start_send(tungstenite_to_sockudo_message(item)?)
                .map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            AnyWsStreamProj::H3 { inner } => inner.start_send(item),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_flush(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_flush(cx),
            #[cfg(feature = "h3")]
            AnyWsStreamProj::H3 { inner } => inner.poll_flush(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            AnyWsStreamProj::H3 { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_close(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_close(cx),
            #[cfg(feature = "h3")]
            AnyWsStreamProj::H3 { inner } => inner.poll_close(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            AnyWsStreamProj::H3 { inner } => inner.poll_close(cx),
        }
    }
}
