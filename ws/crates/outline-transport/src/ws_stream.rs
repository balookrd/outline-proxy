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
}

pub(super) type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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
        Http1 { #[pin] inner: H1WsStream },
        H2 { #[pin] inner: H2WsStream },
        H3 { #[pin] inner: H3WsStream },
    }
}

impl WsTransportStream {
    /// Returns `true` when the underlying shared connection (H2 / H3) is still
    /// usable.  HTTP/1 streams always return `true` because they do not share a
    /// multiplexed connection.  Used by the standby pool to detect and discard
    /// websocket streams whose shared connection was marked broken (e.g. after
    /// an `open_websocket` timeout) — the 1ms peek alone cannot catch this
    /// because H2 keepalive may still succeed on the dying connection.
    pub fn is_connection_alive(&self) -> bool {
        match self {
            WsTransportStream::Http1 { .. } => true,
            WsTransportStream::H2 { inner } => inner.is_connection_alive(),
            #[cfg(feature = "h3")]
            WsTransportStream::H3 { inner } => inner.is_connection_alive(),
            #[cfg(not(feature = "h3"))]
            WsTransportStream::H3 { .. } => true,
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
            WsTransportStreamProj::Http1 { inner } => inner.poll_next(cx),
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
            WsTransportStreamProj::Http1 { inner } => inner.poll_ready(cx),
            WsTransportStreamProj::H2 { inner } => inner.poll_ready(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner.poll_ready(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.poll_ready(cx),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project() {
            WsTransportStreamProj::Http1 { inner } => inner.start_send(item),
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
            WsTransportStreamProj::Http1 { inner } => inner.poll_flush(cx),
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
            WsTransportStreamProj::Http1 { inner } => inner.poll_close(cx),
            WsTransportStreamProj::H2 { inner } => inner.poll_close(cx),
            #[cfg(feature = "h3")]
            WsTransportStreamProj::H3 { inner } => inner.poll_close(cx).map_err(sockudo_to_ws_error),
            #[cfg(not(feature = "h3"))]
            WsTransportStreamProj::H3 { inner } => inner.poll_close(cx),
        }
    }
}
