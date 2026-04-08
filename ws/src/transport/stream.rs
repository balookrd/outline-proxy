use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use hyper_util::rt::TokioIo;

#[cfg(feature = "h3")]
use crate::transport_h3::{
    H3WsStream, sockudo_to_tungstenite_message, sockudo_to_ws_error, tungstenite_to_sockudo_message,
};

use super::guards::AbortOnDrop;

pub(super) type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
pub(super) type RawH2WsStream = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

pin_project! {
    pub(super) struct H2WsStream {
        #[pin]
        pub(super) inner: RawH2WsStream,
        pub(super) driver_task: AbortOnDrop,
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
    pub(super) struct H3WsStream { _never: std::convert::Infallible }
}

#[cfg(not(feature = "h3"))]
impl Stream for H3WsStream {
    type Item = Result<Message, WsError>;
    fn poll_next(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
        -> std::task::Poll<Option<Self::Item>>
    {
        // SAFETY: Infallible can never be constructed, so this branch is unreachable.
        match *self.project()._never {}
    }
}

#[cfg(not(feature = "h3"))]
impl Sink<Message> for H3WsStream {
    type Error = WsError;
    fn poll_ready(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<(), Self::Error>>
    { match *self.project()._never {} }
    fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), Self::Error>
    { match *self.project()._never {} }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<(), Self::Error>>
    { match *self.project()._never {} }
    fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<(), Self::Error>>
    { match *self.project()._never {} }
}

pin_project! {
    #[project = AnyWsStreamProj]
    pub enum AnyWsStream {
        Http1 { #[pin] inner: H1WsStream },
        H2 { #[pin] inner: H2WsStream },
        H3 { #[pin] inner: H3WsStream },
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
                }
                std::task::Poll::Ready(Some(Err(error))) => {
                    std::task::Poll::Ready(Some(Err(sockudo_to_ws_error(error))))
                }
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

pub(super) type WsSink = SplitSink<AnyWsStream, Message>;
pub(super) type WsStream = SplitStream<AnyWsStream>;
