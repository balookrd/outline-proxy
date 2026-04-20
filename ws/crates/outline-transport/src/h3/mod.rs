// HTTP/3 WebSocket transport — only compiled when the `h3` feature is enabled.
// All H3-specific types, statics, and functions live here so that transport.rs
// is free of scattered #[cfg(feature = "h3")] annotations.
//
// Layout:
//   mod.rs  — stream adapter types (`H3WsStream`, `H3ConnectionGuard`),
//              message-format conversion helpers, URI builder.
//   shared  — connection infrastructure: QUIC/TLS configs, shared endpoints,
//              per-key connect locks, shared-connection cache, connect / gc fns.

mod shared;

pub(crate) use shared::{connect_websocket_h3, gc_shared_h3_connections};

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::Uri;
use pin_project_lite::pin_project;
use sockudo_ws::{
    Http3 as SockudoHttp3, Message as SockudoMessage, Stream as SockudoTransportStream,
    WebSocketStream as SockudoWebSocketStream, error::CloseReason as SockudoCloseReason,
};
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Utf8Bytes, coding::CloseCode};
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};

use shared::SharedH3Connection;

type RawH3WsStream = SockudoWebSocketStream<SockudoTransportStream<SockudoHttp3>>;

// ── H3WsStream ────────────────────────────────────────────────────────────────

pin_project! {
    pub(crate) struct H3WsStream {
        #[pin]
        inner: RawH3WsStream,
        // Keep the shared connection alive for as long as this websocket stream
        // is active so the underlying HTTP/3 state does not get torn down.
        _shared_connection: Arc<SharedH3Connection>,
    }
}

impl H3WsStream {
    pub(crate) fn is_connection_alive(&self) -> bool {
        self._shared_connection.is_open()
    }

    pub(crate) fn shared_connection_info(&self) -> (u64, &'static str) {
        (self._shared_connection.id, "h3")
    }
}

impl Stream for H3WsStream {
    type Item = Result<SockudoMessage, sockudo_ws::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

impl Sink<SockudoMessage> for H3WsStream {
    type Error = sockudo_ws::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: SockudoMessage) -> Result<(), Self::Error> {
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

// ── H3ConnectionGuard ─────────────────────────────────────────────────────────

/// Sends QUIC `CONNECTION_CLOSE` when dropped so the server is notified
/// immediately rather than waiting for its idle timeout to fire.
pub(super) struct H3ConnectionGuard(pub(super) quinn::Connection);

impl Drop for H3ConnectionGuard {
    fn drop(&mut self) {
        // H3_NO_ERROR = 0x100 per RFC 9114 §8.1. Using 0 is not a valid H3
        // application error code and causes some servers to respond with
        // H3_INTERNAL_ERROR, triggering a reconnect storm under load.
        self.0.close(0x100u32.into(), b"websocket stream closed");
    }
}

// ── URL utilities (h3-local) ──────────────────────────────────────────────────

fn format_authority(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

pub(super) fn websocket_path(url: &url::Url) -> String {
    let mut path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

// ── URI helper ────────────────────────────────────────────────────────────────

pub(super) fn websocket_h3_target_uri(host: &str, port: u16, path: &str) -> Result<Uri> {
    Uri::builder()
        .scheme("https")
        .authority(format_authority(host, Some(port)))
        .path_and_query(path)
        .build()
        .context("failed to build HTTP/3 websocket target URI")
}

// ── Message conversion (sockudo ↔ tungstenite) ────────────────────────────────

pub(crate) fn sockudo_to_tungstenite_message(message: SockudoMessage) -> Message {
    match message {
        SockudoMessage::Text(bytes) => {
            Message::Text(String::from_utf8_lossy(&bytes).into_owned().into())
        },
        SockudoMessage::Binary(bytes) => Message::Binary(bytes),
        SockudoMessage::Ping(bytes) => Message::Ping(bytes),
        SockudoMessage::Pong(bytes) => Message::Pong(bytes),
        SockudoMessage::Close(reason) => Message::Close(reason.map(sockudo_close_to_tungstenite)),
    }
}

pub(crate) fn tungstenite_to_sockudo_message(message: Message) -> Result<SockudoMessage, WsError> {
    match message {
        Message::Text(text) => Ok(SockudoMessage::Text(Bytes::copy_from_slice(text.as_bytes()))),
        Message::Binary(bytes) => Ok(SockudoMessage::Binary(bytes)),
        Message::Ping(bytes) => Ok(SockudoMessage::Ping(bytes)),
        Message::Pong(bytes) => Ok(SockudoMessage::Pong(bytes)),
        Message::Close(frame) => Ok(SockudoMessage::Close(frame.map(tungstenite_close_to_sockudo))),
        Message::Frame(_) => Err(WsError::Io(std::io::Error::other(
            "raw websocket frames are not supported by the h3 transport adapter",
        ))),
    }
}

pub(crate) fn sockudo_to_ws_error(error: sockudo_ws::Error) -> WsError {
    WsError::Io(std::io::Error::other(error.to_string()))
}

fn sockudo_close_to_tungstenite(reason: SockudoCloseReason) -> CloseFrame {
    CloseFrame {
        code: CloseCode::from(reason.code),
        reason: Utf8Bytes::from(reason.reason),
    }
}

fn tungstenite_close_to_sockudo(frame: CloseFrame) -> SockudoCloseReason {
    SockudoCloseReason::new(u16::from(frame.code), frame.reason.to_string())
}
