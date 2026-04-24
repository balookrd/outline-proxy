// HTTP/2 WebSocket transport — stream adapter and re-exports.
//
// Layout:
//   mod.rs  — H2WsStream adapter, re-exports.
//   shared  — window-size statics, TLS config, H2Io async-IO adapter,
//              connect_tls_h2, H2Dialer, shared-connection cache, connect / gc logic.

mod shared;

pub(super) use shared::{connect_websocket_h2, gc_shared_h2_connections};
pub use shared::init_h2_window_sizes;

use std::sync::Arc;

use anyhow::Result;
use futures_util::{Sink, Stream};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};

use super::ws_stream::SharedConnectionHealth;

// ── H2WsStream ────────────────────────────────────────────────────────────────

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

    pub(super) fn is_connection_alive(&self) -> bool {
        self._shared_connection.is_open()
    }

    pub(super) fn shared_connection_info(&self) -> (u64, &'static str) {
        (
            self._shared_connection.conn_id(),
            self._shared_connection.mode(),
        )
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
