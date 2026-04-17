// HTTP/2 WebSocket transport — stream adapter and URL helpers.
//
// Layout:
//   mod.rs  — H2WsStream adapter, websocket_target_uri, re-exports.
//   shared  — window-size statics, TLS config, H2Io async-IO adapter,
//              connect_tls_h2, shared-connection cache, connect / gc logic.

mod shared;

pub(super) use shared::{connect_websocket_h2, gc_shared_h2_connections};
pub use shared::init_h2_window_sizes;

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use futures_util::{Sink, Stream};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use url::Url;

use super::ws_stream::SharedConnectionHealth;

// ── websocket_target_uri ──────────────────────────────────────────────────────

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

fn websocket_path(url: &Url) -> String {
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

/// Build an HTTP/2 CONNECT target URI from a WebSocket URL.
/// `wss://` → `https://`, `ws://` → `http://`, with path and query preserved.
pub(super) fn websocket_h2_target_uri(url: &Url) -> Result<String> {
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => bail!("unsupported websocket scheme for h2 target URI: {other}"),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let mut uri = format!("{scheme}://{}", format_authority(host, url.port()));
    uri.push_str(&websocket_path(url));
    Ok(uri)
}

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
