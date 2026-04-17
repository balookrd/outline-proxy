// HTTP/2 WebSocket transport — IO layer, TLS config, flow-control window
// sizes, and the H2WsStream adapter.
//
// Layout:
//   mod.rs  — TLS config, window-size statics, H2Io async-IO adapter,
//              connect_tls_h2, websocket_target_uri, H2WsStream.
//   shared  — shared-connection cache, connect / gc logic.

mod shared;

pub(super) use shared::{connect_websocket_h2, gc_shared_h2_connections};

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{Sink, Stream};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use super::connect_tcp_socket;
use super::ws_stream::SharedConnectionHealth;

// ── Window sizes ──────────────────────────────────────────────────────────────

// HTTP/2 flow-control window sizes. Defaults match the sizing used by
// sockudo-ws so the long-lived CONNECT stream carrying UDP datagrams does not
// stall on the small RFC default window under sustained downstream traffic.
// On memory-constrained routers these can be reduced via [h2] in config.toml.
static H2_INITIAL_STREAM_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static H2_INITIAL_CONNECTION_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();

/// Initialise H2 window sizes from config. Must be called before the first
/// outbound H2 connection is opened. Safe to call multiple times with the same
/// values; panics if called with different values after initialization.
pub fn init_h2_window_sizes(stream: u32, connection: u32) {
    H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| stream);
    H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| connection);
}

pub(super) fn h2_stream_window_size() -> u32 {
    *H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| 1024 * 1024)
}

pub(super) fn h2_connection_window_size() -> u32 {
    *H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| 2 * 1024 * 1024)
}

// ── TLS config ────────────────────────────────────────────────────────────────

static H2_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

fn h2_client_tls_config() -> Arc<ClientConfig> {
    Arc::clone(H2_CLIENT_TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }))
}

pub(super) async fn connect_tls_h2(
    addr: std::net::SocketAddr,
    host: &str,
    fwmark: Option<u32>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;
    let connector = TlsConnector::from(h2_client_tls_config());
    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS server name: {host}"))?
    };
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake for h2 websocket failed")
}

// ── H2Io ──────────────────────────────────────────────────────────────────────

pin_project! {
    #[project = H2IoProj]
    pub(super) enum H2Io {
        Plain { #[pin] inner: TcpStream },
        Tls { #[pin] inner: tokio_rustls::client::TlsStream<TcpStream> },
    }
}

impl tokio::io::AsyncRead for H2Io {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_read(cx, buf),
            H2IoProj::Tls { inner } => inner.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for H2Io {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_write(cx, buf),
            H2IoProj::Tls { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_flush(cx),
            H2IoProj::Tls { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_shutdown(cx),
            H2IoProj::Tls { inner } => inner.poll_shutdown(cx),
        }
    }
}

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
pub(super) fn websocket_target_uri(url: &Url) -> Result<String> {
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
