// HTTP/3 WebSocket transport — only compiled when the `h3` feature is enabled.
// All H3-specific types, statics, and functions live here so that transport.rs
// is free of scattered #[cfg(feature = "h3")] annotations.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::{Sink, Stream};
use h3::client::{RequestStream as H3RequestStream, SendRequest as H3SendRequest};
use http::{Method, Request, Uri};
use once_cell::sync::OnceCell;
use pin_project_lite::pin_project;
use sockudo_ws::{
    Config as SockudoConfig, Http3 as SockudoHttp3, Message as SockudoMessage,
    Stream as SockudoTransportStream, WebSocketStream as SockudoWebSocketStream,
    error::CloseReason as SockudoCloseReason,
};
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Utf8Bytes, coding::CloseCode};
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, error};
use url::Url;

use crate::transport::{
    AbortOnDrop, AnyWsStream, TransportConnectGuard, bind_addr_for, bind_udp_socket,
    format_authority, resolve_host_with_preference, websocket_path,
};

type RawH3WsStream = SockudoWebSocketStream<SockudoTransportStream<SockudoHttp3>>;

// ── H3WsStream ────────────────────────────────────────────────────────────────

pin_project! {
    pub(crate) struct H3WsStream {
        #[pin]
        inner: RawH3WsStream,
        pub(crate) endpoint: quinn::Endpoint,
        // Kept alive to prevent the h3 driver from initiating graceful shutdown
        // (H3_NO_ERROR) prematurely. The h3 layer treats the last SendRequest
        // being dropped as a signal that no more requests will be made and may
        // close the connection before the single WebSocket stream is used.
        // Must be declared before `_connection` so it is dropped first: the h3
        // layer needs to see the SendRequest gone before the QUIC connection
        // closes, otherwise the server may receive an abrupt APPLICATION_CLOSE
        // before the proper h3 shutdown sequence completes.
        pub(crate) _send_request: H3SendRequest<h3_quinn::OpenStreams, Bytes>,
        pub(crate) _connection: H3ConnectionGuard,
        pub(crate) driver_task: AbortOnDrop,
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
pub(crate) struct H3ConnectionGuard(pub(crate) quinn::Connection);

impl Drop for H3ConnectionGuard {
    fn drop(&mut self) {
        // H3_NO_ERROR = 0x100 per RFC 9114 §8.1. Using 0 is not a valid H3
        // application error code and causes some servers to respond with
        // H3_INTERNAL_ERROR, triggering a reconnect storm under load.
        self.0.close(0x100u32.into(), b"websocket stream closed");
    }
}

// ── TLS / QUIC client configs (initialised once) ─────────────────────────────

use rustls::{ClientConfig, RootCertStore};
use std::sync::OnceLock;
use webpki_roots::TLS_SERVER_ROOTS;

static H3_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
static H3_QUIC_CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();

/// Returns a shared, lazily-initialised TLS config for H3 connections.
/// Building the config (parsing root certificates) is expensive; doing it once
/// avoids the cost on every connection attempt and every warm-standby refill.
fn h3_client_tls_config() -> Arc<ClientConfig> {
    Arc::clone(H3_CLIENT_TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        Arc::new(config)
    }))
}

/// Returns a cloned QUIC client config built once from the cached TLS config.
fn h3_quic_client_config() -> quinn::ClientConfig {
    H3_QUIC_CLIENT_CONFIG
        .get_or_init(|| {
            let tls = h3_client_tls_config();
            let quic = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
                .expect("H3 TLS ALPN config is always QUIC-compatible");
            let mut config = quinn::ClientConfig::new(Arc::new(quic));
            let mut transport = quinn::TransportConfig::default();
            // Send QUIC PING frames so NAT mappings stay alive and the server
            // detects dead connections promptly.
            transport.keep_alive_interval(Some(Duration::from_secs(10)));
            transport.max_idle_timeout(Some(
                Duration::from_secs(120)
                    .try_into()
                    .expect("valid H3 QUIC client idle timeout"),
            ));
            config.transport_config(Arc::new(transport));
            config
        })
        .clone()
}

// One UDP socket per address family, shared across all H3 connections that do
// not require a per-socket fwmark. Sharing the endpoint eliminates the "N
// warm-standby connections = N UDP sockets" resource explosion.
static H3_CLIENT_ENDPOINT_V4: OnceCell<quinn::Endpoint> = OnceCell::new();
static H3_CLIENT_ENDPOINT_V6: OnceCell<quinn::Endpoint> = OnceCell::new();

fn get_or_init_shared_h3_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    let cell = if bind_addr.is_ipv4() {
        &H3_CLIENT_ENDPOINT_V4
    } else {
        &H3_CLIENT_ENDPOINT_V6
    };
    let endpoint = cell.get_or_try_init(|| {
        let socket = bind_udp_socket(bind_addr, None)?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind shared QUIC client endpoint on {bind_addr}"))
    })?;
    Ok(endpoint.clone())
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h3(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    if url.scheme() != "wss" {
        bail!("h3 websocket transport currently requires wss:// URLs");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addrs = resolve_host_with_preference(
        host,
        port,
        "failed to resolve h3 websocket host",
        ipv6_first,
    )
    .await?;
    if server_addrs.is_empty() {
        bail!("DNS resolution returned no addresses for {host}:{port}");
    }

    let path = websocket_path(url);
    let mut last_error = None;
    for server_addr in server_addrs {
        match connect_h3_quic(server_addr, host, &path, fwmark, source).await {
            Ok(ws) => return Ok(AnyWsStream::H3 { inner: ws }),
            Err(error) => last_error = Some(format!("{server_addr}: {error}")),
        }
    }

    Err(anyhow!(
        "failed to connect to any resolved h3 address for {host}:{port}: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn connect_h3_quic(
    server_addr: std::net::SocketAddr,
    server_name: &str,
    path: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<H3WsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h3");
    let bind_addr = bind_addr_for(server_addr);
    let client_config = h3_quic_client_config();

    // For fwmark connections the socket must be bound with the mark set before
    // connect, so each stream needs its own UDP socket and endpoint.  For all
    // other connections we reuse one shared endpoint per address family so that
    // N warm-standby streams share a single UDP socket rather than opening N.
    let endpoint = if fwmark.is_some() {
        let socket = bind_udp_socket(bind_addr, fwmark)?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind QUIC client endpoint on {bind_addr}"))?
    } else {
        get_or_init_shared_h3_endpoint(bind_addr)?
    };

    let connection = endpoint
        .connect_with(client_config, server_addr, server_name)
        .with_context(|| format!("failed to initiate QUIC connection to {server_addr}"))?
        .await
        .with_context(|| format!("QUIC handshake failed for {server_addr}"))?;
    let connection_handle = connection.clone();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .context("HTTP/3 handshake failed")?;

    let driver_task = AbortOnDrop(tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        let err_text = err.to_string();
        if is_expected_h3_close(&err_text) {
            debug!("h3 connection closed: {err_text}");
        } else {
            error!("h3 connection error: {err_text}");
        }
    }));

    let request: Request<()> = Request::builder()
        .method(Method::CONNECT)
        .uri(websocket_h3_target_uri(
            server_name,
            server_addr.port(),
            path,
        )?)
        .extension(h3::ext::Protocol::WEBSOCKET)
        .header("sec-websocket-version", "13")
        .body(())
        .expect("request builder never fails");

    let mut stream: H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> = send_request
        .send_request(request)
        .await
        .context("failed to send HTTP/3 websocket CONNECT request")?;

    let response = stream
        .recv_response()
        .await
        .context("failed to receive HTTP/3 websocket response")?;
    if !response.status().is_success() {
        bail!(
            "HTTP/3 websocket CONNECT failed with status {}",
            response.status()
        );
    }

    let h3_stream = SockudoTransportStream::<SockudoHttp3>::from_h3_client(stream);
    connect_guard.finish("success");
    Ok(H3WsStream {
        inner: SockudoWebSocketStream::from_raw(
            h3_stream,
            sockudo_ws::Role::Client,
            SockudoConfig::builder().http3_idle_timeout(90_000).build(),
        ),
        endpoint,
        _connection: H3ConnectionGuard(connection_handle),
        _send_request: send_request,
        driver_task,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_expected_h3_close(err: &str) -> bool {
    err.contains("H3_NO_ERROR")
        || err.contains("Connection closed by client")
        || err.contains("connection closed by client")
        // H3 application-level closes from the server (e.g. H3_INTERNAL_ERROR
        // when the backend crashes under load). These are already reported as
        // runtime uplink failures via closed_cleanly=false in the flow reader;
        // logging them as ERROR here would just add noise.
        || err.contains("H3_INTERNAL_ERROR")
        || err.contains("H3_REQUEST_REJECTED")
        || err.contains("H3_CONNECT_ERROR")
        || err.contains("ApplicationClose")
}

fn websocket_h3_target_uri(host: &str, port: u16, path: &str) -> Result<Uri> {
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
        }
        SockudoMessage::Binary(bytes) => Message::Binary(bytes),
        SockudoMessage::Ping(bytes) => Message::Ping(bytes),
        SockudoMessage::Pong(bytes) => Message::Pong(bytes),
        SockudoMessage::Close(reason) => Message::Close(reason.map(sockudo_close_to_tungstenite)),
    }
}

pub(crate) fn tungstenite_to_sockudo_message(message: Message) -> Result<SockudoMessage, WsError> {
    match message {
        Message::Text(text) => Ok(SockudoMessage::Text(Bytes::copy_from_slice(
            text.as_bytes(),
        ))),
        Message::Binary(bytes) => Ok(SockudoMessage::Binary(bytes)),
        Message::Ping(bytes) => Ok(SockudoMessage::Ping(bytes)),
        Message::Pong(bytes) => Ok(SockudoMessage::Pong(bytes)),
        Message::Close(frame) => Ok(SockudoMessage::Close(
            frame.map(tungstenite_close_to_sockudo),
        )),
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
