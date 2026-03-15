use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use h3::client::{RequestStream as H3RequestStream, SendRequest as H3SendRequest};
use http::{Method, Request, Uri, Version};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pin_project_lite::pin_project;
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use sockudo_ws::{
    Config as SockudoConfig, Http3 as SockudoHttp3, Message as SockudoMessage,
    Stream as SockudoTransportStream, WebSocketStream as SockudoWebSocketStream,
    error::CloseReason as SockudoCloseReason,
};
use once_cell::sync::OnceCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::net::lookup_host;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Utf8Bytes, coding::CloseCode};
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async_tls};
use tracing::{debug, error, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::crypto::{
    SHADOWSOCKS_MAX_PAYLOAD, SHADOWSOCKS_TAG_LEN, decrypt, decrypt_udp_packet, derive_subkey,
    encrypt, encrypt_udp_packet, increment_nonce,
};
use crate::metrics::{
    add_transport_connects_active, add_upstream_transports_active, record_transport_connect,
    record_upstream_transport,
};
use crate::types::{CipherKind, WsTransportMode};

type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type RawH2WsStream = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;
type RawH3WsStream = SockudoWebSocketStream<SockudoTransportStream<SockudoHttp3>>;

pin_project! {
    struct H2WsStream {
        #[pin]
        inner: RawH2WsStream,
        driver_task: AbortOnDrop,
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

pin_project! {
    struct H3WsStream {
        #[pin]
        inner: RawH3WsStream,
        endpoint: quinn::Endpoint,
        // Kept alive to prevent the h3 driver from initiating graceful shutdown
        // (H3_NO_ERROR) prematurely. The h3 layer treats the last SendRequest
        // being dropped as a signal that no more requests will be made and may
        // close the connection before the single WebSocket stream is used.
        // Must be declared before `_connection` so it is dropped first: the h3
        // layer needs to see the SendRequest gone before the QUIC connection
        // closes, otherwise the server may receive an abrupt APPLICATION_CLOSE
        // before the proper h3 shutdown sequence completes.
        _send_request: H3SendRequest<h3_quinn::OpenStreams, Bytes>,
        _connection: H3ConnectionGuard,
        driver_task: AbortOnDrop,
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sends QUIC `CONNECTION_CLOSE` when dropped so the server is notified
/// immediately rather than waiting for its idle timeout to fire.
struct H3ConnectionGuard(quinn::Connection);

impl Drop for H3ConnectionGuard {
    fn drop(&mut self) {
        // H3_NO_ERROR = 0x100 per RFC 9114 §8.1. Using 0 is not a valid H3
        // application error code and causes some servers to respond with
        // H3_INTERNAL_ERROR, triggering a reconnect storm under load.
        self.0.close(0x100u32.into(), b"websocket stream closed");
    }
}

static H3_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

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

static H3_QUIC_CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();

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

fn get_or_init_shared_h3_endpoint(bind_addr: SocketAddr) -> Result<quinn::Endpoint> {
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

struct TransportConnectGuard {
    source: &'static str,
    mode: &'static str,
    finished: bool,
}

impl TransportConnectGuard {
    fn new(source: &'static str, mode: &'static str) -> Self {
        add_transport_connects_active(source, mode, 1);
        record_transport_connect(source, mode, "started");
        Self {
            source,
            mode,
            finished: false,
        }
    }

    fn finish(&mut self, result: &'static str) {
        if !self.finished {
            self.finished = true;
            record_transport_connect(self.source, self.mode, result);
        }
    }
}

impl Drop for TransportConnectGuard {
    fn drop(&mut self) {
        if !self.finished {
            record_transport_connect(self.source, self.mode, "error");
        }
        add_transport_connects_active(self.source, self.mode, -1);
    }
}

pub(crate) struct UpstreamTransportGuard {
    source: &'static str,
    protocol: &'static str,
}

impl UpstreamTransportGuard {
    pub(crate) fn new(source: &'static str, protocol: &'static str) -> Arc<Self> {
        add_upstream_transports_active(source, protocol, 1);
        record_upstream_transport(source, protocol, "opened");
        Arc::new(Self { source, protocol })
    }
}

impl Drop for UpstreamTransportGuard {
    fn drop(&mut self) {
        record_upstream_transport(self.source, self.protocol, "closed");
        add_upstream_transports_active(self.source, self.protocol, -1);
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
            AnyWsStreamProj::H3 { inner } => inner.poll_ready(cx).map_err(sockudo_to_ws_error),
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.start_send(item),
            AnyWsStreamProj::H2 { inner } => inner.start_send(item),
            AnyWsStreamProj::H3 { inner } => inner
                .start_send(tungstenite_to_sockudo_message(item)?)
                .map_err(sockudo_to_ws_error),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_flush(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_flush(cx),
            AnyWsStreamProj::H3 { inner } => inner.poll_flush(cx).map_err(sockudo_to_ws_error),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.project() {
            AnyWsStreamProj::Http1 { inner } => inner.poll_close(cx),
            AnyWsStreamProj::H2 { inner } => inner.poll_close(cx),
            AnyWsStreamProj::H3 { inner } => inner.poll_close(cx).map_err(sockudo_to_ws_error),
        }
    }
}

type WsSink = SplitSink<AnyWsStream, Message>;
type WsStream = SplitStream<AnyWsStream>;

pub struct TcpShadowsocksWriter {
    data_tx: Option<mpsc::Sender<Message>>,
    _writer_task: AbortOnDrop,
    cipher: CipherKind,
    key: Vec<u8>,
    nonce: [u8; 12],
    pending_salt: Option<Vec<u8>>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub struct TcpShadowsocksReader {
    stream: WsStream,
    ctrl_tx: mpsc::Sender<Message>,
    cipher: CipherKind,
    master_key: Vec<u8>,
    key: Option<Vec<u8>>,
    nonce: [u8; 12],
    buffer: Vec<u8>,
    _lifetime: Arc<UpstreamTransportGuard>,
    /// `true` when the last read ended with a clean WebSocket close (Close
    /// frame or EOF).  `false` means the stream was interrupted by a transport
    /// error (e.g. QUIC APPLICATION_CLOSE / H3_INTERNAL_ERROR).  Callers can
    /// use this to decide whether to report a runtime uplink failure.
    pub closed_cleanly: bool,
}

pub struct UdpWsTransport {
    data_tx: mpsc::Sender<Message>,
    ctrl_tx: mpsc::Sender<Message>,
    stream: Mutex<WsStream>,
    _writer_task: AbortOnDrop,
    cipher: CipherKind,
    master_key: Vec<u8>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub async fn connect_websocket(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
) -> Result<AnyWsStream> {
    connect_websocket_with_source(url, mode, fwmark, "direct").await
}

pub async fn connect_websocket_with_source(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<AnyWsStream> {
    match mode {
        WsTransportMode::Http1 => {
            let ws_stream = connect_websocket_http1(url, fwmark, source).await?;
            debug!(url = %url, selected_mode = "http1", "websocket transport connected");
            Ok(AnyWsStream::Http1 { inner: ws_stream })
        }
        WsTransportMode::H2 => match connect_websocket_h2(url, fwmark, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h2", "websocket transport connected");
                Ok(stream)
            }
            Err(h2_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h2_error:#}"),
                    fallback = "http1",
                    "h2 websocket connect failed, falling back"
                );
                let ws_stream = connect_websocket_http1(url, fwmark, source).await?;
                debug!(url = %url, selected_mode = "http1", requested_mode = "h2", "websocket transport connected");
                Ok(AnyWsStream::Http1 { inner: ws_stream })
            }
        },
        WsTransportMode::H3 => match connect_websocket_h3(url, fwmark, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h3", "websocket transport connected");
                Ok(stream)
            }
            Err(h3_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h3_error:#}"),
                    fallback = "h2",
                    "h3 websocket connect failed, falling back"
                );
                match connect_websocket_h2(url, fwmark, source).await {
                    Ok(stream) => {
                        debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                        Ok(stream)
                    }
                    Err(h2_error) => {
                        warn!(
                            url = %url,
                            error = %format!("{h2_error:#}"),
                            fallback = "http1",
                            "h2 websocket connect failed after h3 fallback, falling back"
                        );
                        let ws_stream = connect_websocket_http1(url, fwmark, source).await?;
                        debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                        Ok(AnyWsStream::Http1 { inner: ws_stream })
                    }
                }
            }
        },
    }
}

impl TcpShadowsocksWriter {
    /// Connects the TCP shadowsocks writer.  Returns `(writer, ctrl_tx)` where
    /// `ctrl_tx` must be passed to the paired `TcpShadowsocksReader` so that
    /// Pong responses are sent through the priority channel in the writer task.
    pub(crate) async fn connect(
        sink: WsSink,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<(Self, mpsc::Sender<Message>)> {
        let mut salt = vec![0u8; cipher.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);

        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
        let writer_task = tokio::spawn(async move {
            let mut ws_sink = sink;
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = ctrl_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                            None => ctrl_open = false,
                        },
                        msg = data_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                            None => { let _ = ws_sink.close().await; return; }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(m) => {
                            if ws_sink.send(m).await.is_err() { return; }
                        }
                        None => { let _ = ws_sink.close().await; return; }
                    }
                }
            }
        });

        Ok((
            Self {
                data_tx: Some(data_tx),
                _writer_task: AbortOnDrop(writer_task),
                cipher,
                key: derive_subkey(cipher, master_key, &salt)?,
                nonce: [0u8; 12],
                pending_salt: Some(salt),
                _lifetime: lifetime,
            },
            ctrl_tx,
        ))
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > SHADOWSOCKS_MAX_PAYLOAD {
            bail!("payload too large: {}", payload.len());
        }

        let len = (payload.len() as u16).to_be_bytes();
        let encrypted_len = encrypt(self.cipher, &self.key, &self.nonce, &len)?;
        increment_nonce(&mut self.nonce);

        let encrypted_payload = encrypt(self.cipher, &self.key, &self.nonce, payload)?;
        increment_nonce(&mut self.nonce);

        let pending_salt_len = self.pending_salt.as_ref().map_or(0, Vec::len);
        let mut frame =
            Vec::with_capacity(pending_salt_len + encrypted_len.len() + encrypted_payload.len());
        if let Some(salt) = self.pending_salt.take() {
            frame.extend_from_slice(&salt);
        }
        frame.extend_from_slice(&encrypted_len);
        frame.extend_from_slice(&encrypted_payload);

        self.data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?
            .send(Message::Binary(frame.into()))
            .await
            .context("failed to send encrypted frame")?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        // Drop the sender; the writer task will flush and close the underlying sink.
        drop(self.data_tx.take());
        Ok(())
    }
}

impl TcpShadowsocksReader {
    pub(crate) fn new(
        stream: WsStream,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
        ctrl_tx: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            stream,
            ctrl_tx,
            cipher,
            master_key: master_key.to_vec(),
            key: None,
            nonce: [0u8; 12],
            buffer: Vec::new(),
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        if self.key.is_none() {
            let salt = self.read_exact_from_ws(self.cipher.salt_len()).await?;
            self.key = Some(derive_subkey(self.cipher, &self.master_key, &salt)?);
        }
        let key = self
            .key
            .clone()
            .ok_or_else(|| anyhow!("missing derived key"))?;

        let encrypted_len = self.read_exact_from_ws(2 + SHADOWSOCKS_TAG_LEN).await?;
        let len = decrypt(self.cipher, &key, &self.nonce, &encrypted_len)?;
        increment_nonce(&mut self.nonce);

        if len.len() != 2 {
            bail!("invalid decrypted length block");
        }
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if payload_len > SHADOWSOCKS_MAX_PAYLOAD {
            bail!("payload length exceeds limit: {payload_len}");
        }

        let encrypted_payload = self
            .read_exact_from_ws(payload_len + SHADOWSOCKS_TAG_LEN)
            .await?;
        let payload = decrypt(self.cipher, &key, &self.nonce, &encrypted_payload)?;
        increment_nonce(&mut self.nonce);
        Ok(payload)
    }

    async fn read_exact_from_ws(&mut self, len: usize) -> Result<Vec<u8>> {
        while self.buffer.len() < len {
            let next = match self.stream.next().await {
                None => {
                    self.closed_cleanly = true;
                    bail!("websocket closed");
                }
                Some(Ok(msg)) => msg,
                Some(Err(e)) => return Err(anyhow!("websocket read failed: {e}")),
            };

            match next {
                Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
                Message::Close(_) => {
                    self.closed_cleanly = true;
                    bail!("websocket closed");
                }
                Message::Ping(payload) => {
                    // Send Pong through the priority channel so it is not
                    // delayed behind queued binary data frames.
                    let _ = self.ctrl_tx.try_send(Message::Pong(payload));
                }
                Message::Pong(_) => {}
                Message::Text(_) => bail!("unexpected text websocket frame"),
                Message::Frame(_) => {}
            }
        }

        // split_off(len) returns buffer[len..], leaving buffer[..len] in place;
        // swap so we return the head and retain the tail.
        let tail = self.buffer.split_off(len);
        Ok(std::mem::replace(&mut self.buffer, tail))
    }
}

impl UdpWsTransport {
    pub(crate) fn from_websocket(
        ws_stream: AnyWsStream,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
    ) -> Self {
        let (sink, stream) = ws_stream.split();
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
        let writer_task = tokio::spawn(async move {
            let mut ws_sink = sink;
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = ctrl_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                            None => ctrl_open = false,
                        },
                        msg = data_rx.recv() => match msg {
                            Some(Message::Close(_)) | None => {
                                let _ = ws_sink.close().await;
                                return;
                            }
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(Message::Close(_)) | None => {
                            let _ = ws_sink.close().await;
                            return;
                        }
                        Some(m) => {
                            if ws_sink.send(m).await.is_err() { return; }
                        }
                    }
                }
            }
        });
        Self {
            data_tx,
            ctrl_tx,
            stream: Mutex::new(stream),
            _writer_task: AbortOnDrop(writer_task),
            cipher,
            master_key: cipher.derive_master_key(password),
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        }
    }

    pub async fn connect(
        url: &Url,
        mode: WsTransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        source: &'static str,
    ) -> Result<Self> {
        let ws_stream = connect_websocket_with_source(url, mode, fwmark, source)
            .await
            .with_context(|| format!("failed to connect to {}", url))?;
        Ok(Self::from_websocket(ws_stream, cipher, password, source))
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        let packet = encrypt_udp_packet(self.cipher, &self.master_key, payload)?;
        self.data_tx
            .send(Message::Binary(packet.into()))
            .await
            .context("failed to send UDP websocket frame")?;
        Ok(())
    }

    pub async fn read_packet(&self) -> Result<Vec<u8>> {
        let mut stream = self.stream.lock().await;
        loop {
            let message = stream
                .next()
                .await
                .ok_or_else(|| anyhow!("websocket closed"))?
                .context("websocket read failed")?;
            match message {
                Message::Binary(bytes) => {
                    return decrypt_udp_packet(self.cipher, &self.master_key, &bytes);
                }
                Message::Close(_) => bail!("websocket closed"),
                Message::Ping(payload) => {
                    // Send Pong through the priority channel so it is not
                    // delayed behind queued binary data frames.
                    let _ = self.ctrl_tx.try_send(Message::Pong(payload));
                }
                Message::Pong(_) => {}
                Message::Text(_) => bail!("unexpected text websocket frame"),
                Message::Frame(_) => {}
            }
        }
    }

    pub async fn close(&self) -> Result<()> {
        // Signal the writer task to flush pending frames and close the sink.
        let _ = self.data_tx.send(Message::Close(None)).await;
        Ok(())
    }
}

async fn connect_websocket_http1(
    url: &Url,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<H1WsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "http1");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr = lookup_host((host, port))
        .await
        .context("failed to resolve websocket host")?
        .next()
        .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {host}:{port}"))?;
    let tcp = connect_tcp_socket(server_addr, fwmark).await?;
    let (ws_stream, _) = client_async_tls(url.as_str(), tcp)
        .await
        .context("HTTP/1 websocket handshake failed")?;
    connect_guard.finish("success");
    Ok(ws_stream)
}

async fn connect_websocket_h2(
    url: &Url,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<AnyWsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr = lookup_host((host, port))
        .await
        .context("failed to resolve h2 websocket host")?
        .next()
        .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {host}:{port}"))?;
    let target_uri = websocket_target_uri(url)?;

    let io = match url.scheme() {
        "ws" => H2Io::Plain {
            inner: connect_tcp_socket(server_addr, fwmark).await?,
        },
        "wss" => H2Io::Tls {
            inner: connect_tls_h2(server_addr, host, fwmark).await?,
        },
        scheme => bail!("unsupported scheme for h2 websocket: {scheme}"),
    };

    let (mut send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(20))
        .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
        .await
        .context("HTTP/2 handshake failed")?;

    let driver_task = AbortOnDrop(tokio::spawn(async move {
        if let Err(err) = conn.await {
            error!("h2 connection error: {err}");
        }
    }));

    let req: Request<Empty<Bytes>> = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(target_uri)
        .extension(Protocol::from_static("websocket"))
        .header("sec-websocket-version", "13")
        .body(Empty::new())
        .expect("request builder never fails");

    let mut response: http::Response<hyper::body::Incoming> =
        send_request.send_request(req).await?;
    if !response.status().is_success() {
        bail!(
            "HTTP/2 websocket CONNECT failed with status {}",
            response.status()
        );
    }

    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .context("failed to upgrade HTTP/2 websocket stream")?;
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    connect_guard.finish("success");
    Ok(AnyWsStream::H2 {
        inner: H2WsStream {
            inner: ws,
            driver_task,
        },
    })
}

async fn connect_websocket_h3(
    url: &Url,
    fwmark: Option<u32>,
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
    let mut server_addrs = lookup_host((host, port))
        .await
        .context("failed to resolve h3 websocket host")?
        .collect::<Vec<_>>();
    if server_addrs.is_empty() {
        bail!("DNS resolution returned no addresses for {host}:{port}");
    }
    server_addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });

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

async fn connect_tls_h2(
    addr: SocketAddr,
    host: &str,
    fwmark: Option<u32>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;

    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = TlsConnector::from(std::sync::Arc::new(tls_config));
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

async fn connect_tcp_socket(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )
    .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    socket
        .connect(&addr.into())
        .with_context(|| format!("failed to connect TCP socket to {addr}"))?;
    socket
        .set_nonblocking(true)
        .context("failed to set TCP socket nonblocking")?;
    TcpStream::from_std(socket.into()).context("failed to adopt TCP socket into tokio")
}

fn bind_udp_socket(bind_addr: SocketAddr, fwmark: Option<u32>) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )
    .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    apply_fwmark(&socket, fwmark)?;
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?;
    Ok(socket.into())
}

fn apply_fwmark(socket: &Socket, fwmark: Option<u32>) -> Result<()> {
    let Some(mark) = fwmark else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let value = mark as libc::c_uint;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to apply SO_MARK={mark}"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _mark = mark;
        let _ = socket;
        bail!("fwmark is only supported on Linux")
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

fn websocket_target_uri(url: &Url) -> Result<String> {
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

fn websocket_h3_target_uri(host: &str, port: u16, path: &str) -> Result<Uri> {
    Uri::builder()
        .scheme("https")
        .authority(format_authority(host, Some(port)))
        .path_and_query(path)
        .build()
        .context("failed to build HTTP/3 websocket target URI")
}

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

fn bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn sockudo_to_tungstenite_message(message: SockudoMessage) -> Message {
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

fn tungstenite_to_sockudo_message(message: Message) -> Result<SockudoMessage, WsError> {
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

fn sockudo_close_to_tungstenite(reason: SockudoCloseReason) -> CloseFrame {
    CloseFrame {
        code: CloseCode::from(reason.code),
        reason: Utf8Bytes::from(reason.reason),
    }
}

fn tungstenite_close_to_sockudo(frame: CloseFrame) -> SockudoCloseReason {
    SockudoCloseReason::new(u16::from(frame.code), frame.reason.to_string())
}

fn sockudo_to_ws_error(error: sockudo_ws::Error) -> WsError {
    WsError::Io(std::io::Error::other(error.to_string()))
}

pin_project! {
    #[project = H2IoProj]
    enum H2Io {
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
