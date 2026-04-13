use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::{Method, Request, Version};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pin_project_lite::pin_project;
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{protocol::Message, Error as WsError};
use tokio_tungstenite::{client_async_tls, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(feature = "h3")]
use crate::transport_h3::{
    connect_websocket_h3, sockudo_to_tungstenite_message, sockudo_to_ws_error,
    tungstenite_to_sockudo_message, H3WsStream,
};

use crate::crypto::{
    decrypt, decrypt_udp_packet, decrypt_udp_packet_2022, derive_subkey, encrypt,
    encrypt_udp_packet, encrypt_udp_packet_2022, increment_nonce, validate_ss2022_timestamp,
    SHADOWSOCKS_MAX_PAYLOAD, SHADOWSOCKS_TAG_LEN,
};
use crate::dns_cache::DnsCache;
use crate::metrics::{
    add_transport_connects_active, add_upstream_transports_active, record_transport_connect,
    record_upstream_transport,
};
use crate::types::{CipherKind, ServerAddr, TargetAddr, WsTransportMode};

type H1WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type RawH2WsStream = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

const MAX_UDP_SOCKET_PACKET_SIZE: usize = 65_507;
const OVERSIZED_UDP_UPLINK_DROP_ERR: &str = "oversized UDP packet dropped before uplink send";
// HTTP/2 flow-control window sizes. Defaults match the sizing used by
// sockudo-ws so the long-lived CONNECT stream carrying UDP datagrams does not
// stall on the small RFC default window under sustained downstream traffic.
// On memory-constrained routers these can be reduced via [h2] in config.toml.
static H2_INITIAL_STREAM_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static H2_INITIAL_CONNECTION_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static UDP_RECV_BUF_BYTES: OnceLock<usize> = OnceLock::new();
static UDP_SEND_BUF_BYTES: OnceLock<usize> = OnceLock::new();
static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();

/// Initialise H2 window sizes from config. Must be called before the first
/// outbound H2 connection is opened. Safe to call multiple times with the same
/// values; panics if called with different values after initialization.
pub fn init_h2_window_sizes(stream: u32, connection: u32) {
    H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| stream);
    H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| connection);
}

/// Initialise UDP socket buffer overrides from config. When set, every UDP
/// socket created by `bind_udp_socket` will request the given buffer sizes
/// from the kernel via `SO_RCVBUF` / `SO_SNDBUF`. The kernel may silently
/// cap the value to `/proc/sys/net/core/rmem_max` (Linux). `None` leaves
/// the kernel default unchanged.
pub fn init_udp_socket_bufs(recv: Option<usize>, send: Option<usize>) {
    if let Some(v) = recv {
        UDP_RECV_BUF_BYTES.get_or_init(|| v);
    }
    if let Some(v) = send {
        UDP_SEND_BUF_BYTES.get_or_init(|| v);
    }
}

fn h2_stream_window_size() -> u32 {
    *H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| 1024 * 1024)
}

fn h2_connection_window_size() -> u32 {
    *H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| 2 * 1024 * 1024)
}

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

pub(crate) struct AbortOnDrop(pub(crate) JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl AbortOnDrop {
    fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }

    async fn finish(mut self) {
        let handle = std::mem::replace(&mut self.0, tokio::spawn(async {}));
        let _ = handle.await;
    }
}

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

pub(crate) struct TransportConnectGuard {
    source: &'static str,
    mode: &'static str,
    finished: bool,
}

impl TransportConnectGuard {
    pub(crate) fn new(source: &'static str, mode: &'static str) -> Self {
        add_transport_connects_active(source, mode, 1);
        record_transport_connect(source, mode, "started");
        Self { source, mode, finished: false }
    }

    pub(crate) fn finish(&mut self, result: &'static str) {
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

type WsSink = SplitSink<AnyWsStream, Message>;
type WsStream = SplitStream<AnyWsStream>;

enum TcpWriteTransport {
    Websocket {
        data_tx: Option<mpsc::Sender<Message>>,
        writer_task: Option<AbortOnDrop>,
    },
    Socket {
        writer: OwnedWriteHalf,
    },
}

enum TcpReadTransport {
    Websocket {
        stream: WsStream,
        ctrl_tx: mpsc::Sender<Message>,
    },
    Socket {
        reader: OwnedReadHalf,
    },
}

enum UdpTransport {
    Websocket {
        data_tx: mpsc::Sender<Message>,
        ctrl_tx: mpsc::Sender<Message>,
        stream: Mutex<WsStream>,
        _writer_task: AbortOnDrop,
        _keepalive_task: Option<AbortOnDrop>,
    },
    Socket {
        socket: UdpSocket,
    },
}

struct Ss2022TcpWriterState {
    request_salt: Vec<u8>,
    header_sent: bool,
}

struct Ss2022TcpReaderState {
    request_salt: Vec<u8>,
    response_header_read: bool,
}

struct Ss2022UdpState {
    client_session_id: u64,
    next_client_packet_id: u64,
    server_session_id: Option<u64>,
    last_server_packet_id: Option<u64>,
}

pub struct TcpShadowsocksWriter {
    transport: TcpWriteTransport,
    cipher: CipherKind,
    key: Vec<u8>,
    nonce: [u8; 12],
    pending_salt: Option<Vec<u8>>,
    ss2022: Option<Ss2022TcpWriterState>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub struct TcpShadowsocksReader {
    transport: TcpReadTransport,
    cipher: CipherKind,
    master_key: Vec<u8>,
    key: Option<Vec<u8>>,
    nonce: [u8; 12],
    buffer: Vec<u8>,
    ss2022: Option<Ss2022TcpReaderState>,
    _lifetime: Arc<UpstreamTransportGuard>,
    /// `true` when the last read ended with a clean WebSocket close (Close
    /// frame or EOF).  `false` means the stream was interrupted by a transport
    /// error (e.g. QUIC APPLICATION_CLOSE / H3_INTERNAL_ERROR).  Callers can
    /// use this to decide whether to report a runtime uplink failure.
    pub closed_cleanly: bool,
}

pub struct UdpWsTransport {
    transport: UdpTransport,
    cipher: CipherKind,
    master_key: Vec<u8>,
    ss2022: Option<Mutex<Ss2022UdpState>>,
    close_signal: watch::Sender<bool>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub async fn connect_websocket(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
) -> Result<AnyWsStream> {
    connect_websocket_with_source(url, mode, fwmark, ipv6_first, "direct").await
}

pub async fn connect_websocket_with_source(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    match mode {
        WsTransportMode::Http1 => {
            let ws_stream = connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
            debug!(url = %url, selected_mode = "http1", "websocket transport connected");
            Ok(AnyWsStream::Http1 { inner: ws_stream })
        },
        WsTransportMode::H2 => match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h2", "websocket transport connected");
                Ok(stream)
            },
            Err(h2_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h2_error:#}"),
                    fallback = "http1",
                    "h2 websocket connect failed, falling back"
                );
                let ws_stream = connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                debug!(url = %url, selected_mode = "http1", requested_mode = "h2", "websocket transport connected");
                Ok(AnyWsStream::Http1 { inner: ws_stream })
            },
        },
        #[cfg(feature = "h3")]
        WsTransportMode::H3 => match connect_websocket_h3(url, fwmark, ipv6_first, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h3", "websocket transport connected");
                Ok(stream)
            },
            Err(h3_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h3_error:#}"),
                    fallback = "h2",
                    "h3 websocket connect failed, falling back"
                );
                match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
                    Ok(stream) => {
                        debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                        Ok(stream)
                    },
                    Err(h2_error) => {
                        warn!(
                            url = %url,
                            error = %format!("{h2_error:#}"),
                            fallback = "http1",
                            "h2 websocket connect failed after h3 fallback, falling back"
                        );
                        let ws_stream =
                            connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                        debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                        Ok(AnyWsStream::Http1 { inner: ws_stream })
                    },
                }
            },
        },
        #[cfg(not(feature = "h3"))]
        WsTransportMode::H3 => {
            warn!(url = %url, "H3 requested but compiled without h3 feature, falling back to h2");
            match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
                Ok(stream) => {
                    debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                    Ok(stream)
                },
                Err(h2_error) => {
                    warn!(url = %url, error = %format!("{h2_error:#}"), fallback = "http1", "h2 websocket connect failed, falling back");
                    let ws_stream =
                        connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                    debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                    Ok(AnyWsStream::Http1 { inner: ws_stream })
                },
            }
        },
    }
}

pub async fn connect_shadowsocks_tcp_with_source(
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<TcpStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "tcp");
    let server_addr = resolve_server_addr(addr, ipv6_first).await?;
    let stream = connect_tcp_socket(server_addr, fwmark).await?;
    connect_guard.finish("success");
    Ok(stream)
}

pub async fn connect_shadowsocks_udp_with_source(
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<UdpSocket> {
    let mut connect_guard = TransportConnectGuard::new(source, "udp");
    let server_addr = resolve_server_addr(addr, ipv6_first).await?;
    let bind_addr = bind_addr_for(server_addr);
    let socket = if fwmark.is_some() {
        UdpSocket::from_std(bind_udp_socket(bind_addr, fwmark)?)
            .context("failed to adopt UDP socket into tokio")?
    } else {
        UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?
    };
    socket
        .connect(server_addr)
        .await
        .with_context(|| format!("failed to connect UDP socket to {server_addr}"))?;
    connect_guard.finish("success");
    Ok(socket)
}

pub fn is_dropped_oversized_udp_error(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains(OVERSIZED_UDP_UPLINK_DROP_ERR)
}

async fn resolve_server_addr(addr: &ServerAddr, ipv6_first: bool) -> Result<SocketAddr> {
    resolve_host_with_preference(
        addr.host(),
        addr.port(),
        &format!("failed to resolve {}", addr),
        ipv6_first,
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {}", addr))
}

pub(crate) async fn resolve_host_with_preference(
    host: &str,
    port: u16,
    context: &str,
    ipv6_first: bool,
) -> Result<Vec<SocketAddr>> {
    let cache = DNS_CACHE.get_or_init(DnsCache::new);
    let mut server_addrs = if let Some(addrs) = cache.get(host, port) {
        addrs
    } else {
        match lookup_host((host, port)).await {
            Ok(resolved) => {
                let addrs = resolved.collect::<Vec<_>>();
                cache.insert(host, port, addrs.clone());
                addrs
            },
            Err(err) => {
                if let Some(stale) = cache.get_stale(host, port) {
                    warn!(
                        host,
                        port,
                        error = %err,
                        "DNS lookup failed, using stale cached addresses"
                    );
                    stale
                } else {
                    return Err(err).with_context(|| context.to_string());
                }
            },
        }
    };
    server_addrs.sort_by_key(|addr| {
        if ipv6_first {
            if addr.is_ipv6() {
                0
            } else {
                1
            }
        } else if addr.is_ipv4() {
            0
        } else {
            1
        }
    });
    Ok(server_addrs)
}

fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

fn build_ss2022_request_header(target: &TargetAddr) -> Result<(Vec<u8>, Vec<u8>)> {
    let target = target.to_wire_bytes()?;
    let padding_len: u16 = 16;
    let mut fixed = Vec::with_capacity(11);
    fixed.push(0);
    fixed.extend_from_slice(&unix_timestamp_secs()?.to_be_bytes());
    fixed.extend_from_slice(
        &(target.len() as u16 + 2 + usize::from(padding_len) as u16).to_be_bytes(),
    );

    let mut variable = Vec::with_capacity(target.len() + 2 + usize::from(padding_len));
    variable.extend_from_slice(&target);
    variable.extend_from_slice(&padding_len.to_be_bytes());
    let mut padding = vec![0u8; usize::from(padding_len)];
    rand::thread_rng().fill_bytes(&mut padding);
    variable.extend_from_slice(&padding);
    Ok((fixed, variable))
}

fn parse_ss2022_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<usize> {
    let expected_len = 1 + 8 + cipher.salt_len() + 2;
    if plaintext.len() != expected_len {
        bail!("invalid ss2022 response header length: {}", plaintext.len());
    }
    if plaintext[0] != 1 {
        bail!("invalid ss2022 response header type: {}", plaintext[0]);
    }
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[1..9]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let request_salt_start = 9;
    let request_salt_end = request_salt_start + cipher.salt_len();
    if &plaintext[request_salt_start..request_salt_end] != request_salt {
        bail!("ss2022 response header request salt mismatch");
    }

    Ok(u16::from_be_bytes([plaintext[request_salt_end], plaintext[request_salt_end + 1]]) as usize)
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
                            if ws_sink.send(m).await.is_err() {
                                return;
                            }
                        },
                        None => {
                            let _ = ws_sink.close().await;
                            return;
                        },
                    }
                }
            }
        });

        let request_salt = salt.clone();
        Ok((
            Self {
                transport: TcpWriteTransport::Websocket {
                    data_tx: Some(data_tx),
                    writer_task: Some(AbortOnDrop::new(writer_task)),
                },
                cipher,
                key: derive_subkey(cipher, master_key, &salt)?,
                nonce: [0u8; 12],
                pending_salt: Some(salt),
                ss2022: cipher
                    .is_ss2022()
                    .then(|| Ss2022TcpWriterState { request_salt, header_sent: false }),
                _lifetime: lifetime,
            },
            ctrl_tx,
        ))
    }

    pub(crate) fn connect_socket(
        writer: OwnedWriteHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<Self> {
        let mut salt = vec![0u8; cipher.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        Ok(Self {
            transport: TcpWriteTransport::Socket { writer },
            cipher,
            key: derive_subkey(cipher, master_key, &salt)?,
            nonce: [0u8; 12],
            pending_salt: Some(salt.clone()),
            ss2022: cipher
                .is_ss2022()
                .then(|| Ss2022TcpWriterState { request_salt: salt, header_sent: false }),
            _lifetime: lifetime,
        })
    }

    pub fn request_salt(&self) -> Option<&[u8]> {
        self.ss2022.as_ref().map(|state| state.request_salt.as_slice())
    }

    pub fn supports_half_close(&self) -> bool {
        matches!(self.transport, TcpWriteTransport::Socket { .. })
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }

        if let Some(state) = &mut self.ss2022 {
            if !state.header_sent {
                let target = TargetAddr::from_wire_bytes(payload)
                    .context("invalid ss2022 initial target header")?
                    .0;
                let (fixed_header, variable_header) = build_ss2022_request_header(&target)?;
                let encrypted_fixed = encrypt(self.cipher, &self.key, &self.nonce, &fixed_header)?;
                increment_nonce(&mut self.nonce);
                let encrypted_variable =
                    encrypt(self.cipher, &self.key, &self.nonce, &variable_header)?;
                increment_nonce(&mut self.nonce);

                let pending_salt_len = self.pending_salt.as_ref().map_or(0, Vec::len);
                let mut frame = Vec::with_capacity(
                    pending_salt_len + encrypted_fixed.len() + encrypted_variable.len(),
                );
                if let Some(salt) = self.pending_salt.take() {
                    state.request_salt = salt.clone();
                    frame.extend_from_slice(&salt);
                }
                frame.extend_from_slice(&encrypted_fixed);
                frame.extend_from_slice(&encrypted_variable);
                state.header_sent = true;

                self.write_frame(frame).await?;
                return Ok(());
            }
        }

        for chunk in payload.chunks(self.cipher.max_payload_len()) {
            self.send_payload_frame(chunk).await?;
        }
        Ok(())
    }

    async fn send_payload_frame(&mut self, payload: &[u8]) -> Result<()> {
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

        self.write_frame(frame).await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        match &mut self.transport {
            TcpWriteTransport::Websocket { data_tx, writer_task } => {
                drop(data_tx.take());
                if let Some(task) = writer_task.take() {
                    task.finish().await;
                }
            },
            TcpWriteTransport::Socket { writer } => {
                writer.shutdown().await.context("socket shutdown failed")?;
            },
        }
        Ok(())
    }

    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        match &mut self.transport {
            TcpWriteTransport::Websocket { data_tx, .. } => data_tx
                .as_ref()
                .ok_or_else(|| anyhow!("writer already closed"))?
                .send(Message::Binary(frame.into()))
                .await
                .context("failed to send encrypted frame"),
            TcpWriteTransport::Socket { writer } => writer
                .write_all(&frame)
                .await
                .context("failed to write encrypted frame to socket"),
        }
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
            transport: TcpReadTransport::Websocket { stream, ctrl_tx },
            cipher,
            master_key: master_key.to_vec(),
            key: None,
            nonce: [0u8; 12],
            buffer: Vec::new(),
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub(crate) fn new_socket(
        reader: OwnedReadHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        Self {
            transport: TcpReadTransport::Socket { reader },
            cipher,
            master_key: master_key.to_vec(),
            key: None,
            nonce: [0u8; 12],
            buffer: Vec::new(),
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub(crate) fn with_request_salt(mut self, request_salt: Option<Vec<u8>>) -> Self {
        self.ss2022 = request_salt.map(|request_salt| Ss2022TcpReaderState {
            request_salt,
            response_header_read: false,
        });
        self
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        if self.key.is_none() {
            let salt = self.read_exact_from_ws(self.cipher.salt_len()).await?;
            self.key = Some(derive_subkey(self.cipher, &self.master_key, &salt)?);
        }
        let key = self.key.clone().ok_or_else(|| anyhow!("missing derived key"))?;

        let need_ss2022_response_header =
            self.ss2022.as_ref().is_some_and(|state| !state.response_header_read);
        if need_ss2022_response_header {
            let request_salt = self
                .ss2022
                .as_ref()
                .map(|state| state.request_salt.clone())
                .ok_or_else(|| anyhow!("missing ss2022 request salt"))?;
            {
                let header_len = 1 + 8 + self.cipher.salt_len() + 2 + SHADOWSOCKS_TAG_LEN;
                let encrypted_header = self.read_exact_from_ws(header_len).await?;
                let header = decrypt(self.cipher, &key, &self.nonce, &encrypted_header)?;
                increment_nonce(&mut self.nonce);
                let payload_len =
                    parse_ss2022_response_header(self.cipher, &request_salt, &header)?;
                let encrypted_payload =
                    self.read_exact_from_ws(payload_len + SHADOWSOCKS_TAG_LEN).await?;
                let payload = decrypt(self.cipher, &key, &self.nonce, &encrypted_payload)?;
                increment_nonce(&mut self.nonce);
                if let Some(state) = &mut self.ss2022 {
                    state.response_header_read = true;
                }
                if !payload.is_empty() {
                    return Ok(payload);
                }
                // Empty initial payload is valid in SS2022 (the server had no
                // target data to bundle yet).  Fall through to read the first
                // real data frame so callers never see an empty-payload return
                // that would be misinterpreted as EOF.
            }
        }

        let encrypted_len = self.read_exact_from_ws(2 + SHADOWSOCKS_TAG_LEN).await?;
        let len = decrypt(self.cipher, &key, &self.nonce, &encrypted_len)?;
        increment_nonce(&mut self.nonce);

        if len.len() != 2 {
            bail!("invalid decrypted length block");
        }
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if payload_len > self.cipher.max_payload_len() {
            bail!("payload length exceeds limit: {payload_len}");
        }

        let encrypted_payload = self.read_exact_from_ws(payload_len + SHADOWSOCKS_TAG_LEN).await?;
        let payload = decrypt(self.cipher, &key, &self.nonce, &encrypted_payload)?;
        increment_nonce(&mut self.nonce);
        Ok(payload)
    }

    async fn read_exact_from_ws(&mut self, len: usize) -> Result<Vec<u8>> {
        match &mut self.transport {
            TcpReadTransport::Socket { reader } => {
                let mut buf = vec![0u8; len];
                if let Err(err) = reader.read_exact(&mut buf).await {
                    if err.kind() == std::io::ErrorKind::UnexpectedEof {
                        self.closed_cleanly = true;
                        bail!("socket closed");
                    }
                    return Err(err).context("socket read failed");
                }
                Ok(buf)
            },
            TcpReadTransport::Websocket { stream, ctrl_tx } => {
                while self.buffer.len() < len {
                    let next = match stream.next().await {
                        None => {
                            self.closed_cleanly = true;
                            bail!("websocket closed");
                        },
                        Some(Ok(msg)) => msg,
                        Some(Err(e)) => return Err(anyhow!("websocket read failed: {e}")),
                    };

                    match next {
                        Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
                        Message::Close(_) => {
                            self.closed_cleanly = true;
                            bail!("websocket closed");
                        },
                        Message::Ping(payload) => {
                            let _ = ctrl_tx.try_send(Message::Pong(payload));
                        },
                        Message::Pong(_) => {},
                        Message::Text(_) => bail!("unexpected text websocket frame"),
                        Message::Frame(_) => {},
                    }
                }

                let tail = self.buffer.split_off(len);
                Ok(std::mem::replace(&mut self.buffer, tail))
            },
        }
    }
}

impl UdpWsTransport {
    pub(crate) fn from_websocket(
        ws_stream: AnyWsStream,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let master_key = cipher.derive_master_key(password)?;
        let (close_signal, _close_rx) = watch::channel(false);
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
                        },
                        Some(m) => {
                            if ws_sink.send(m).await.is_err() {
                                return;
                            }
                        },
                    }
                }
            }
        });
        let keepalive_task = keepalive_interval.map(|interval| {
            let keepalive_ctrl_tx = ctrl_tx.clone();
            AbortOnDrop(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // skip the first immediate tick
                loop {
                    ticker.tick().await;
                    if keepalive_ctrl_tx.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }))
        });
        Ok(Self {
            transport: UdpTransport::Websocket {
                data_tx,
                ctrl_tx,
                stream: Mutex::new(stream),
                _writer_task: AbortOnDrop(writer_task),
                _keepalive_task: keepalive_task,
            },
            cipher,
            master_key,
            ss2022: cipher.is_ss2022().then(|| {
                Mutex::new(Ss2022UdpState {
                    client_session_id: rand::random::<u64>(),
                    next_client_packet_id: 0,
                    server_session_id: None,
                    last_server_packet_id: None,
                })
            }),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    pub(crate) fn from_socket(
        socket: UdpSocket,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
    ) -> Result<Self> {
        let (close_signal, _close_rx) = watch::channel(false);
        let master_key = cipher.derive_master_key(password)?;
        Ok(Self {
            transport: UdpTransport::Socket { socket },
            cipher,
            master_key,
            ss2022: cipher.is_ss2022().then(|| {
                Mutex::new(Ss2022UdpState {
                    client_session_id: rand::random::<u64>(),
                    next_client_packet_id: 0,
                    server_session_id: None,
                    last_server_packet_id: None,
                })
            }),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    pub async fn connect(
        url: &Url,
        mode: WsTransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let ws_stream = connect_websocket_with_source(url, mode, fwmark, ipv6_first, source)
            .await
            .with_context(|| format!("failed to connect to {}", url))?;
        Self::from_websocket(ws_stream, cipher, password, source, keepalive_interval)
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        let packet = if let Some(state) = &self.ss2022 {
            let mut state = state.lock().await;
            let packet = encrypt_udp_packet_2022(
                self.cipher,
                &self.master_key,
                state.client_session_id,
                state.next_client_packet_id,
                payload,
            )?;
            state.next_client_packet_id += 1;
            packet
        } else {
            encrypt_udp_packet(self.cipher, &self.master_key, payload)?
        };
        match &self.transport {
            UdpTransport::Websocket { data_tx, .. } => data_tx
                .send(Message::Binary(packet.into()))
                .await
                .context("failed to send UDP websocket frame"),
            UdpTransport::Socket { socket } => {
                if packet.len() > MAX_UDP_SOCKET_PACKET_SIZE {
                    warn!(
                        packet_len = packet.len(),
                        limit = MAX_UDP_SOCKET_PACKET_SIZE,
                        cipher = %self.cipher,
                        "dropping oversized UDP packet before shadowsocks uplink send"
                    );
                    crate::metrics::record_dropped_oversized_udp_packet("outgoing");
                    bail!(OVERSIZED_UDP_UPLINK_DROP_ERR);
                }
                socket
                    .send(&packet)
                    .await
                    .context("failed to send UDP shadowsocks packet")
                    .map(|_| ())
            },
        }
    }

    pub async fn read_packet(&self) -> Result<Vec<u8>> {
        match &self.transport {
            UdpTransport::Socket { socket } => {
                let mut close_rx = self.close_signal.subscribe();
                let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD + 128];
                if *close_rx.borrow() {
                    bail!("udp transport closed");
                }
                let len = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            bail!("udp transport closed");
                        }
                        bail!("udp transport close state changed unexpectedly");
                    }
                    len = socket.recv(&mut buf) => {
                        len.context("failed to read UDP shadowsocks packet")?
                    }
                };
                self.decrypt_udp_bytes(&buf[..len]).await
            },
            UdpTransport::Websocket { stream, ctrl_tx, .. } => {
                let mut close_rx = self.close_signal.subscribe();
                let mut stream = stream.lock().await;
                loop {
                    if *close_rx.borrow() {
                        bail!("udp transport closed");
                    }
                    let message = tokio::select! {
                        _ = close_rx.changed() => {
                            if *close_rx.borrow() {
                                bail!("udp transport closed");
                            }
                            continue;
                        }
                        message = stream.next() => {
                            message
                                .ok_or_else(|| anyhow!("websocket closed"))?
                                .context("websocket read failed")?
                        }
                    };
                    match message {
                        Message::Binary(bytes) => return self.decrypt_udp_bytes(&bytes).await,
                        Message::Close(_) => bail!("websocket closed"),
                        Message::Ping(payload) => {
                            let _ = ctrl_tx.try_send(Message::Pong(payload));
                        },
                        Message::Pong(_) => {},
                        Message::Text(_) => bail!("unexpected text websocket frame"),
                        Message::Frame(_) => {},
                    }
                }
            },
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        if let UdpTransport::Websocket { data_tx, .. } = &self.transport {
            let _ = data_tx.send(Message::Close(None)).await;
        }
        Ok(())
    }

    async fn decrypt_udp_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        if let Some(state) = &self.ss2022 {
            let expected_client_session_id = state.lock().await.client_session_id;
            let (session_id, packet_id, payload) = decrypt_udp_packet_2022(
                self.cipher,
                &self.master_key,
                expected_client_session_id,
                bytes,
            )?;
            let mut state = state.lock().await;
            if let Some(last_server_packet_id) = state.last_server_packet_id {
                if state.server_session_id == Some(session_id) && packet_id <= last_server_packet_id
                {
                    bail!("duplicate or out-of-order ss2022 UDP packet");
                }
            }
            state.server_session_id = Some(session_id);
            state.last_server_packet_id = Some(packet_id);
            return Ok(payload);
        }
        decrypt_udp_packet(self.cipher, &self.master_key, bytes)
    }
}

async fn connect_websocket_http1(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<H1WsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "http1");
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr =
        resolve_host_with_preference(host, port, "failed to resolve websocket host", ipv6_first)
            .await?
            .into_iter()
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
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr =
        resolve_host_with_preference(host, port, "failed to resolve h2 websocket host", ipv6_first)
            .await?
            .into_iter()
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
        .initial_stream_window_size(Some(h2_stream_window_size()))
        .initial_connection_window_size(Some(h2_connection_window_size()))
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
        bail!("HTTP/2 websocket CONNECT failed with status {}", response.status());
    }

    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .context("failed to upgrade HTTP/2 websocket stream")?;
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    connect_guard.finish("success");
    Ok(AnyWsStream::H2 {
        inner: H2WsStream { inner: ws, driver_task },
    })
}

async fn connect_tls_h2(
    addr: SocketAddr,
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

async fn connect_tcp_socket(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    // For connections without fwmark use tokio's async connector so we never
    // block a Tokio worker thread waiting for the TCP handshake to complete.
    if fwmark.is_none() {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect TCP socket to {addr}"))?;
        configure_tcp_stream_low_latency(&stream, addr)?;
        return Ok(stream);
    }
    connect_tcp_socket_with_fwmark(addr, fwmark).await
}

/// fwmark variant: needs SO_MARK set on the raw socket before connect, which
/// requires socket2.  Only supported on Linux; on other platforms apply_fwmark
/// returns Err before we reach the connect logic.
#[cfg(target_os = "linux")]
async fn connect_tcp_socket_with_fwmark(
    addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(SocketProtocol::TCP))
        .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    // Set non-blocking BEFORE connect so that the handshake is driven by tokio
    // instead of blocking the current thread.
    socket
        .set_nonblocking(true)
        .context("failed to set TCP socket nonblocking")?;
    // Non-blocking connect: returns EINPROGRESS while the handshake is in flight.
    match socket.connect(&addr.into()) {
        Ok(()) => {},
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            // Connection in progress; writable() below will signal completion.
        },
        Err(e) => return Err(e).with_context(|| format!("failed to connect TCP socket to {addr}")),
    }
    let stream =
        TcpStream::from_std(socket.into()).context("failed to adopt TCP socket into tokio")?;
    // Yield to the runtime until the OS signals that the socket is writable,
    // which means the three-way handshake completed (or failed).
    stream
        .writable()
        .await
        .with_context(|| format!("failed waiting for TCP connect to {addr}"))?;
    // Retrieve the actual connect result via getsockopt(SO_ERROR).
    if let Some(err) = stream.take_error().context("failed to retrieve TCP socket error")? {
        return Err(err).with_context(|| format!("TCP connection to {addr} failed"));
    }
    configure_tcp_stream_low_latency(&stream, addr)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_tcp_socket_with_fwmark(
    _addr: SocketAddr,
    _fwmark: Option<u32>,
) -> Result<TcpStream> {
    bail!("fwmark is only supported on Linux")
}

pub(crate) fn bind_udp_socket(
    bind_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<std::net::UdpSocket> {
    let socket =
        Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(SocketProtocol::UDP))
            .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    apply_fwmark(&socket, fwmark)?;
    if let Some(&size) = UDP_RECV_BUF_BYTES.get() {
        let _ = socket.set_recv_buffer_size(size);
    }
    if let Some(&size) = UDP_SEND_BUF_BYTES.get() {
        let _ = socket.set_send_buffer_size(size);
    }
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?;
    Ok(socket.into())
}

fn configure_tcp_stream_low_latency(stream: &TcpStream, addr: SocketAddr) -> Result<()> {
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for {addr}"))
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

pub(crate) fn websocket_path(url: &Url) -> String {
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

fn websocket_target_uri(url: &Url) -> Result<String> {
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => bail!("unsupported websocket scheme for h2 target URI: {other}"),
    };

    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let mut uri = format!("{scheme}://{}", format_authority(host, url.port()));
    uri.push_str(&websocket_path(url));
    Ok(uri)
}

pub(crate) fn format_authority(host: &str, port: Option<u16>) -> String {
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

pub(crate) fn bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
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

#[cfg(test)]
mod tests;
