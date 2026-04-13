use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::{Method, Request, Version};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pin_project_lite::pin_project;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{WebSocketStream, client_async_tls};
use tracing::{debug, error, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(feature = "h3")]
use crate::transport_h3::connect_websocket_h3;

use crate::dns_cache::DnsCache;
use crate::metrics::{
    add_transport_connects_active, add_upstream_transports_active, record_transport_connect,
    record_upstream_transport,
};
use crate::types::{ServerAddr, WsTransportMode};

mod socket;
mod tcp_transport;
mod udp_transport;
mod ws_stream;

use socket::connect_tcp_socket;
use ws_stream::{H1WsStream, H2WsStream};
pub use socket::init_udp_socket_bufs;
pub(crate) use socket::{bind_addr_for, bind_udp_socket};
pub use tcp_transport::{TcpShadowsocksReader, TcpShadowsocksWriter};
pub use udp_transport::{UdpWsTransport, is_dropped_oversized_udp_error};
pub use ws_stream::AnyWsStream;

// HTTP/2 flow-control window sizes. Defaults match the sizing used by
// sockudo-ws so the long-lived CONNECT stream carrying UDP datagrams does not
// stall on the small RFC default window under sustained downstream traffic.
// On memory-constrained routers these can be reduced via [h2] in config.toml.
static H2_INITIAL_STREAM_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static H2_INITIAL_CONNECTION_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();

/// Initialise H2 window sizes from config. Must be called before the first
/// outbound H2 connection is opened. Safe to call multiple times with the same
/// values; panics if called with different values after initialization.
pub fn init_h2_window_sizes(stream: u32, connection: u32) {
    H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| stream);
    H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| connection);
}

fn h2_stream_window_size() -> u32 {
    *H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| 1024 * 1024)
}

fn h2_connection_window_size() -> u32 {
    *H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| 2 * 1024 * 1024)
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
            if addr.is_ipv6() { 0 } else { 1 }
        } else if addr.is_ipv4() {
            0
        } else {
            1
        }
    });
    Ok(server_addrs)
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
        inner: H2WsStream::new(ws, driver_task),
    })
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
