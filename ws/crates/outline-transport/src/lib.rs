use std::fmt;
use std::time::Duration;

/// Typed marker placed in an `anyhow` error chain whenever a WebSocket
/// connection closes cleanly (Close frame or EOF from the peer). Classifiers
/// can match this via `error.chain().any(|e| e.downcast_ref::<WebSocketClosed>().is_some())`
/// instead of pattern-matching on the formatted string.
#[derive(Debug)]
pub struct WebSocketClosed;

impl fmt::Display for WebSocketClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "websocket closed")
    }
}

impl std::error::Error for WebSocketClosed {}

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_tungstenite::client_async_tls;
use tracing::{debug, warn};
use url::Url;

// Upper bound for the HTTP/1.1 WebSocket handshake (TCP connect + TLS +
// HTTP upgrade).  Unlike h2/h3 there is no shared pool to get stuck in, but
// `TcpStream::connect` is bounded only by the OS SYN-retransmit budget
// (Linux ~127s, macOS ~75s), and `client_async_tls` has no timeout of its
// own.  Without a bound here the fallback chain h3 → h2 → h1 could stall
// for minutes when the server is in a network black hole, before
// `report_runtime_failure` gets a chance to mark the uplink down.
const HTTP1_WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "h3")]
use crate::h3::connect_websocket_h3;

pub mod config;
mod dns;
mod dns_cache;
mod guards;
mod h2;
#[cfg(feature = "h3")]
pub(crate) mod h3;
mod socket;
mod tcp_transport;
mod udp_transport;
mod ws_stream;

pub use config::{ServerAddr, WsTransportMode};
pub use dns_cache::{DEFAULT_DNS_CACHE_TTL, DnsCache};

use dns::resolve_server_addr;
use h2::connect_websocket_h2;
use ws_stream::H1WsStream;

pub use h2::init_h2_window_sizes;
pub use socket::{bind_udp_socket, configure_inbound_tcp_stream, connect_tcp_socket, init_udp_socket_bufs};
pub use tcp_transport::{
    TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    WsTcpReader, WsTcpWriter, SocketTcpReader, SocketTcpWriter,
};
pub use udp_transport::{UdpWsTransport, is_dropped_oversized_udp_error};
pub use ws_stream::WsTransportStream;
pub(crate) use ws_stream::SharedConnectionHealth;

pub use dns::resolve_host_with_preference;
pub use guards::UpstreamTransportGuard;
pub(crate) use guards::{AbortOnDrop, TransportConnectGuard};
pub(crate) use socket::bind_addr_for;

/// Sweep H2 (and H3 when enabled) shared-connection caches, removing entries
/// whose underlying connection is no longer open.  Should be called
/// periodically (e.g. every 15 s from the warm-standby maintenance loop) to
/// prevent dead entries from accumulating when a cache key is never looked up
/// again (DNS rotation, server IP change, etc.).
pub async fn gc_shared_connections() {
    h2::gc_shared_h2_connections().await;
    #[cfg(feature = "h3")]
    crate::h3::gc_shared_h3_connections().await;
}

pub async fn connect_websocket(
    cache: &DnsCache,
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
) -> Result<WsTransportStream> {
    connect_websocket_with_source(cache, url, mode, fwmark, ipv6_first, "direct").await
}

pub async fn connect_websocket_with_source(
    cache: &DnsCache,
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    match mode {
        WsTransportMode::Http1 => {
            let ws_stream = connect_websocket_http1(cache, url, fwmark, ipv6_first, source).await?;
            debug!(url = %url, selected_mode = "http1", "websocket transport connected");
            Ok(WsTransportStream::Http1 { inner: ws_stream })
        },
        WsTransportMode::H2 => match connect_websocket_h2(cache, url, fwmark, ipv6_first, source).await {
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
                let ws_stream = connect_websocket_http1(cache, url, fwmark, ipv6_first, source).await?;
                debug!(url = %url, selected_mode = "http1", requested_mode = "h2", "websocket transport connected");
                Ok(WsTransportStream::Http1 { inner: ws_stream })
            },
        },
        #[cfg(feature = "h3")]
        WsTransportMode::H3 => match connect_websocket_h3(cache, url, fwmark, ipv6_first, source).await {
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
                match connect_websocket_h2(cache, url, fwmark, ipv6_first, source).await {
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
                            connect_websocket_http1(cache, url, fwmark, ipv6_first, source).await?;
                        debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                        Ok(WsTransportStream::Http1 { inner: ws_stream })
                    },
                }
            },
        },
        #[cfg(not(feature = "h3"))]
        WsTransportMode::H3 => {
            warn!(url = %url, "H3 requested but compiled without h3 feature, falling back to h2");
            match connect_websocket_h2(cache, url, fwmark, ipv6_first, source).await {
                Ok(stream) => {
                    debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                    Ok(stream)
                },
                Err(h2_error) => {
                    warn!(url = %url, error = %format!("{h2_error:#}"), fallback = "http1", "h2 websocket connect failed, falling back");
                    let ws_stream =
                        connect_websocket_http1(cache, url, fwmark, ipv6_first, source).await?;
                    debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                    Ok(WsTransportStream::Http1 { inner: ws_stream })
                },
            }
        },
    }
}

pub async fn connect_shadowsocks_tcp_with_source(
    cache: &DnsCache,
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<TcpStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "tcp");
    let server_addr = resolve_server_addr(cache, addr, ipv6_first).await?;
    let stream = connect_tcp_socket(server_addr, fwmark).await?;
    connect_guard.finish("success");
    Ok(stream)
}

pub async fn connect_shadowsocks_udp_with_source(
    cache: &DnsCache,
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<UdpSocket> {
    let mut connect_guard = TransportConnectGuard::new(source, "udp");
    let server_addr = resolve_server_addr(cache, addr, ipv6_first).await?;
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

async fn connect_websocket_http1(
    cache: &DnsCache,
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
        resolve_host_with_preference(cache, host, port, "failed to resolve websocket host", ipv6_first)
            .await?
            .first()
            .copied()
            .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {host}:{port}"))?;
    let ws_stream = timeout(HTTP1_WS_CONNECT_TIMEOUT, async {
        let tcp = connect_tcp_socket(server_addr, fwmark).await?;
        let (ws_stream, _) = client_async_tls(url.as_str(), tcp)
            .await
            .context("HTTP/1 websocket handshake failed")?;
        Ok::<_, anyhow::Error>(ws_stream)
    })
    .await
    .map_err(|_| {
        anyhow!(
            "HTTP/1 websocket handshake timed out after {}s connecting to {server_addr}",
            HTTP1_WS_CONNECT_TIMEOUT.as_secs()
        )
    })??;
    connect_guard.finish("success");
    Ok(ws_stream)
}

#[cfg(test)]
mod tests;
