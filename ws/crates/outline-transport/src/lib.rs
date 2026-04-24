//! Transport connectors for outline-ws-rust.
//!
//! Provides outbound connection primitives over WebSocket (HTTP/1 upgrade),
//! HTTP/2, HTTP/3 (QUIC), and direct TCP/UDP, plus shared DNS resolution with
//! an in-process cache.  All transports carry Shadowsocks-encrypted streams
//! to the configured uplink server.

use std::fmt;
use std::time::Duration;

/// Typed marker placed in an `anyhow` error chain whenever a WebSocket
/// connection closes cleanly (Close frame or EOF from the peer). Classifiers
/// can match this via `error.chain().any(|e| e.downcast_ref::<WsClosed>().is_some())`
/// instead of pattern-matching on the formatted string.
#[derive(Debug)]
pub struct WsClosed;

impl fmt::Display for WsClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ws closed")
    }
}

impl std::error::Error for WsClosed {}

/// Typed marker for the high-level operation that produced a transport error.
/// Placed as an `anyhow` context layer at the failure site so classifiers can
/// identify the operation via `downcast_ref` rather than grepping the
/// formatted error string.
#[derive(Debug)]
pub enum TransportOperation {
    WebSocketRead,
    WebSocketSend,
    SocketShutdown,
    Connect { target: String },
    DnsResolveNoAddresses { host: String },
}

impl fmt::Display for TransportOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportOperation::WebSocketRead => write!(f, "websocket read failed"),
            TransportOperation::WebSocketSend => write!(f, "failed to send websocket frame"),
            TransportOperation::SocketShutdown => write!(f, "socket shutdown failed"),
            TransportOperation::Connect { target } => write!(f, "failed to connect {target}"),
            TransportOperation::DnsResolveNoAddresses { host } => {
                write!(f, "DNS resolution returned no addresses for {host}")
            },
        }
    }
}

impl std::error::Error for TransportOperation {}

/// Find a typed error of type `T` in an `anyhow::Error`.
///
/// `anyhow` exposes two distinct namespaces:
/// 1. Context layers added via `.context(T)` / `.with_context(|| T)` — these
///    are found by `anyhow::Error::downcast_ref::<T>()` but NOT by walking
///    `chain()` (the std `Error::source()` iterator does not expose
///    context values).
/// 2. Typed root/source errors (e.g. `bail!(outline_ss2022::Ss2022Error::…)`, `Error::new(T)`)
///    — found by either `downcast_ref` or `chain().find_map()`.
///
/// Many call-sites use form 1 (`.with_context(|| TransportOperation::…)`), so
/// classifiers MUST call `downcast_ref` on the `Error` itself; the chain walk
/// is kept as a fallback for typed errors constructed deeper.
pub fn find_typed<T: std::error::Error + Send + Sync + 'static>(
    error: &anyhow::Error,
) -> Option<&T> {
    error
        .downcast_ref::<T>()
        .or_else(|| error.chain().find_map(|e| e.downcast_ref::<T>()))
}

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

pub mod collections;
mod config;
mod dns;
mod dns_cache;
mod error_classify;
mod guards;
mod h2;
#[cfg(feature = "h3")]
pub(crate) mod h3;
mod tcp_transport;
mod udp_transport;
mod shared_cache;
mod shared_dial;
mod tls;
// Note: protocol-agnostic socket helpers now live in the `outline-net` crate.
mod url_utils;
mod ws_stream;

use dns::resolve_server_addr;
use h2::connect_websocket_h2;
pub(crate) use outline_net::{bind_addr_for, bind_udp_socket};
use std::net::SocketAddr;
use ws_stream::H1WsStream;

pub(crate) use guards::{AbortOnDrop, TransportConnectGuard};
pub(crate) use ws_stream::SharedConnectionHealth;

/// Local wrapper around `outline_net::connect_tcp_socket` that layers the
/// transport-level `TransportOperation::Connect` context onto the error so
/// classifiers in `outline-uplink` / `outline-tun` can recognise connect
/// failures via `find_typed::<TransportOperation>`. Kept as a thin wrapper
/// because `outline-net` is intentionally protocol-agnostic and does not
/// depend on the `TransportOperation` enum.
pub(crate) async fn connect_tcp_socket(
    addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<TcpStream> {
    outline_net::connect_tcp_socket(addr, fwmark)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("TCP socket to {addr}") })
}

// --- Public surface kept intentionally narrow. Group by concern so it's
// --- clear at a glance what the transport crate exposes. -------------------

// Config data types reused by callers that construct transport parameters
// (uplink config loader, CLI args, main-binary schema).
pub use config::{ServerAddr, WsTransportMode};

// DNS cache: shared by every resolve path in the main binary.
pub use dns::resolve_host_with_preference;
pub use dns_cache::{DEFAULT_DNS_CACHE_TTL, DnsCache};

// Entry points — connection constructors for TCP/UDP/WebSocket transports.
pub use udp_transport::{UdpWsTransport, is_dropped_oversized_udp_error};
pub use ws_stream::WsTransportStream;

// TCP transport primitives. `TcpReader` / `TcpWriter` are the unified enums
// TUN and the proxy plumb through; the `TcpShadowsocks*` helpers construct
// them. The half-specific variants (`WsTcpWriter`, `SocketTcpWriter`) are
// re-exported for TUN's state-machine pattern matching.
pub use tcp_transport::{
    TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    WsReadDiag, WsTcpWriter, SocketTcpWriter,
};

// Error-chain inspection helpers shared across crates.
pub use error_classify::{contains_any, find_io_error_kind, is_transport_level_disconnect, lower_error};

// HTTP/2 window-size tuning: called once during startup from the main binary.
pub use h2::init_h2_window_sizes;

// Transport lifetime guards — published because the uplink crate pairs a
// `UpstreamTransportGuard` to every connection it hands out.
pub use guards::UpstreamTransportGuard;

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
            Ok(WsTransportStream::new_http1(ws_stream))
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
                Ok(WsTransportStream::new_http1(ws_stream))
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
                        Ok(WsTransportStream::new_http1(ws_stream))
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
                    Ok(WsTransportStream::new_http1(ws_stream))
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
        .with_context(|| TransportOperation::Connect {
            target: format!("UDP socket to {server_addr}"),
        })?;
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
            .ok_or_else(|| {
                anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
                    host: format!("{host}:{port}"),
                })
            })?;
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
