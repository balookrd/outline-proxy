//! Transport connectors for outline-ws-rust.
//!
//! Provides outbound connection primitives over WebSocket (HTTP/1 upgrade),
//! HTTP/2, HTTP/3 (QUIC), and direct TCP/UDP, plus shared DNS resolution with
//! an in-process cache.  All transports carry Shadowsocks-encrypted streams
//! to the configured uplink server.

use std::fmt;

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

use anyhow::{Context, Result};
use tokio::net::{TcpStream, UdpSocket};

// Re-export resumption surface so callers in outline-uplink (and any
// future user) can reach `SessionId`, `global_resume_cache`, and friends
// without taking a direct dependency on the inner module path.
pub use resumption::{ResumeCache, SessionId, global_resume_cache};

pub mod ack_prefix;
#[cfg(feature = "cert-check")]
pub mod cert_check;
pub mod collections;
mod config;
mod dial_plan;
mod dns;
mod dns_cache;
pub mod downlink_replay;
mod error_classify;
pub mod fingerprint_profile;
pub mod frame_io;
#[cfg(feature = "quic")]
mod frame_io_quic;
mod frame_io_ws;
mod guards;
mod h2;
#[cfg(feature = "h3")]
pub(crate) mod h3;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
mod quic_connect;
pub mod resumption;
mod shared_cache;
mod shared_dial;
mod tcp_transport;
mod tls;
mod udp_transport;
pub mod vless;
#[cfg(feature = "quic")]
mod vless_quic_mux;
#[cfg(feature = "quic")]
mod vless_udp_hybrid;
// Note: protocol-agnostic socket helpers now live in the `outline-net` crate.
mod url_utils;
mod ws_mode_cache;
mod ws_stream;
mod xhttp;
mod xhttp_mode_cache;
mod xhttp_submode_cache;

use dns::resolve_server_addr;
pub(crate) use outline_net::{bind_addr_for, bind_udp_socket};
use std::net::SocketAddr;

pub use guards::AbortOnDrop;
pub(crate) use guards::TransportConnectGuard;
pub(crate) use ws_stream::SharedConnectionHealth;

/// Local wrapper around `outline_net::connect_tcp_socket` that layers the
/// transport-level `TransportOperation::Connect` context onto the error so
/// classifiers in `outline-uplink` / `outline-tun` can recognise connect
/// failures via `find_typed::<TransportOperation>`. Kept as a thin wrapper
/// because `outline-net` is intentionally protocol-agnostic and does not
/// depend on the `TransportOperation` enum.
pub(crate) async fn connect_tcp_socket(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    outline_net::connect_tcp_socket(addr, fwmark)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("TCP socket to {addr}") })
}

// --- Public surface kept intentionally narrow. Group by concern so it's
// --- clear at a glance what the transport crate exposes. -------------------

// Config data types reused by callers that construct transport parameters
// (uplink config loader, CLI args, main-binary schema).
pub use config::{ServerAddr, TransportMode};
pub use xhttp::XhttpSubmode;

// Test-only TLS knob: cross-repo integration tests in `outline-ss-rust`
// (which spin up an in-process self-signed server) call this before
// dialing so XHTTP h2/h3 trust their cert. Gated behind the `test-tls`
// feature so the symbol is absent from production builds; tests opt in
// via `outline-transport = { features = ["test-tls"] }`.
#[cfg(any(test, feature = "test-tls"))]
pub use tls::install_test_tls_root;

// HTTPS data-path probe: re-export the rustls types it needs so the probe
// crate can drive a TLS handshake over our chunk-based tunnel without
// taking a direct rustls dependency. `build_https_probe_client_config`
// shares root-store / test-override plumbing with every other dial in
// this crate (see [`tls::build_client_config`]).
pub use rustls::ClientConnection as TlsClientConnection;
pub use rustls::pki_types::ServerName as TlsServerName;
pub use tls::build_https_probe_client_config;

// DNS cache: shared by every resolve path in the main binary.
pub use dns::resolve_host_with_preference;
pub use dns_cache::{DEFAULT_DNS_CACHE_CAPACITY, DEFAULT_DNS_CACHE_TTL, DnsCache};

// Entry points — connection constructors for TCP/UDP/HTTP-family transports.
pub use dial_plan::{
    DialNetworkOptions, DialResumeOptions, TransportDialOptions, connect_transport,
};
#[cfg(feature = "quic")]
pub use quic_connect::{
    connect_ss_tcp_quic, connect_ss_udp_quic, connect_vless_tcp_quic,
    connect_vless_tcp_quic_with_resume, connect_vless_udp_session_quic,
};
pub use udp_transport::{
    OversizedUdpDatagram, UdpSessionTransport, UdpWsTransport, is_dropped_oversized_udp_error,
};
pub use vless::{
    VlessTcpReader, VlessTcpWriter, VlessUdpDowngradeNotifier, VlessUdpMuxLimits,
    VlessUdpSessionMux, VlessUdpWsTransport,
};
#[cfg(feature = "quic")]
pub use vless_quic_mux::VlessUdpQuicMux;
#[cfg(feature = "quic")]
pub use vless_udp_hybrid::{FallbackNotifier, VlessUdpHybridMux, WsFallbackFactory};
// `TargetAddr` is the input type for `connect_vless_tcp_quic*` and
// the SS QUIC dialers — re-exporting it spares callers from depending
// on the `socks5-proto` workspace crate directly.
pub use socks5_proto::TargetAddr;

// `CipherKind` is the input type for `TcpShadowsocksReader/Writer`
// constructors — re-exporting it spares callers from depending on
// the `shadowsocks-crypto` workspace crate directly.
pub use shadowsocks_crypto::CipherKind;
pub use ws_stream::TransportStream;

// TCP transport primitives. `TcpReader` / `TcpWriter` are the unified enums
// TUN and the proxy plumb through; the `TcpShadowsocks*` helpers construct
// them. The half-specific variants (`WsTcpWriter`, `SocketTcpWriter`) are
// re-exported for TUN's state-machine pattern matching.
#[cfg(feature = "quic")]
pub use tcp_transport::{QuicTcpReader, QuicTcpWriter};
pub use tcp_transport::{
    SocketTcpWriter, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter, WsReadDiag,
    WsTcpWriter,
};

// Error-chain inspection helpers shared across crates.
pub use error_classify::{
    contains_any, find_io_error_kind, is_transport_level_disconnect, lower_error,
};

// HTTP/2 window-size tuning: called once during startup from the main binary.
pub use h2::init_h2_window_sizes;

// Per-host downgrade cache TTL: called once during startup from the
// main binary, fed from the `mode_downgrade_secs` config knob. All
// three caches (WS h-version, XHTTP h-version, XHTTP submode) share
// the same knob — every axis decays on the same cadence, but the
// slots are independent so a `record_failure` on one axis cannot
// clobber the cap on another.
pub fn init_downgrade_ttl(ttl: std::time::Duration) {
    ws_mode_cache::init_downgrade_ttl(ttl);
    xhttp_mode_cache::init_downgrade_ttl(ttl);
    xhttp_submode_cache::init_downgrade_ttl(ttl);
}

/// Time remaining on the per-host XHTTP stream-one block for this dial
/// URL, or `None` when no block is active. Wraps the internal submode
/// cache so the uplink-snapshot builder can surface the cache state on
/// dashboards without depending on the cache module directly. Returns
/// `None` for non-XHTTP URLs (the cache simply has no entry there).
pub async fn xhttp_stream_one_block_remaining(url: &url::Url) -> Option<std::time::Duration> {
    xhttp_submode_cache::stream_one_block_remaining(url).await
}

// Browser fingerprint profile strategy: called once at startup when a
// deployment wants WS / XHTTP dials to mix in browser-style headers
// (User-Agent, Accept-*, Sec-Fetch-*). Default (knob unset) leaves the
// wire shape byte-identical to pre-profile builds.
pub use fingerprint_profile::{
    Strategy as FingerprintProfileStrategy,
    current_strategy as current_fingerprint_profile_strategy,
    init_strategy as init_fingerprint_profile_strategy,
};

// Transport lifetime guards — published because the uplink crate pairs a
// `UpstreamTransportGuard` to every connection it hands out.
pub use guards::{UplinkConnectionBinding, UpstreamTransportGuard};

/// Sweep H2 (and H3 when enabled) shared-connection caches, removing entries
/// whose underlying connection is no longer open.  Should be called
/// periodically (e.g. every 15 s from the warm-standby maintenance loop) to
/// prevent dead entries from accumulating when a cache key is never looked up
/// again (DNS rotation, server IP change, etc.).
pub async fn gc_shared_connections() {
    h2::gc_shared_h2_connections().await;
    #[cfg(feature = "h3")]
    crate::h3::gc_shared_h3_connections().await;
    #[cfg(feature = "quic")]
    crate::quic::gc_shared_quic_connections().await;
    ws_mode_cache::gc().await;
    xhttp_mode_cache::gc().await;
    xhttp_submode_cache::gc().await;
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

#[cfg(test)]
mod tests;
