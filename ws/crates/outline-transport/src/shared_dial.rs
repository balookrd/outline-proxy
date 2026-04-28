//! Generic "reuse-or-dial" skeleton shared by the H2 and H3 WebSocket transports.
//!
//! [`WsDialer`] abstracts the transport-specific parts: connection key type,
//! underlying connection establishment, and opening a single WebSocket stream
//! on an existing connection. The two generic entry points —
//! [`connect_ws_reused`] and [`connect_ws_probe`] — provide the common
//! skeleton: DNS resolution, optional multi-address failover, the
//! [`TransportConnectGuard`] lifecycle, and the `with_reuse` cache
//! integration.

use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tracing::debug;

use crate::{
    DnsCache, TransportConnectGuard, TransportOperation, WsTransportStream,
    resolve_host_with_preference,
};
use crate::shared_cache::{CachedEntry, SharedConnectionRegistry, with_reuse};

// ── Trait ─────────────────────────────────────────────────────────────────────

pub(crate) trait WsDialer: 'static {
    type Key: Clone + Eq + Hash + Send + Sync + 'static;
    type Conn: CachedEntry + crate::SharedConnectionHealth + Send + Sync + 'static;

    fn registry(&self) -> &'static SharedConnectionRegistry<Self::Key, Self::Conn>;
    fn metric_label(&self) -> &'static str;

    /// Whether to try every resolved DNS address on failure rather than only
    /// the first.  H3 sets this; H2 currently uses the first address only.
    fn multi_address_failover_enabled(&self) -> bool;

    fn make_key(&self, server_name: &str, server_port: u16, fwmark: Option<u32>) -> Self::Key;

    /// Establish a fresh underlying connection to `addr`.  `cache_key` is
    /// `Some` when the driver task should auto-invalidate the cache on close
    /// (reuse path); `None` for probe connections.
    async fn establish(
        &self,
        addr: SocketAddr,
        server_name: &str,
        fwmark: Option<u32>,
        cache_key: Option<Self::Key>,
    ) -> Result<Arc<Self::Conn>>;

    /// Open one WebSocket stream on `conn`, returning it already wrapped in
    /// the correct `WsTransportStream` variant.
    async fn open_on(
        &self,
        conn: &Arc<Self::Conn>,
        server_name: &str,
        server_port: u16,
        path: &str,
    ) -> Result<WsTransportStream>;
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Reuse-or-dial path for non-probe connections.
pub(crate) async fn connect_ws_reused<D: WsDialer>(
    dialer: &D,
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    path: &str,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    let key = dialer.make_key(server_name, server_port, fwmark);
    let label = dialer.metric_label();

    with_reuse(
        dialer.registry(),
        key.clone(),
        |shared| async move {
            match dialer.open_on(&shared, server_name, server_port, path).await {
                Ok(ws) => {
                    outline_metrics::record_transport_connect(source, label, "reused");
                    Ok(ws)
                },
                Err(error) => {
                    debug!(
                        server_name,
                        server_port,
                        error = %format!("{error:#}"),
                        "cached shared {label} connection failed to open websocket stream; reconnecting"
                    );
                    Err(error)
                },
            }
        },
        || async move {
            resolve_and_dial(dialer, cache, server_name, server_port, path, fwmark, ipv6_first, source, Some(key)).await
        },
    )
    .await
}

/// Fresh-connection (probe) path — bypasses the shared-connection cache.
pub(crate) async fn connect_ws_probe<D: WsDialer>(
    dialer: &D,
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    path: &str,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    let (_shared, ws) = resolve_and_dial(
        dialer, cache, server_name, server_port, path, fwmark, ipv6_first, source, None,
    )
    .await?;
    Ok(ws)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Resolve DNS then dial one or all addresses depending on
/// `dialer.multi_address_failover_enabled()`.  Returns the first successful
/// `(connection, stream)` pair or a `TransportOperation::Connect` error.
async fn resolve_and_dial<D: WsDialer>(
    dialer: &D,
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    path: &str,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    cache_key: Option<D::Key>,
) -> Result<(Arc<D::Conn>, WsTransportStream)> {
    let label = dialer.metric_label();
    let context = format!("failed to resolve {label} websocket host");
    let server_addrs =
        resolve_host_with_preference(cache, server_name, server_port, &context, ipv6_first)
            .await?;
    if server_addrs.is_empty() {
        return Err(anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
            host: format!("{server_name}:{server_port}"),
        }));
    }

    let addrs: &[SocketAddr] = if dialer.multi_address_failover_enabled() {
        &server_addrs
    } else {
        &server_addrs[..1]
    };

    let mut last_error = None;
    for &addr in addrs {
        let mut guard = TransportConnectGuard::new(source, label);
        match dialer.establish(addr, server_name, fwmark, cache_key.clone()).await {
            Ok(conn) => {
                match dialer.open_on(&conn, server_name, server_port, path).await {
                    Ok(ws) => {
                        guard.finish("success");
                        return Ok((conn, ws));
                    },
                    Err(e) => last_error = Some(format!("{addr}: {e}")),
                }
            },
            Err(e) => last_error = Some(format!("{addr}: {e}")),
        }
    }

    Err(anyhow::Error::new(TransportOperation::Connect {
        target: format!(
            "to any resolved {label} address for {server_name}:{server_port}: {}",
            last_error.unwrap_or_else(|| "unknown error".to_string())
        ),
    }))
}
