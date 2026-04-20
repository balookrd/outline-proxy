// Connection infrastructure for the HTTP/3 WebSocket transport.
//
// Owns the QUIC/TLS configs, shared endpoints, per-key connect locks,
// shared-connection cache, and all connect / gc logic.  The stream adapter
// types (`H3WsStream`, `H3ConnectionGuard`) and the message-conversion helpers
// live in the parent module (`mod.rs`) because they are the public API
// consumed by `ws_stream.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h3::client::{RequestStream as H3RequestStream, SendRequest as H3SendRequest};
use http::{Method, Request};
use once_cell::sync::OnceCell;
use rustls::ClientConfig;
use sockudo_ws::{
    Config as SockudoConfig, Http3 as SockudoHttp3, Stream as SockudoTransportStream,
    WebSocketStream as SockudoWebSocketStream,
};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info};
use url::Url;

use crate::{
    AbortOnDrop, WsTransportStream, TransportConnectGuard, TransportOperation,
    bind_addr_for, bind_udp_socket,
    DnsCache, resolve_host_with_preference,
};

use super::{H3ConnectionGuard, H3WsStream, websocket_h3_target_uri, websocket_path};

type H3RequestStreamHandle = H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3SendRequestHandle = H3SendRequest<h3_quinn::OpenStreams, Bytes>;

// Upper bound for opening a new H3 WebSocket stream on top of an already
// established QUIC connection.  Without this bound, a silently-broken shared
// QUIC connection (network dropped but quinn has not yet hit its 120s idle
// timeout) makes every new SOCKS TCP session hang indefinitely on the CONNECT
// request instead of producing an error that would invalidate the shared
// connection and trigger failover through `report_runtime_failure`.  The
// handshake itself is already complete at this point; a generous budget of a
// few seconds is plenty for a healthy path and keeps the worst-case recovery
// latency bounded.
const OPEN_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(7);

// Upper bound for establishing a fresh HTTP/3 connection (QUIC handshake +
// HTTP/3 handshake).  Without this bound, a server black hole would let the
// QUIC handshake stall for up to `max_idle_timeout` (120s), which masks
// failover in exactly the same way as the shared-connection stalls do.
// 10 seconds matches the bound used for fresh H2 and H1 handshakes.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Connection key ────────────────────────────────────────────────────────────

// The cache key is intentionally based on the *hostname* and port rather than
// the resolved IP address.  Using the IP address would create a new cache entry
// on every DNS rotation (round-robin CDN, failover, etc.), leaving the old
// QUIC connection alive in the map forever because `is_open()` stays `true`
// until the server eventually drops the idle connection.  A hostname-based key
// means there is at most one shared H3 connection per logical server: when the
// DNS answer changes, the old connection is kept until it fails naturally, at
// which point a fresh connection is made to the (now re-resolved) new address.
pub(super) type H3ConnectionKey = crate::shared_cache::ConnectionKey;

// ── Shared connection ─────────────────────────────────────────────────────────

pub(super) struct SharedH3Connection {
    pub(super) id: u64,
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    // Kept alive to prevent the h3 driver from initiating graceful shutdown
    // (H3_NO_ERROR) prematurely. The h3 layer treats the last SendRequest
    // being dropped as a signal that no more requests will be made.
    send_request: Mutex<H3SendRequestHandle>,
    /// Soft-close flag: set to `true` by `open_websocket` on timeout so no
    /// new streams are opened, but existing streams continue to work
    /// undisturbed.  Using `connection.close()` was too aggressive — it kills
    /// ALL active H3 streams on the shared connection, causing a cascade of
    /// reconnects and rapid FD growth.
    closed: AtomicBool,
    // conn_life diagnostics: counts every WS stream opened on this connection
    // (observed at close by the driver task) to correlate session_death bursts
    // with a single underlying connection's death.
    streams_opened: Arc<AtomicU64>,
    _connection_guard: H3ConnectionGuard,
    _driver_task: AbortOnDrop,
}

impl SharedH3Connection {
    pub(super) fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.connection.close_reason().is_none()
    }

    pub(super) async fn open_websocket(
        self: &Arc<Self>,
        server_name: &str,
        server_port: u16,
        path: &str,
    ) -> Result<H3WsStream> {
        match self.open_websocket_inner(server_name, server_port, path).await {
            Ok(ws) => Ok(ws),
            Err(error) => {
                // Any failure opening a new CONNECT stream on an already-cached
                // shared QUIC connection is a strong signal the connection is
                // sick (send timeout, response timeout, non-2xx status, etc.).
                // Soft-close so concurrent callers racing to open another
                // stream skip this entry in `is_open()` and fall through to
                // the cache-invalidation path.
                self.closed.store(true, Ordering::Relaxed);
                Err(error)
            },
        }
    }

    async fn open_websocket_inner(
        self: &Arc<Self>,
        server_name: &str,
        server_port: u16,
        path: &str,
    ) -> Result<H3WsStream> {
        if !self.is_open() {
            bail!("shared h3 connection is already closed");
        }

        let request: Request<()> = Request::builder()
            .method(Method::CONNECT)
            .uri(websocket_h3_target_uri(server_name, server_port, path)?)
            .extension(h3::ext::Protocol::WEBSOCKET)
            .header("sec-websocket-version", "13")
            .body(())
            .expect("request builder never fails");

        let mut stream: H3RequestStreamHandle = timeout(OPEN_WEBSOCKET_TIMEOUT, async {
            let mut send_request = self.send_request.lock().await;
            send_request
                .send_request(request)
                .await
                .context("failed to send HTTP/3 websocket CONNECT request")
        })
        .await
        .map_err(|_| {
            anyhow!(
                "HTTP/3 websocket CONNECT request timed out after {}s on shared connection",
                OPEN_WEBSOCKET_TIMEOUT.as_secs()
            )
        })??;

        let response = timeout(OPEN_WEBSOCKET_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| {
                anyhow!(
                    "HTTP/3 websocket CONNECT response timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to receive HTTP/3 websocket response")?;
        if !response.status().is_success() {
            bail!("HTTP/3 websocket CONNECT failed with status {}", response.status());
        }

        let h3_stream = SockudoTransportStream::<SockudoHttp3>::from_h3_client(stream);
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok(H3WsStream {
            inner: SockudoWebSocketStream::from_raw(
                h3_stream,
                sockudo_ws::Role::Client,
                SockudoConfig::builder().http3_idle_timeout(90_000).build(),
            ),
            _shared_connection: Arc::clone(self),
        })
    }
}

impl crate::SharedConnectionHealth for SharedH3Connection {
    fn is_open(&self) -> bool {
        self.is_open()
    }

    fn conn_id(&self) -> u64 {
        self.id
    }

    fn mode(&self) -> &'static str {
        "h3"
    }
}

// ── TLS / QUIC client configs (initialised once) ─────────────────────────────

static H3_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
static H3_QUIC_CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();

/// Returns a shared, lazily-initialised TLS config for H3 connections.
/// Building the config (parsing root certificates) is expensive; doing it once
/// avoids the cost on every connection attempt and every warm-standby refill.
fn h3_client_tls_config() -> Arc<ClientConfig> {
    Arc::clone(H3_CLIENT_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"h3"])))
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
            // detects dead connections promptly.  Tighter max_idle_timeout
            // (30s, down from 120s) so a silently-dropped QUIC path on
            // consumer-router conntrack is torn down within ~30s instead of 2
            // minutes, letting the shared-connection cache evict the dead
            // entry and reconnects succeed promptly.  PING every 10s keeps
            // NAT mappings fresh well inside that budget.
            transport.keep_alive_interval(Some(Duration::from_secs(10)));
            transport.max_idle_timeout(Some(
                Duration::from_secs(30)
                    .try_into()
                    .expect("valid H3 QUIC client idle timeout"),
            ));
            config.transport_config(Arc::new(transport));
            config
        })
        .clone()
}

// ── Shared endpoints ──────────────────────────────────────────────────────────

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

// ── Shared-connection cache ───────────────────────────────────────────────────

// Global shared-connection cache. `RwLock<HashMap<K, Arc<V>>>` mirrors the
// flow-table pattern in `tun_tcp` / `tun_udp` (and `h2_shared`): hot-path
// lookups take a brief read-lock, clone the `Arc`, and release before any
// `.await` on the value. Only cache mutations (insert / evict / gc) take
// the write-lock. Avoids serialising every QUIC open behind one Mutex.
static H3_SHARED_CONNECTIONS: OnceCell<RwLock<HashMap<H3ConnectionKey, Arc<SharedH3Connection>>>> =
    OnceCell::new();
static H3_SHARED_CONNECTION_IDS: AtomicU64 = AtomicU64::new(1);

// Per-server-key mutex that serialises concurrent QUIC connection establishment.
// Without this, when the shared QUIC connection drops and N sessions try to
// reconnect simultaneously, each starts its own QUIC handshake (thundering herd).
// With the lock: the first waiter establishes the connection and caches it; the
// rest re-check the cache after acquiring the lock and reuse the result.
// The HashMap entries are never removed; they remain as empty Mutex<()> objects
// (a few bytes each) — acceptable because the set of unique server keys is small.
static H3_CONNECT_LOCKS: OnceCell<
    parking_lot::Mutex<HashMap<H3ConnectionKey, Arc<tokio::sync::Mutex<()>>>>,
> = OnceCell::new();

fn h3_connect_locks(
) -> &'static parking_lot::Mutex<HashMap<H3ConnectionKey, Arc<tokio::sync::Mutex<()>>>> {
    H3_CONNECT_LOCKS.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn get_h3_connect_lock(key: &H3ConnectionKey) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = h3_connect_locks().lock();
    locks.entry(key.clone()).or_default().clone()
}

fn h3_shared_connections() -> &'static RwLock<HashMap<H3ConnectionKey, Arc<SharedH3Connection>>> {
    H3_SHARED_CONNECTIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h3(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    if url.scheme() != "wss" {
        bail!("h3 websocket transport currently requires wss:// URLs");
    }

    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let path = websocket_path(url);

    if should_reuse_h3_connection(source) {
        // DNS resolution is deferred to the slow path inside connect_h3_quic_reused
        // so the cache key stays hostname-based and is not affected by DNS rotation.
        let ws = connect_h3_quic_reused(cache, host, port, &path, fwmark, ipv6_first, source).await?;
        return Ok(WsTransportStream::H3 { inner: ws });
    }

    // Probes never share connections; resolve DNS upfront and try each address.
    let server_addrs = resolve_host_with_preference(
        cache,
        host,
        port,
        "failed to resolve h3 websocket host",
        ipv6_first,
    )
    .await?;
    if server_addrs.is_empty() {
        return Err(anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
            host: format!("{host}:{port}"),
        }));
    }

    let mut last_error = None;
    for server_addr in server_addrs.iter().copied() {
        match connect_h3_quic_new(server_addr, host, port, &path, fwmark, None, source).await {
            Ok(ws) => return Ok(WsTransportStream::H3 { inner: ws }),
            Err(error) => last_error = Some(format!("{server_addr}: {error}")),
        }
    }

    Err(anyhow::Error::new(TransportOperation::Connect {
        target: format!(
            "to any resolved h3 address for {host}:{port}: {}",
            last_error.unwrap_or_else(|| "unknown error".to_string())
        ),
    }))
}

async fn connect_h3_quic_reused(
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    path: &str,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<H3WsStream> {
    let key = H3ConnectionKey::new(server_name, server_port, fwmark);

    // Fast path: reuse an already-established shared connection without locking.
    // DNS is NOT resolved here — the key is hostname-based so cache lookups are
    // independent of which IP address the server currently resolves to.
    if let Some(shared) = cached_shared_h3_connection(&key).await {
        match shared.open_websocket(server_name, server_port, path).await {
            Ok(ws) => {
                outline_metrics::record_transport_connect(source, "h3", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_name,
                    server_port,
                    error = %format!("{error:#}"),
                    "cached shared h3 connection failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h3_connection_if_current(&key, shared.id).await;
            },
        }
    }

    // Slow path: need to establish a new QUIC connection.  Serialise per
    // server key so that concurrent reconnect attempts (e.g. after the shared
    // QUIC connection drops and N sessions all try to reconnect at once) share
    // the single new connection rather than each starting their own QUIC
    // handshake (thundering herd).
    let connect_lock = get_h3_connect_lock(&key);
    let _connect_guard = connect_lock.lock().await;

    // Re-check the cache under the lock: another waiter may have established
    // and cached a fresh connection while we were waiting.
    if let Some(shared) = cached_shared_h3_connection(&key).await {
        match shared.open_websocket(server_name, server_port, path).await {
            Ok(ws) => {
                outline_metrics::record_transport_connect(source, "h3", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_name,
                    server_port,
                    error = %format!("{error:#}"),
                    "shared h3 connection (post-lock recheck) failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h3_connection_if_current(&key, shared.id).await;
            },
        }
    }

    // Resolve DNS only now — we actually need a new QUIC connection.  By
    // deferring resolution to this point we always connect to the *current*
    // address while keeping the cache key hostname-based.
    let server_addrs = resolve_host_with_preference(
        cache,
        server_name,
        server_port,
        "failed to resolve h3 websocket host",
        ipv6_first,
    )
    .await?;
    if server_addrs.is_empty() {
        return Err(anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
            host: format!("{server_name}:{server_port}"),
        }));
    }

    let mut last_error = None;
    for server_addr in server_addrs.iter().copied() {
        match connect_h3_quic_new(
            server_addr,
            server_name,
            server_port,
            path,
            fwmark,
            Some(key.clone()),
            source,
        )
        .await
        {
            Ok(ws) => return Ok(ws),
            Err(error) => last_error = Some(format!("{server_addr}: {error}")),
        }
    }

    Err(anyhow::Error::new(TransportOperation::Connect {
        target: format!(
            "to any resolved h3 address for {server_name}:{server_port}: {}",
            last_error.unwrap_or_else(|| "unknown error".to_string())
        ),
    }))
}

/// Establishes a brand-new QUIC + HTTP/3 connection to `server_addr`, opens
/// one WebSocket stream on it, and — if `cache_key` is provided — inserts the
/// connection into the shared cache for future reuse.
async fn connect_h3_quic_new(
    server_addr: SocketAddr,
    server_name: &str,
    server_port: u16,
    path: &str,
    fwmark: Option<u32>,
    cache_key: Option<H3ConnectionKey>,
    source: &'static str,
) -> Result<H3WsStream> {
    let mut transport_guard = TransportConnectGuard::new(source, "h3");
    let shared = Arc::new(
        connect_h3_connection(server_addr, server_name, fwmark, cache_key.clone()).await?,
    );
    let ws = shared.open_websocket(server_name, server_port, path).await?;
    transport_guard.finish("success");
    if let Some(key) = cache_key {
        cache_shared_h3_connection(key, Arc::clone(&shared)).await;
    }
    Ok(ws)
}

async fn connect_h3_connection(
    server_addr: SocketAddr,
    server_name: &str,
    fwmark: Option<u32>,
    cache_key: Option<H3ConnectionKey>,
) -> Result<SharedH3Connection> {
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

    let connecting = endpoint
        .connect_with(client_config, server_addr, server_name)
        .with_context(|| format!("failed to initiate QUIC connection to {server_addr}"))?;
    let (connection_handle, mut driver, send_request) = timeout(FRESH_CONNECT_TIMEOUT, async {
        let connection = connecting
            .await
            .with_context(|| format!("QUIC handshake failed for {server_addr}"))?;
        let connection_handle = connection.clone();
        let (driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .context("HTTP/3 handshake failed")?;
        Ok::<_, anyhow::Error>((connection_handle, driver, send_request))
    })
    .await
    .map_err(|_| {
        anyhow!(
            "HTTP/3 fresh connect timed out after {}s to {server_addr}",
            FRESH_CONNECT_TIMEOUT.as_secs()
        )
    })??;

    let id = H3_SHARED_CONNECTION_IDS.fetch_add(1, Ordering::Relaxed);
    let streams_opened = Arc::new(AtomicU64::new(0));
    let streams_opened_driver = Arc::clone(&streams_opened);
    let opened_at = Instant::now();
    let peer = server_addr.to_string();
    let peer_for_driver = peer.clone();
    info!(
        target: "outline_transport::conn_life",
        id, peer = %peer, mode = "h3", "h3 connection opened"
    );
    let driver_task = AbortOnDrop(tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Some(cache_key) = cache_key {
            invalidate_shared_h3_connection_if_current(&cache_key, id).await;
        }
        let err_text = err.to_string();
        let age_secs = opened_at.elapsed().as_secs();
        let streams = streams_opened_driver.load(Ordering::Relaxed);
        let class = classify_h3_close(&err_text);
        if is_expected_h3_close(&err_text) {
            info!(
                target: "outline_transport::conn_life",
                id,
                peer = %peer_for_driver,
                mode = "h3",
                age_secs,
                streams,
                class,
                error = %err_text,
                "h3 connection closed"
            );
        } else {
            info!(
                target: "outline_transport::conn_life",
                id,
                peer = %peer_for_driver,
                mode = "h3",
                age_secs,
                streams,
                class,
                error = %err_text,
                "h3 connection closed with error"
            );
            error!("h3 connection error: {err_text}");
        }
    }));

    Ok(SharedH3Connection {
        id,
        endpoint,
        connection: connection_handle.clone(),
        send_request: Mutex::new(send_request),
        closed: AtomicBool::new(false),
        streams_opened,
        _connection_guard: H3ConnectionGuard(connection_handle),
        _driver_task: driver_task,
    })
}

fn classify_h3_close(err: &str) -> &'static str {
    if err.contains("H3_NO_ERROR") {
        "h3_no_error"
    } else if err.contains("H3_INTERNAL_ERROR") {
        "h3_internal"
    } else if err.contains("H3_REQUEST_REJECTED") {
        "h3_rejected"
    } else if err.contains("H3_CONNECT_ERROR") {
        "h3_connect_error"
    } else if err.contains("ApplicationClose") {
        "app_close"
    } else if err.contains("Timeout") || err.contains("timed out") {
        "timeout"
    } else if err.contains("closed by client") || err.contains("Connection closed by client") {
        "local_close"
    } else if err.contains("reset") || err.contains("Reset") {
        "rst"
    } else if err.contains("tls") || err.contains("TLS") || err.contains("certificate") {
        "tls"
    } else {
        "other"
    }
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

async fn cached_shared_h3_connection(key: &H3ConnectionKey) -> Option<Arc<SharedH3Connection>> {
    // Hot path: read-lock, clone the `Arc`, release the lock. Concurrent
    // lookups on *other* keys are no longer serialised behind a single Mutex.
    let candidate = {
        let shared = h3_shared_connections().read().await;
        shared.get(key).cloned()
    };
    match candidate {
        Some(connection) if connection.is_open() => Some(connection),
        Some(stale) => {
            // Slow path: take the write-lock only to evict the stale entry,
            // and re-check under it — another waiter may have already replaced
            // the entry with a fresh connection between our read/write locks.
            let mut shared = h3_shared_connections().write().await;
            if shared.get(key).is_some_and(|c| c.id == stale.id) {
                shared.remove(key);
            }
            None
        },
        None => None,
    }
}

async fn cache_shared_h3_connection(key: H3ConnectionKey, connection: Arc<SharedH3Connection>) {
    let mut shared = h3_shared_connections().write().await;
    match shared.get(&key) {
        Some(existing) if existing.is_open() => {},
        _ => {
            shared.insert(key, connection);
        },
    }
}

async fn invalidate_shared_h3_connection_if_current(key: &H3ConnectionKey, id: u64) {
    // Cheap pre-check under the read-lock — the common case (entry gone or
    // replaced) avoids taking the write-lock at all.
    let needs_evict = {
        let shared = h3_shared_connections().read().await;
        shared.get(key).is_some_and(|connection| connection.id == id)
    };
    if !needs_evict {
        return;
    }
    let mut shared = h3_shared_connections().write().await;
    if shared.get(key).is_some_and(|connection| connection.id == id) {
        shared.remove(key);
    }
}

/// Remove all cache entries whose shared connection is no longer open.
/// Called periodically from the warm-standby maintenance loop so dead entries
/// do not linger indefinitely when no new request re-checks their key (e.g.
/// after DNS rotation changes the resolved address for a server name).
pub(crate) async fn gc_shared_h3_connections() {
    crate::shared_cache::gc_stale_entries(h3_shared_connections(), |c| c.is_open()).await;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(super) fn should_reuse_h3_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
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
        // QUIC idle timeout: Quinn surfaces this as the plain string "Timeout".
        // The session side already records a runtime failure; the driver task
        // logging it again at ERROR is redundant noise.
        || err.contains("Timeout")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_shared_connection_key_distinguishes_server_name_port_and_fwmark() {
        let base = H3ConnectionKey::new("example.com", 443, None);

        // Same key for any resolved IP — the key is hostname-based
        assert_eq!(base, H3ConnectionKey::new("example.com", 443, None));
        // Different hostname
        assert_ne!(base, H3ConnectionKey::new("example.net", 443, None));
        // Different fwmark
        assert_ne!(base, H3ConnectionKey::new("example.com", 443, Some(100)));
        // Different port
        assert_ne!(base, H3ConnectionKey::new("example.com", 8443, None));
    }

    #[test]
    fn probe_sources_do_not_reuse_shared_h3_connections() {
        assert!(should_reuse_h3_connection("socks_tcp"));
        assert!(should_reuse_h3_connection("standby_udp"));
        assert!(!should_reuse_h3_connection("probe_ws"));
        assert!(!should_reuse_h3_connection("probe_http"));
    }
}
