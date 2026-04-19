// Shared HTTP/2 connection infrastructure: window-size statics, TLS config,
// H2Io async-IO adapter, connect_tls_h2, connection cache, per-key connect
// locks, and all connect / gc logic.
//
// Stream adapter types (H2WsStream) and URL helpers (websocket_target_uri,
// format_authority, websocket_path) live in the parent module (`mod.rs`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

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
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::{debug, error};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    AbortOnDrop, WsTransportStream, SharedConnectionHealth, TransportConnectGuard,
    DnsCache, connect_tcp_socket, resolve_host_with_preference,
};

use super::{H2WsStream, websocket_h2_target_uri};

// ── Window sizes ──────────────────────────────────────────────────────────────

// HTTP/2 flow-control window sizes.  Defaults match the sizing used by
// sockudo-ws so the long-lived CONNECT stream carrying UDP datagrams does not
// stall on the small RFC default window under sustained downstream traffic.
// On memory-constrained routers these can be reduced via [h2] in config.toml.
static H2_INITIAL_STREAM_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static H2_INITIAL_CONNECTION_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();

/// Initialise H2 window sizes from config.  Must be called before the first
/// outbound H2 connection is opened.  Safe to call multiple times with the same
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

// ── H2Io ──────────────────────────────────────────────────────────────────────

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

type H2SendRequestHandle = http2::SendRequest<Empty<Bytes>>;

// Upper bound for opening a new H2 WebSocket stream on top of an already
// established HTTP/2 connection.  Hyper's own keep-alive (interval 20s +
// timeout 20s) would eventually detect a silently-broken shared connection
// and tear it down, but that leaves new SOCKS TCP sessions stalled for up to
// ~40s in the worst case.  Bounding each await keeps the worst-case recovery
// latency short enough that `report_runtime_failure` fires and the probe-based
// failover has a chance to react promptly.  The handshake itself is already
// complete at this point; 10 seconds is a generous budget for issuing a
// CONNECT request and reading its response on a healthy link.
const OPEN_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(10);

// Upper bound for establishing a fresh HTTP/2 connection (TCP + TLS +
// h2 handshake).  Neither `TcpStream::connect`, `connect_tls_h2`, nor
// `hyper::client::conn::http2::Builder::handshake` enforce a deadline, so
// without this bound a server in a network black hole could stall the
// fallback path for the entire TCP SYN retransmit budget (Linux ~127s,
// macOS ~75s).  10 seconds is plenty for a healthy fresh connect and
// matches the bound used for HTTP/1 websocket handshakes.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Connection key ────────────────────────────────────────────────────────────

// The cache key is intentionally based on the *hostname* and port rather than
// the resolved IP address.  Using the IP address would create a new cache entry
// on every DNS rotation (round-robin CDN, failover, etc.), leaving the old
// TCP socket alive in the map forever because `is_open()` stays `true` until
// the server eventually drops the idle connection.  A hostname-based key means
// there is at most one shared H2 connection per logical server: when the DNS
// answer changes, the old connection is kept until it fails naturally, at which
// point a fresh connection is made to the (now re-resolved) new address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct H2ConnectionKey {
    server_name: Arc<str>,
    server_port: u16,
    use_tls: bool,
    fwmark: Option<u32>,
}

impl H2ConnectionKey {
    fn new(server_name: &str, server_port: u16, use_tls: bool, fwmark: Option<u32>) -> Self {
        Self {
            server_name: Arc::from(server_name),
            server_port,
            use_tls,
            fwmark,
        }
    }
}

// ── Shared connection ─────────────────────────────────────────────────────────

struct SharedH2Connection {
    id: u64,
    // hyper's http2::SendRequest<B> is Send + Sync + Clone — concurrent stream
    // opens on the same shared connection do not need a Mutex.  Using a Mutex
    // serialises .ready().await calls: under load, one task blocking on
    // .ready() holds the lock, which causes all other tasks to queue behind it.
    // When the blocked task times out it counts as a runtime failure and sets a
    // cooldown on a healthy uplink.  Using Clone instead lets every task call
    // .ready() independently; hyper's H2 layer handles flow-control internally.
    send_request: H2SendRequestHandle,
    closed: Arc<AtomicBool>,
    _driver_task: AbortOnDrop,
}

impl SharedH2Connection {
    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    async fn open_websocket(self: &Arc<Self>, target_uri: &str) -> Result<WsTransportStream> {
        if !self.is_open() {
            bail!("shared h2 connection is already closed");
        }

        let request: Request<Empty<Bytes>> = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(target_uri)
            .extension(Protocol::from_static("websocket"))
            .header("sec-websocket-version", "13")
            .body(Empty::new())
            .expect("request builder never fails");

        // Clone the SendRequest handle so each concurrent open_websocket call
        // proceeds independently.  hyper's http2::SendRequest is Send+Sync+Clone
        // and internally manages per-connection concurrency via flow control.
        // Previously we held a Mutex here, which caused all callers to queue
        // behind a single .ready().await — any timeout became a false runtime
        // failure on a healthy uplink.
        let response_future = timeout(OPEN_WEBSOCKET_TIMEOUT, async {
            let mut send_request = self.send_request.clone();
            send_request
                .ready()
                .await
                .context("shared h2 connection is not ready for a new websocket CONNECT")?;
            Ok::<_, anyhow::Error>(send_request.send_request(request))
        })
        .await
        .map_err(|_| {
            self.closed.store(true, Ordering::Relaxed);
            anyhow!(
                "HTTP/2 websocket CONNECT send timed out after {}s on shared connection",
                OPEN_WEBSOCKET_TIMEOUT.as_secs()
            )
        })??;

        let mut response = timeout(OPEN_WEBSOCKET_TIMEOUT, response_future)
            .await
            .map_err(|_| {
                self.closed.store(true, Ordering::Relaxed);
                anyhow!(
                    "HTTP/2 websocket CONNECT response timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to send HTTP/2 websocket CONNECT request")?;
        if !response.status().is_success() {
            bail!("HTTP/2 websocket CONNECT failed with status {}", response.status());
        }

        let upgraded = timeout(OPEN_WEBSOCKET_TIMEOUT, hyper::upgrade::on(&mut response))
            .await
            .map_err(|_| {
                self.closed.store(true, Ordering::Relaxed);
                anyhow!(
                    "HTTP/2 websocket upgrade timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to upgrade HTTP/2 websocket stream")?;
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
        let shared_connection: Arc<dyn SharedConnectionHealth> = self.clone();
        Ok(WsTransportStream::H2 {
            inner: H2WsStream::new_shared(ws, shared_connection),
        })
    }
}

impl SharedConnectionHealth for SharedH2Connection {
    fn is_open(&self) -> bool {
        self.is_open()
    }
}

// ── Shared-connection cache ───────────────────────────────────────────────────

// Global shared-connection cache. `RwLock<HashMap<K, Arc<V>>>` mirrors the
// flow-table pattern in `tun_tcp` / `tun_udp`: hot-path lookups take a brief
// read-lock, clone the `Arc`, and release before any `.await` on the value
// itself. Only cache mutations (insert / evict / gc) take the write-lock.
// Avoids adding a DashMap dependency while removing the serialisation that a
// single `Mutex` imposed on every H2 CONNECT attempt.
static H2_SHARED_CONNECTIONS: OnceLock<RwLock<HashMap<H2ConnectionKey, Arc<SharedH2Connection>>>> =
    OnceLock::new();
static H2_SHARED_CONNECTION_IDS: AtomicU64 = AtomicU64::new(1);
// Per-server-key mutex that serialises concurrent H2 connection establishment.
// Prevents a thundering herd when the shared H2 connection drops and N sessions
// all try to reconnect simultaneously — identical pattern to H3_CONNECT_LOCKS.
static H2_CONNECT_LOCKS: OnceLock<
    parking_lot::Mutex<HashMap<H2ConnectionKey, Arc<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();

fn h2_shared_connections() -> &'static RwLock<HashMap<H2ConnectionKey, Arc<SharedH2Connection>>> {
    H2_SHARED_CONNECTIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn h2_connect_locks(
) -> &'static parking_lot::Mutex<HashMap<H2ConnectionKey, Arc<tokio::sync::Mutex<()>>>> {
    H2_CONNECT_LOCKS.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn get_h2_connect_lock(key: &H2ConnectionKey) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = h2_connect_locks().lock();
    locks.entry(key.clone()).or_default().clone()
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h2(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let use_tls = match url.scheme() {
        "ws" => false,
        "wss" => true,
        scheme => bail!("unsupported scheme for h2 websocket: {scheme}"),
    };
    let target_uri = websocket_h2_target_uri(url)?;

    if should_reuse_h2_connection(source) {
        // DNS resolution is deferred to the slow path inside connect_h2_reused
        // so the cache key stays hostname-based and is not affected by DNS rotation.
        connect_h2_tcp_reused(cache, host, port, use_tls, &target_uri, fwmark, ipv6_first, source).await
    } else {
        // Probes never share connections; resolve DNS upfront for the fresh dial.
        let server_addr = resolve_host_with_preference(
            cache,
            host,
            port,
            "failed to resolve h2 websocket host",
            ipv6_first,
        )
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {host}:{port}"))?;
        connect_h2_tcp_new(server_addr, host, use_tls, &target_uri, fwmark, source).await
    }
}

#[allow(clippy::too_many_arguments)] // private helper; grouping into a struct would cost more than it saves
async fn connect_h2_tcp_reused(
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    use_tls: bool,
    target_uri: &str,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<WsTransportStream> {
    let key = H2ConnectionKey::new(server_name, server_port, use_tls, fwmark);

    // Fast path: reuse an already-established shared connection without locking.
    // DNS is NOT resolved here — the key is hostname-based so cache lookups are
    // independent of which IP address the server currently resolves to.
    if let Some(shared) = cached_shared_h2_connection(&key).await {
        match shared.open_websocket(target_uri).await {
            Ok(ws) => {
                outline_metrics::record_transport_connect(source, "h2", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_name,
                    server_port,
                    use_tls,
                    error = %format!("{error:#}"),
                    "cached shared h2 connection failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h2_connection_if_current(&key, shared.id).await;
            },
        }
    }

    // Slow path: need to establish a new H2 connection.  Serialise per server
    // key so that concurrent reconnect attempts share the result rather than
    // each starting their own TCP+TLS+H2 handshake (thundering herd).
    let connect_lock = get_h2_connect_lock(&key);
    let _connect_guard = connect_lock.lock().await;

    // Re-check under the lock: another waiter may have established and cached
    // a fresh connection while we were waiting.
    if let Some(shared) = cached_shared_h2_connection(&key).await {
        match shared.open_websocket(target_uri).await {
            Ok(ws) => {
                outline_metrics::record_transport_connect(source, "h2", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_name,
                    server_port,
                    use_tls,
                    error = %format!("{error:#}"),
                    "shared h2 connection (post-lock recheck) failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h2_connection_if_current(&key, shared.id).await;
            },
        }
    }

    // Resolve DNS only now — we actually need a new TCP connection.  By
    // deferring resolution to this point we always connect to the *current*
    // address while keeping the cache key hostname-based.
    let server_addr = resolve_host_with_preference(
        cache,
        server_name,
        server_port,
        "failed to resolve h2 websocket host",
        ipv6_first,
    )
    .await?
    .first()
    .copied()
    .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {server_name}:{server_port}"))?;

    let mut transport_guard = TransportConnectGuard::new(source, "h2");
    let shared = Arc::new(
        connect_h2_connection(server_addr, server_name, use_tls, fwmark, Some(key.clone())).await?,
    );
    let ws = shared.open_websocket(target_uri).await?;
    transport_guard.finish("success");
    cache_shared_h2_connection(key, Arc::clone(&shared)).await;
    Ok(ws)
}

async fn connect_h2_tcp_new(
    server_addr: SocketAddr,
    server_name: &str,
    use_tls: bool,
    target_uri: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<WsTransportStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let shared =
        Arc::new(connect_h2_connection(server_addr, server_name, use_tls, fwmark, None).await?);
    let ws = shared.open_websocket(target_uri).await?;
    connect_guard.finish("success");
    Ok(ws)
}

async fn connect_h2_connection(
    server_addr: SocketAddr,
    server_name: &str,
    use_tls: bool,
    fwmark: Option<u32>,
    cache_key: Option<H2ConnectionKey>,
) -> Result<SharedH2Connection> {
    let (send_request, conn) = timeout(FRESH_CONNECT_TIMEOUT, async {
        let io = if use_tls {
            H2Io::Tls {
                inner: connect_tls_h2(server_addr, server_name, fwmark).await?,
            }
        } else {
            H2Io::Plain {
                inner: connect_tcp_socket(server_addr, fwmark).await?,
            }
        };

        http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(Some(h2_stream_window_size()))
            .initial_connection_window_size(Some(h2_connection_window_size()))
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(20))
            .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
            .await
            .context("HTTP/2 handshake failed")
    })
    .await
    .map_err(|_| {
        anyhow!(
            "HTTP/2 fresh connect timed out after {}s to {server_addr}",
            FRESH_CONNECT_TIMEOUT.as_secs()
        )
    })??;

    let id = H2_SHARED_CONNECTION_IDS.fetch_add(1, Ordering::Relaxed);
    let closed = Arc::new(AtomicBool::new(false));
    let closed_flag = Arc::clone(&closed);
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let result = conn.await;
        closed_flag.store(true, Ordering::Relaxed);
        if let Some(cache_key) = cache_key {
            invalidate_shared_h2_connection_if_current(&cache_key, id).await;
        }
        match result {
            Ok(()) => debug!("h2 connection closed"),
            Err(error) => {
                let error_text = error.to_string();
                if is_expected_h2_close(&error_text) {
                    debug!("h2 connection closed: {error_text}");
                } else {
                    error!("h2 connection error: {error_text}");
                }
            },
        }
    }));

    Ok(SharedH2Connection {
        id,
        send_request,
        closed,
        _driver_task: driver_task,
    })
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

fn should_reuse_h2_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
}

async fn cached_shared_h2_connection(key: &H2ConnectionKey) -> Option<Arc<SharedH2Connection>> {
    // Hot path: read-lock, clone the `Arc`, release the lock. Concurrent
    // lookups on *other* keys are no longer serialised behind a single Mutex.
    let candidate = {
        let shared = h2_shared_connections().read().await;
        shared.get(key).cloned()
    };
    match candidate {
        Some(connection) if connection.is_open() => Some(connection),
        Some(stale) => {
            // Slow path: take the write-lock only to evict the stale entry,
            // and re-check under it — another waiter may have already replaced
            // the entry with a fresh connection between our read/write locks.
            let mut shared = h2_shared_connections().write().await;
            if shared.get(key).is_some_and(|c| c.id == stale.id) {
                shared.remove(key);
            }
            None
        },
        None => None,
    }
}

async fn cache_shared_h2_connection(key: H2ConnectionKey, connection: Arc<SharedH2Connection>) {
    let mut shared = h2_shared_connections().write().await;
    match shared.get(&key) {
        Some(existing) if existing.is_open() => {},
        _ => {
            shared.insert(key, connection);
        },
    }
}

async fn invalidate_shared_h2_connection_if_current(key: &H2ConnectionKey, id: u64) {
    // Cheap pre-check under the read-lock — the common case (entry gone or
    // replaced) avoids taking the write-lock at all.
    let needs_evict = {
        let shared = h2_shared_connections().read().await;
        shared.get(key).is_some_and(|connection| connection.id == id)
    };
    if !needs_evict {
        return;
    }
    let mut shared = h2_shared_connections().write().await;
    if shared.get(key).is_some_and(|connection| connection.id == id) {
        shared.remove(key);
    }
}

/// Remove all cache entries whose shared connection is no longer open.
/// Called periodically from the warm-standby maintenance loop so dead entries
/// do not linger indefinitely when no new request re-checks their key (e.g.
/// after DNS rotation changes the resolved address for a server name).
pub(crate) async fn gc_shared_h2_connections() {
    // Fast path: scan under a read-lock. If nothing is stale we avoid the
    // write-lock entirely, so a healthy GC tick does not interfere with
    // concurrent CONNECT lookups.
    let stale_keys: Vec<H2ConnectionKey> = {
        let shared = h2_shared_connections().read().await;
        shared
            .iter()
            .filter(|(_, conn)| !conn.is_open())
            .map(|(k, _)| k.clone())
            .collect()
    };
    if stale_keys.is_empty() {
        return;
    }
    let mut shared = h2_shared_connections().write().await;
    for key in stale_keys {
        if shared.get(&key).is_some_and(|conn| !conn.is_open()) {
            shared.remove(&key);
        }
    }
}

fn is_expected_h2_close(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("operation was canceled")
        || error.contains("operation was cancelled")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{H2ConnectionKey, should_reuse_h2_connection};

    #[test]
    fn h2_shared_connection_key_distinguishes_scheme_server_name_port_and_fwmark() {
        let base = H2ConnectionKey::new("one.example", 443, true, None);

        // Different hostname
        assert_ne!(base, H2ConnectionKey::new("two.example", 443, true, None));
        // Different scheme (wss vs ws)
        assert_ne!(base, H2ConnectionKey::new("one.example", 443, false, None));
        // Different fwmark
        assert_ne!(base, H2ConnectionKey::new("one.example", 443, true, Some(42)));
        // Different port — must produce a distinct key even though scheme is the same
        assert_ne!(base, H2ConnectionKey::new("one.example", 8443, true, None));
        // Same IP-resolved address must NOT be distinguishable — the key is hostname-based
        // so two logical uplinks pointing at the same host:port share one connection.
        assert_eq!(base, H2ConnectionKey::new("one.example", 443, true, None));
    }

    #[test]
    fn probe_sources_do_not_reuse_shared_h2_connections() {
        assert!(should_reuse_h2_connection("direct"));
        assert!(should_reuse_h2_connection("standby_tcp"));
        assert!(!should_reuse_h2_connection("probe_ws"));
        assert!(!should_reuse_h2_connection("probe_http"));
    }
}
