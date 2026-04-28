// HTTP/2 connection infrastructure: window-size statics, TLS config, H2Io
// async-IO adapter, connect_tls_h2, H2Dialer (WsDialer impl), connection
// cache, and connect / gc logic.
//
// Stream adapter types (H2WsStream) live in the parent module (`mod.rs`).
// The generic dial skeleton is in `crate::shared_dial`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::{Method, Request, Version};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pin_project_lite::pin_project;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::info;
use url::Url;

use crate::{
    AbortOnDrop, WsTransportStream, SharedConnectionHealth,
    DnsCache, connect_tcp_socket,
};
use crate::shared_cache::{
    ConnCloseLog, SharedConnectionRegistry, classify_by_substrings, log_conn_close,
};
use crate::url_utils::{format_authority, websocket_path};

use super::H2WsStream;

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
    Arc::clone(H2_CLIENT_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"h2"])))
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
    base: crate::shared_cache::ConnectionKey,
    use_tls: bool,
}

impl H2ConnectionKey {
    fn new(server_name: &str, server_port: u16, use_tls: bool, fwmark: Option<u32>) -> Self {
        Self {
            base: crate::shared_cache::ConnectionKey::new(server_name, server_port, fwmark),
            use_tls,
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
    // conn_life diagnostics: counts every WS stream opened on this connection
    // (observed at close by the driver task) to correlate session_death bursts
    // with a single underlying connection's death.
    streams_opened: Arc<AtomicU64>,
    _driver_task: AbortOnDrop,
}

impl SharedH2Connection {
    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    async fn open_websocket(
        self: &Arc<Self>,
        target_uri: &str,
        resume_request: Option<crate::resumption::SessionId>,
    ) -> Result<WsTransportStream> {
        match self.open_websocket_inner(target_uri, resume_request).await {
            Ok(ws) => Ok(ws),
            Err(error) => {
                // Any failure opening a new CONNECT stream on an already-cached
                // shared connection is a strong signal the connection is sick
                // (hyper's .ready() failed, server sent non-2xx, upgrade hung,
                // etc.).  Mark it closed now so concurrent callers racing to
                // open another stream skip this entry in `is_open()` instead
                // of repeating the same failure before the caller invalidates
                // the cache entry.
                self.closed.store(true, Ordering::Release);
                Err(error)
            },
        }
    }

    async fn open_websocket_inner(
        self: &Arc<Self>,
        target_uri: &str,
        resume_request: Option<crate::resumption::SessionId>,
    ) -> Result<WsTransportStream> {
        if !self.is_open() {
            bail!("shared h2 connection is already closed");
        }

        let mut request_builder = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(target_uri)
            .extension(Protocol::from_static("websocket"))
            .header("sec-websocket-version", "13")
            // Always advertise resumption support; the server only mints a
            // Session ID when this header is present and resumption is
            // enabled in its config. Servers without the feature ignore it.
            .header(crate::resumption::RESUME_CAPABLE_HEADER, "1");
        if let Some(id) = resume_request {
            request_builder =
                request_builder.header(crate::resumption::RESUME_REQUEST_HEADER, id.to_hex());
        }
        let request: Request<Empty<Bytes>> = request_builder
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
            anyhow!(
                "HTTP/2 websocket CONNECT send timed out after {}s on shared connection",
                OPEN_WEBSOCKET_TIMEOUT.as_secs()
            )
        })??;

        let mut response = timeout(OPEN_WEBSOCKET_TIMEOUT, response_future)
            .await
            .map_err(|_| {
                anyhow!(
                    "HTTP/2 websocket CONNECT response timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to send HTTP/2 websocket CONNECT request")?;
        if !response.status().is_success() {
            bail!("HTTP/2 websocket CONNECT failed with status {}", response.status());
        }
        let issued_session_id = response
            .headers()
            .get(crate::resumption::SESSION_RESPONSE_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::resumption::SessionId::parse_hex);

        let upgraded = timeout(OPEN_WEBSOCKET_TIMEOUT, hyper::upgrade::on(&mut response))
            .await
            .map_err(|_| {
                anyhow!(
                    "HTTP/2 websocket upgrade timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to upgrade HTTP/2 websocket stream")?;
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
        let shared_connection: Arc<dyn SharedConnectionHealth> = self.clone();
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok(WsTransportStream::H2 {
            inner: H2WsStream::new_shared(ws, shared_connection),
            issued_session_id,
            downgraded_from: None,
        })
    }
}

impl SharedConnectionHealth for SharedH2Connection {
    fn is_open(&self) -> bool {
        self.is_open()
    }

    fn conn_id(&self) -> u64 {
        self.id
    }

    fn mode(&self) -> &'static str {
        "h2"
    }
}

impl crate::shared_cache::CachedEntry for SharedH2Connection {
    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_open(&self) -> bool {
        self.is_open()
    }
}

// ── Shared-connection cache ───────────────────────────────────────────────────

// Global registry holding the shared-connection map, the per-key reconnect
// locks, and the connection-id counter. Hot-path lookups take only a brief
// read-lock on the inner map, mirroring the flow-table pattern in `tun_tcp` /
// `tun_udp`. The registry abstraction lives in `shared_cache` and is shared
// with H3.
static H2_REGISTRY: OnceLock<SharedConnectionRegistry<H2ConnectionKey, SharedH2Connection>> =
    OnceLock::new();

fn h2_registry() -> &'static SharedConnectionRegistry<H2ConnectionKey, SharedH2Connection> {
    H2_REGISTRY.get_or_init(SharedConnectionRegistry::new)
}

// ── H2Dialer ──────────────────────────────────────────────────────────────────

struct H2Dialer {
    use_tls: bool,
    /// Session ID the caller wants to resume on this open. Captured at
    /// dialer construction so the trait `open_on` method can stay
    /// signature-stable while threading the request through to
    /// `SharedH2Connection::open_websocket`.
    resume_request: Option<crate::resumption::SessionId>,
}

impl crate::shared_dial::WsDialer for H2Dialer {
    type Key = H2ConnectionKey;
    type Conn = SharedH2Connection;

    fn registry(&self) -> &'static SharedConnectionRegistry<H2ConnectionKey, SharedH2Connection> {
        h2_registry()
    }

    fn metric_label(&self) -> &'static str {
        "h2"
    }

    fn try_all_dns_addrs(&self) -> bool {
        false
    }

    fn make_key(&self, server_name: &str, server_port: u16, fwmark: Option<u32>) -> H2ConnectionKey {
        H2ConnectionKey::new(server_name, server_port, self.use_tls, fwmark)
    }

    async fn establish(
        &self,
        addr: SocketAddr,
        server_name: &str,
        fwmark: Option<u32>,
        cache_key: Option<H2ConnectionKey>,
    ) -> Result<Arc<SharedH2Connection>> {
        Ok(Arc::new(connect_h2_connection(addr, server_name, self.use_tls, fwmark, cache_key).await?))
    }

    async fn open_on(
        &self,
        conn: &Arc<SharedH2Connection>,
        server_name: &str,
        server_port: u16,
        path: &str,
    ) -> Result<WsTransportStream> {
        let scheme = if self.use_tls { "https" } else { "http" };
        let target_uri = format!("{scheme}://{}/{path}", format_authority(server_name, Some(server_port)));
        conn.open_websocket(&target_uri, self.resume_request).await
    }
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h2(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    resume_request: Option<crate::resumption::SessionId>,
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
    let path = websocket_path(url);
    let dialer = H2Dialer { use_tls, resume_request };

    if crate::shared_cache::should_reuse_connection(source) {
        // DNS resolution is deferred to the slow path inside connect_ws_reused
        // so the cache key stays hostname-based and is not affected by DNS rotation.
        crate::shared_dial::connect_ws_reused(&dialer, cache, host, port, &path, fwmark, ipv6_first, source).await
    } else {
        // Probes never share connections; fresh dial with no cache interaction.
        crate::shared_dial::connect_ws_probe(&dialer, cache, host, port, &path, fwmark, ipv6_first, source).await
    }
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
            // Tighter than the previous 20s/20s so a silently-broken shared
            // connection (e.g. NAT/conntrack on the router path through
            // hev-socks5-tunnel loses the TCP mapping) is detected within ~20s
            // instead of ~40s, bounding how long new SOCKS sessions stall on
            // the dead cache entry before failover can pick a fresh uplink.
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .keep_alive_timeout(Duration::from_secs(10))
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

    let id = h2_registry().next_id();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_flag = Arc::clone(&closed);
    let streams_opened = Arc::new(AtomicU64::new(0));
    let streams_opened_driver = Arc::clone(&streams_opened);
    let opened_at = Instant::now();
    let peer = server_addr.to_string();
    let peer_for_driver = peer.clone();
    let mode = if use_tls { "h2s" } else { "h2c" };
    info!(
        target: "outline_transport::conn_life",
        id, peer = %peer, mode, "h2 connection opened"
    );
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let result = conn.await;
        closed_flag.store(true, Ordering::Release);
        if let Some(cache_key) = cache_key {
            h2_registry().invalidate_if_current(&cache_key, id).await;
        }
        let fields = ConnCloseLog {
            id,
            peer: &peer_for_driver,
            mode,
            age_secs: opened_at.elapsed().as_secs(),
            streams: streams_opened_driver.load(Ordering::Relaxed),
        };
        match result {
            Ok(()) => log_conn_close(fields, None, "normal", true),
            Err(error) => {
                let error_text = error.to_string();
                let class = classify_h2_close(&error_text);
                let expected = is_expected_h2_close(&error_text);
                log_conn_close(fields, Some(&error_text), class, expected);
            }
        }
    }));

    Ok(SharedH2Connection {
        id,
        send_request,
        closed,
        streams_opened,
        _driver_task: driver_task,
    })
}

fn classify_h2_close(error: &str) -> &'static str {
    // H2 errors come from several layers (hyper, h2 crate, rustls, tokio IO);
    // normalize to lowercase once so the table stays case-insensitive.
    let e = error.to_ascii_lowercase();
    classify_by_substrings(
        &e,
        &[
            (&["goaway"], "goaway"),
            (&["reset", "rst"], "rst"),
            (&["timed out", "timeout", "keepalive"], "timeout"),
            (&["tls", "certificate", "handshake"], "tls"),
            (
                &[
                    "broken pipe",
                    "connection reset",
                    "connection closed",
                    "eof",
                    "unexpected end",
                ],
                "eof",
            ),
            (&["operation was canceled", "operation was cancelled"], "cancelled"),
            (&["io"], "io"),
        ],
        "other",
    )
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

/// Remove all cache entries whose shared connection is no longer open.
/// Called periodically from the warm-standby maintenance loop so dead entries
/// do not linger indefinitely when no new request re-checks their key (e.g.
/// after DNS rotation changes the resolved address for a server name).
pub(crate) async fn gc_shared_h2_connections() {
    h2_registry().gc().await;
}

fn is_expected_h2_close(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("operation was canceled")
        || error.contains("operation was cancelled")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::H2ConnectionKey;
    use crate::shared_cache::should_reuse_connection;

    #[test]
    fn h2_shared_connection_key_distinguishes_scheme_server_name_port_and_fwmark() {
        let base = H2ConnectionKey::new("one.example", 443, true, None);

        assert_ne!(base, H2ConnectionKey::new("two.example", 443, true, None));
        assert_ne!(base, H2ConnectionKey::new("one.example", 443, false, None));
        assert_ne!(base, H2ConnectionKey::new("one.example", 443, true, Some(42)));
        assert_ne!(base, H2ConnectionKey::new("one.example", 8443, true, None));
        assert_eq!(base, H2ConnectionKey::new("one.example", 443, true, None));
    }

    #[test]
    fn probe_sources_do_not_reuse_shared_h2_connections() {
        assert!(should_reuse_connection("direct"));
        assert!(should_reuse_connection("standby_tcp"));
        assert!(!should_reuse_connection("probe_ws"));
        assert!(!should_reuse_connection("probe_http"));
    }
}
