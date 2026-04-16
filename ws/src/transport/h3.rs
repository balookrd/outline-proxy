// HTTP/3 WebSocket transport — only compiled when the `h3` feature is enabled.
// All H3-specific types, statics, and functions live here so that transport.rs
// is free of scattered #[cfg(feature = "h3")] annotations.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures_util::{Sink, Stream};
use h3::client::{RequestStream as H3RequestStream, SendRequest as H3SendRequest};
use http::{Method, Request, Uri};
use once_cell::sync::OnceCell;
use pin_project_lite::pin_project;
use sockudo_ws::{
    Config as SockudoConfig, Http3 as SockudoHttp3, Message as SockudoMessage,
    Stream as SockudoTransportStream, WebSocketStream as SockudoWebSocketStream,
    error::CloseReason as SockudoCloseReason,
};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Utf8Bytes, coding::CloseCode};
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, error};
use url::Url;

use crate::transport::{
    AbortOnDrop, AnyWsStream, TransportConnectGuard, bind_addr_for, bind_udp_socket,
    format_authority, resolve_host_with_preference, websocket_path,
};

type RawH3WsStream = SockudoWebSocketStream<SockudoTransportStream<SockudoHttp3>>;
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

// ── H3WsStream ────────────────────────────────────────────────────────────────

pin_project! {
    pub(crate) struct H3WsStream {
        #[pin]
        inner: RawH3WsStream,
        // Keep the shared connection alive for as long as this websocket stream
        // is active so the underlying HTTP/3 state does not get torn down.
        pub(crate) _shared_connection: Arc<SharedH3Connection>,
    }
}

impl H3WsStream {
    pub(crate) fn is_connection_alive(&self) -> bool {
        self._shared_connection.is_open()
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

// ── H3ConnectionGuard ─────────────────────────────────────────────────────────

/// Sends QUIC `CONNECTION_CLOSE` when dropped so the server is notified
/// immediately rather than waiting for its idle timeout to fire.
pub(crate) struct H3ConnectionGuard(pub(crate) quinn::Connection);

impl Drop for H3ConnectionGuard {
    fn drop(&mut self) {
        // H3_NO_ERROR = 0x100 per RFC 9114 §8.1. Using 0 is not a valid H3
        // application error code and causes some servers to respond with
        // H3_INTERNAL_ERROR, triggering a reconnect storm under load.
        self.0.close(0x100u32.into(), b"websocket stream closed");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct H3ConnectionKey {
    server_addr: SocketAddr,
    server_name: String,
    fwmark: Option<u32>,
}

impl H3ConnectionKey {
    fn new(server_addr: SocketAddr, server_name: &str, fwmark: Option<u32>) -> Self {
        Self {
            server_addr,
            server_name: server_name.to_string(),
            fwmark,
        }
    }
}

struct SharedH3Connection {
    id: u64,
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
    _connection_guard: H3ConnectionGuard,
    _driver_task: AbortOnDrop,
}

impl SharedH3Connection {
    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.connection.close_reason().is_none()
    }

    async fn open_websocket(
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
            self.closed.store(true, Ordering::Relaxed);
            anyhow!(
                "HTTP/3 websocket CONNECT request timed out after {}s on shared connection",
                OPEN_WEBSOCKET_TIMEOUT.as_secs()
            )
        })??;

        let response = timeout(OPEN_WEBSOCKET_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| {
                self.closed.store(true, Ordering::Relaxed);
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

impl crate::transport::SharedConnectionHealth for SharedH3Connection {
    fn is_open(&self) -> bool {
        self.is_open()
    }
}

// ── TLS / QUIC client configs (initialised once) ─────────────────────────────

use rustls::{ClientConfig, RootCertStore};
use std::sync::OnceLock;
use webpki_roots::TLS_SERVER_ROOTS;

static H3_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
static H3_QUIC_CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();

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
static H3_SHARED_CONNECTIONS: OnceCell<Mutex<HashMap<H3ConnectionKey, Arc<SharedH3Connection>>>> =
    OnceCell::new();
static H3_SHARED_CONNECTION_IDS: AtomicU64 = AtomicU64::new(1);
// Per-server-key mutex that serialises concurrent QUIC connection establishment.
// Without this, when the shared QUIC connection drops and N sessions try to
// reconnect simultaneously, each starts its own QUIC handshake (thundering herd).
// With the lock: the first waiter establishes the connection and caches it; the
// rest re-check the cache after acquiring the lock and reuse the result.
// The HashMap entries are never removed; they remain as empty Mutex<()> objects
// (a few bytes each) — acceptable because the set of unique server keys is small.
static H3_CONNECT_LOCKS: OnceCell<std::sync::Mutex<HashMap<H3ConnectionKey, Arc<tokio::sync::Mutex<()>>>>> =
    OnceCell::new();

fn h3_connect_locks(
) -> &'static std::sync::Mutex<HashMap<H3ConnectionKey, Arc<tokio::sync::Mutex<()>>>> {
    H3_CONNECT_LOCKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn get_h3_connect_lock(key: &H3ConnectionKey) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = h3_connect_locks().lock().expect("H3_CONNECT_LOCKS poisoned");
    locks.entry(key.clone()).or_default().clone()
}

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

fn h3_shared_connections() -> &'static Mutex<HashMap<H3ConnectionKey, Arc<SharedH3Connection>>> {
    H3_SHARED_CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h3(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    if url.scheme() != "wss" {
        bail!("h3 websocket transport currently requires wss:// URLs");
    }

    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addrs =
        resolve_host_with_preference(host, port, "failed to resolve h3 websocket host", ipv6_first)
            .await?;
    if server_addrs.is_empty() {
        bail!("DNS resolution returned no addresses for {host}:{port}");
    }

    let path = websocket_path(url);
    let mut last_error = None;
    for server_addr in server_addrs {
        let connect_result = if should_reuse_h3_connection(source) {
            connect_h3_quic_reused(server_addr, host, &path, fwmark, source).await
        } else {
            connect_h3_quic_fresh(server_addr, host, &path, fwmark, source).await
        };
        match connect_result {
            Ok(ws) => return Ok(AnyWsStream::H3 { inner: ws }),
            Err(error) => last_error = Some(format!("{server_addr}: {error}")),
        }
    }

    Err(anyhow!(
        "failed to connect to any resolved h3 address for {host}:{port}: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

async fn connect_h3_quic_reused(
    server_addr: SocketAddr,
    server_name: &str,
    path: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<H3WsStream> {
    let key = H3ConnectionKey::new(server_addr, server_name, fwmark);

    // Fast path: reuse an already-established shared connection without locking.
    if let Some(shared) = cached_shared_h3_connection(&key).await {
        match shared.open_websocket(server_name, server_addr.port(), path).await {
            Ok(ws) => {
                crate::metrics::record_transport_connect(source, "h3", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_addr = %server_addr,
                    server_name,
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
        match shared.open_websocket(server_name, server_addr.port(), path).await {
            Ok(ws) => {
                crate::metrics::record_transport_connect(source, "h3", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_addr = %server_addr,
                    server_name,
                    error = %format!("{error:#}"),
                    "shared h3 connection (post-lock recheck) failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h3_connection_if_current(&key, shared.id).await;
            },
        }
    }

    let mut transport_guard = TransportConnectGuard::new(source, "h3");
    let shared =
        Arc::new(connect_h3_connection(server_addr, server_name, fwmark, Some(key.clone())).await?);
    let ws = shared.open_websocket(server_name, server_addr.port(), path).await?;
    transport_guard.finish("success");
    cache_shared_h3_connection(key, Arc::clone(&shared)).await;
    Ok(ws)
}

async fn connect_h3_quic_fresh(
    server_addr: SocketAddr,
    server_name: &str,
    path: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<H3WsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h3");
    let shared = Arc::new(connect_h3_connection(server_addr, server_name, fwmark, None).await?);
    let ws = shared.open_websocket(server_name, server_addr.port(), path).await?;
    connect_guard.finish("success");
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
    let driver_task = AbortOnDrop(tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Some(cache_key) = cache_key {
            invalidate_shared_h3_connection_if_current(&cache_key, id).await;
        }
        let err_text = err.to_string();
        if is_expected_h3_close(&err_text) {
            debug!("h3 connection closed: {err_text}");
        } else {
            error!("h3 connection error: {err_text}");
        }
    }));

    Ok(SharedH3Connection {
        id,
        endpoint,
        connection: connection_handle.clone(),
        send_request: Mutex::new(send_request),
        closed: AtomicBool::new(false),
        _connection_guard: H3ConnectionGuard(connection_handle),
        _driver_task: driver_task,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn should_reuse_h3_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
}

async fn cached_shared_h3_connection(key: &H3ConnectionKey) -> Option<Arc<SharedH3Connection>> {
    let mut shared = h3_shared_connections().lock().await;
    match shared.get(key).cloned() {
        Some(connection) if connection.is_open() => Some(connection),
        Some(_) => {
            shared.remove(key);
            None
        },
        None => None,
    }
}

async fn cache_shared_h3_connection(key: H3ConnectionKey, connection: Arc<SharedH3Connection>) {
    let mut shared = h3_shared_connections().lock().await;
    match shared.get(&key) {
        Some(existing) if existing.is_open() => {},
        _ => {
            shared.insert(key, connection);
        },
    }
}

async fn invalidate_shared_h3_connection_if_current(key: &H3ConnectionKey, id: u64) {
    let mut shared = h3_shared_connections().lock().await;
    if shared.get(key).is_some_and(|connection| connection.id == id) {
        shared.remove(key);
    }
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

fn websocket_h3_target_uri(host: &str, port: u16, path: &str) -> Result<Uri> {
    Uri::builder()
        .scheme("https")
        .authority(format_authority(host, Some(port)))
        .path_and_query(path)
        .build()
        .context("failed to build HTTP/3 websocket target URI")
}

// ── Message conversion (sockudo ↔ tungstenite) ────────────────────────────────

pub(crate) fn sockudo_to_tungstenite_message(message: SockudoMessage) -> Message {
    match message {
        SockudoMessage::Text(bytes) => {
            Message::Text(String::from_utf8_lossy(&bytes).into_owned().into())
        },
        SockudoMessage::Binary(bytes) => Message::Binary(bytes),
        SockudoMessage::Ping(bytes) => Message::Ping(bytes),
        SockudoMessage::Pong(bytes) => Message::Pong(bytes),
        SockudoMessage::Close(reason) => Message::Close(reason.map(sockudo_close_to_tungstenite)),
    }
}

pub(crate) fn tungstenite_to_sockudo_message(message: Message) -> Result<SockudoMessage, WsError> {
    match message {
        Message::Text(text) => Ok(SockudoMessage::Text(Bytes::copy_from_slice(text.as_bytes()))),
        Message::Binary(bytes) => Ok(SockudoMessage::Binary(bytes)),
        Message::Ping(bytes) => Ok(SockudoMessage::Ping(bytes)),
        Message::Pong(bytes) => Ok(SockudoMessage::Pong(bytes)),
        Message::Close(frame) => Ok(SockudoMessage::Close(frame.map(tungstenite_close_to_sockudo))),
        Message::Frame(_) => Err(WsError::Io(std::io::Error::other(
            "raw websocket frames are not supported by the h3 transport adapter",
        ))),
    }
}

pub(crate) fn sockudo_to_ws_error(error: sockudo_ws::Error) -> WsError {
    WsError::Io(std::io::Error::other(error.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_shared_connection_key_distinguishes_server_name_and_fwmark() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let base = H3ConnectionKey::new(addr, "example.com", None);

        assert_eq!(base, H3ConnectionKey::new(addr, "example.com", None));
        assert_ne!(base, H3ConnectionKey::new(addr, "example.net", None));
        assert_ne!(base, H3ConnectionKey::new(addr, "example.com", Some(100)));
    }

    #[test]
    fn probe_sources_do_not_reuse_shared_h3_connections() {
        assert!(should_reuse_h3_connection("socks_tcp"));
        assert!(should_reuse_h3_connection("standby_udp"));
        assert!(!should_reuse_h3_connection("probe_ws"));
        assert!(!should_reuse_h3_connection("probe_http"));
    }
}
