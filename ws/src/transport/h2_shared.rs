use std::collections::HashMap;
use std::net::SocketAddr;
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
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::{debug, error};
use url::Url;

use super::AnyWsStream;
use super::dns::resolve_host_with_preference;
use super::guards::{AbortOnDrop, TransportConnectGuard};
use super::h2_io::{H2Io, connect_tls_h2, h2_connection_window_size, h2_stream_window_size};
use super::socket::connect_tcp_socket;
use super::url_util::websocket_target_uri;
use super::ws_stream::H2WsStream;

type H2SendRequestHandle = http2::SendRequest<Empty<Bytes>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct H2ConnectionKey {
    server_addr: SocketAddr,
    server_name: String,
    secure: bool,
    fwmark: Option<u32>,
}

impl H2ConnectionKey {
    fn new(server_addr: SocketAddr, server_name: &str, secure: bool, fwmark: Option<u32>) -> Self {
        Self {
            server_addr,
            server_name: server_name.to_string(),
            secure,
            fwmark,
        }
    }
}

struct SharedH2Connection {
    id: u64,
    send_request: Mutex<H2SendRequestHandle>,
    closed: Arc<AtomicBool>,
    _driver_task: AbortOnDrop,
}

impl SharedH2Connection {
    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    async fn open_websocket(self: &Arc<Self>, target_uri: &str) -> Result<AnyWsStream> {
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

        let response_future = {
            let mut send_request = self.send_request.lock().await;
            send_request
                .ready()
                .await
                .context("shared h2 connection is not ready for a new websocket CONNECT")?;
            send_request.send_request(request)
        };

        let mut response = response_future
            .await
            .context("failed to send HTTP/2 websocket CONNECT request")?;
        if !response.status().is_success() {
            bail!("HTTP/2 websocket CONNECT failed with status {}", response.status());
        }

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .context("failed to upgrade HTTP/2 websocket stream")?;
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
        let shared_connection: Arc<dyn Send + Sync> = self.clone();
        Ok(AnyWsStream::H2 {
            inner: H2WsStream::new_shared(ws, shared_connection),
        })
    }
}

static H2_SHARED_CONNECTIONS: OnceLock<Mutex<HashMap<H2ConnectionKey, Arc<SharedH2Connection>>>> =
    OnceLock::new();
static H2_SHARED_CONNECTION_IDS: AtomicU64 = AtomicU64::new(1);

fn h2_shared_connections() -> &'static Mutex<HashMap<H2ConnectionKey, Arc<SharedH2Connection>>> {
    H2_SHARED_CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) async fn connect_websocket_h2(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
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
    let secure = match url.scheme() {
        "ws" => false,
        "wss" => true,
        scheme => bail!("unsupported scheme for h2 websocket: {scheme}"),
    };
    let target_uri = websocket_target_uri(url)?;

    if should_reuse_h2_connection(source) {
        connect_h2_reused(server_addr, host, secure, &target_uri, fwmark, source).await
    } else {
        connect_h2_fresh(server_addr, host, secure, &target_uri, fwmark, source).await
    }
}

async fn connect_h2_reused(
    server_addr: SocketAddr,
    server_name: &str,
    secure: bool,
    target_uri: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<AnyWsStream> {
    let key = H2ConnectionKey::new(server_addr, server_name, secure, fwmark);

    if let Some(shared) = cached_shared_h2_connection(&key).await {
        match shared.open_websocket(target_uri).await {
            Ok(ws) => {
                crate::metrics::record_transport_connect(source, "h2", "reused");
                return Ok(ws);
            },
            Err(error) => {
                debug!(
                    server_addr = %server_addr,
                    server_name,
                    secure,
                    error = %format!("{error:#}"),
                    "cached shared h2 connection failed to open websocket stream; reconnecting"
                );
                invalidate_shared_h2_connection_if_current(&key, shared.id).await;
            },
        }
    }

    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let shared = Arc::new(
        connect_h2_connection(server_addr, server_name, secure, fwmark, Some(key.clone())).await?,
    );
    let ws = shared.open_websocket(target_uri).await?;
    connect_guard.finish("success");
    cache_shared_h2_connection(key, Arc::clone(&shared)).await;
    Ok(ws)
}

async fn connect_h2_fresh(
    server_addr: SocketAddr,
    server_name: &str,
    secure: bool,
    target_uri: &str,
    fwmark: Option<u32>,
    source: &'static str,
) -> Result<AnyWsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let shared =
        Arc::new(connect_h2_connection(server_addr, server_name, secure, fwmark, None).await?);
    let ws = shared.open_websocket(target_uri).await?;
    connect_guard.finish("success");
    Ok(ws)
}

async fn connect_h2_connection(
    server_addr: SocketAddr,
    server_name: &str,
    secure: bool,
    fwmark: Option<u32>,
    cache_key: Option<H2ConnectionKey>,
) -> Result<SharedH2Connection> {
    let io = if secure {
        H2Io::Tls {
            inner: connect_tls_h2(server_addr, server_name, fwmark).await?,
        }
    } else {
        H2Io::Plain {
            inner: connect_tcp_socket(server_addr, fwmark).await?,
        }
    };

    let (send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .initial_stream_window_size(Some(h2_stream_window_size()))
        .initial_connection_window_size(Some(h2_connection_window_size()))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(20))
        .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
        .await
        .context("HTTP/2 handshake failed")?;

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
        send_request: Mutex::new(send_request),
        closed,
        _driver_task: driver_task,
    })
}

fn should_reuse_h2_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
}

async fn cached_shared_h2_connection(key: &H2ConnectionKey) -> Option<Arc<SharedH2Connection>> {
    let mut shared = h2_shared_connections().lock().await;
    match shared.get(key).cloned() {
        Some(connection) if connection.is_open() => Some(connection),
        Some(_) => {
            shared.remove(key);
            None
        },
        None => None,
    }
}

async fn cache_shared_h2_connection(key: H2ConnectionKey, connection: Arc<SharedH2Connection>) {
    let mut shared = h2_shared_connections().lock().await;
    match shared.get(&key) {
        Some(existing) if existing.is_open() => {},
        _ => {
            shared.insert(key, connection);
        },
    }
}

async fn invalidate_shared_h2_connection_if_current(key: &H2ConnectionKey, id: u64) {
    let mut shared = h2_shared_connections().lock().await;
    if shared.get(key).is_some_and(|connection| connection.id == id) {
        shared.remove(key);
    }
}

fn is_expected_h2_close(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("operation was canceled")
        || error.contains("operation was cancelled")
}

#[cfg(test)]
mod tests {
    use super::{H2ConnectionKey, should_reuse_h2_connection};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn h2_shared_connection_key_distinguishes_scheme_server_name_and_fwmark() {
        let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
        let base = H2ConnectionKey::new(server_addr, "one.example", true, None);

        assert_ne!(base, H2ConnectionKey::new(server_addr, "two.example", true, None));
        assert_ne!(base, H2ConnectionKey::new(server_addr, "one.example", false, None));
        assert_ne!(base, H2ConnectionKey::new(server_addr, "one.example", true, Some(42)));
    }

    #[test]
    fn probe_sources_do_not_reuse_shared_h2_connections() {
        assert!(should_reuse_h2_connection("direct"));
        assert!(should_reuse_h2_connection("standby_tcp"));
        assert!(!should_reuse_h2_connection("probe_ws"));
        assert!(!should_reuse_h2_connection("probe_http"));
    }
}
