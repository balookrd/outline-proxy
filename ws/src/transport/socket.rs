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
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::error;
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use super::dns::resolve_host_with_preference;
use super::guards::{AbortOnDrop, TransportConnectGuard};
use super::stream::{AnyWsStream, H1WsStream, H2WsStream};

// ── H2 flow-control statics ────────────────────────────────────────────────────

// HTTP/2 flow-control window sizes. Defaults match the sizing used by
// sockudo-ws so the long-lived CONNECT stream carrying UDP datagrams does not
// stall on the small RFC default window under sustained downstream traffic.
// On memory-constrained routers these can be reduced via [h2] in config.toml.
static H2_INITIAL_STREAM_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();
static H2_INITIAL_CONNECTION_WINDOW_SIZE: OnceLock<u32> = OnceLock::new();

pub(crate) static UDP_RECV_BUF_BYTES: OnceLock<usize> = OnceLock::new();
pub(crate) static UDP_SEND_BUF_BYTES: OnceLock<usize> = OnceLock::new();

static H2_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

/// Maximum time to wait for a TCP handshake to the upstream server to complete.
/// Prevents connections from hanging for the OS default (~2 min) when the server
/// is unreachable or the router's conntrack table is exhausted.
pub(super) const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Public init functions ──────────────────────────────────────────────────────

/// Initialise H2 window sizes from config. Must be called before the first
/// outbound H2 connection is opened. Safe to call multiple times with the same
/// values; panics if called with different values after initialization.
pub fn init_h2_window_sizes(stream: u32, connection: u32) {
    H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| stream);
    H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| connection);
}

/// Initialise UDP socket buffer overrides from config. When set, every UDP
/// socket created by `bind_udp_socket` will request the given buffer sizes
/// from the kernel via `SO_RCVBUF` / `SO_SNDBUF`. The kernel may silently
/// cap the value to `/proc/sys/net/core/rmem_max` (Linux). `None` leaves
/// the kernel default unchanged.
pub fn init_udp_socket_bufs(recv: Option<usize>, send: Option<usize>) {
    if let Some(v) = recv {
        UDP_RECV_BUF_BYTES.get_or_init(|| v);
    }
    if let Some(v) = send {
        UDP_SEND_BUF_BYTES.get_or_init(|| v);
    }
}

// ── Private helpers ────────────────────────────────────────────────────────────

fn h2_stream_window_size() -> u32 {
    *H2_INITIAL_STREAM_WINDOW_SIZE.get_or_init(|| 1024 * 1024)
}

fn h2_connection_window_size() -> u32 {
    *H2_INITIAL_CONNECTION_WINDOW_SIZE.get_or_init(|| 2 * 1024 * 1024)
}

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

// ── H2Io ──────────────────────────────────────────────────────────────────────

pin_project! {
    #[project = H2IoProj]
    pub(super) enum H2Io {
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

// ── WebSocket connectors ───────────────────────────────────────────────────────

pub(super) async fn connect_websocket_http1(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<H1WsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "http1");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
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
    let (ws_stream, _) = tokio_tungstenite::client_async_tls(url.as_str(), tcp)
        .await
        .context("HTTP/1 websocket handshake failed")?;
    connect_guard.finish("success");
    Ok(ws_stream)
}

pub(super) async fn connect_websocket_h2(
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    let mut connect_guard = TransportConnectGuard::new(source, "h2");
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr = resolve_host_with_preference(
        host,
        port,
        "failed to resolve h2 websocket host",
        ipv6_first,
    )
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
        bail!(
            "HTTP/2 websocket CONNECT failed with status {}",
            response.status()
        );
    }

    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .context("failed to upgrade HTTP/2 websocket stream")?;
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    connect_guard.finish("success");
    Ok(AnyWsStream::H2 {
        inner: H2WsStream {
            inner: ws,
            driver_task,
        },
    })
}

pub(super) async fn connect_tls_h2(
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

// ── TCP socket ────────────────────────────────────────────────────────────────

pub(super) async fn connect_tcp_socket(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    // For connections without fwmark use tokio's async connector so we never
    // block a Tokio worker thread waiting for the TCP handshake to complete.
    if fwmark.is_none() {
        let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .with_context(|| format!("TCP connect to {addr} timed out"))?
            .with_context(|| format!("failed to connect TCP socket to {addr}"))?;
        configure_tcp_stream_low_latency(&stream, addr)?;
        return Ok(stream);
    }
    connect_tcp_socket_with_fwmark(addr, fwmark).await
}

/// fwmark variant: needs SO_MARK set on the raw socket before connect, which
/// requires socket2.  Only supported on Linux; on other platforms apply_fwmark
/// returns Err before we reach the connect logic.
#[cfg(target_os = "linux")]
async fn connect_tcp_socket_with_fwmark(
    addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(addr),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )
    .context("failed to create TCP socket")?;
    apply_fwmark(&socket, fwmark)?;
    // Set non-blocking BEFORE connect so that the handshake is driven by tokio
    // instead of blocking the current thread.
    socket
        .set_nonblocking(true)
        .context("failed to set TCP socket nonblocking")?;
    // Non-blocking connect: returns EINPROGRESS while the handshake is in flight.
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e)
            if e.raw_os_error() == Some(libc::EINPROGRESS)
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            // Connection in progress; writable() below will signal completion.
        }
        Err(e) => return Err(e).with_context(|| format!("failed to connect TCP socket to {addr}")),
    }
    let stream =
        TcpStream::from_std(socket.into()).context("failed to adopt TCP socket into tokio")?;
    // Yield to the runtime until the OS signals that the socket is writable,
    // which means the three-way handshake completed (or failed).
    tokio::time::timeout(TCP_CONNECT_TIMEOUT, stream.writable())
        .await
        .with_context(|| format!("TCP connect to {addr} timed out"))?
        .with_context(|| format!("failed waiting for TCP connect to {addr}"))?;
    // Retrieve the actual connect result via getsockopt(SO_ERROR).
    if let Some(err) = stream
        .take_error()
        .context("failed to retrieve TCP socket error")?
    {
        return Err(err).with_context(|| format!("TCP connection to {addr} failed"));
    }
    configure_tcp_stream_low_latency(&stream, addr)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
async fn connect_tcp_socket_with_fwmark(
    _addr: SocketAddr,
    _fwmark: Option<u32>,
) -> Result<TcpStream> {
    bail!("fwmark is only supported on Linux")
}

// ── UDP socket ────────────────────────────────────────────────────────────────

pub(crate) fn bind_udp_socket(
    bind_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )
    .context("failed to create UDP socket")?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    apply_fwmark(&socket, fwmark)?;
    if let Some(&size) = UDP_RECV_BUF_BYTES.get() {
        let _ = socket.set_recv_buffer_size(size);
    }
    if let Some(&size) = UDP_SEND_BUF_BYTES.get() {
        let _ = socket.set_send_buffer_size(size);
    }
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket nonblocking")?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?;
    Ok(socket.into())
}

fn configure_tcp_stream_low_latency(stream: &TcpStream, addr: SocketAddr) -> Result<()> {
    stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for {addr}"))
}

fn apply_fwmark(socket: &Socket, fwmark: Option<u32>) -> Result<()> {
    let Some(mark) = fwmark else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let value = mark as libc::c_uint;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to apply SO_MARK={mark}"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _mark = mark;
        let _ = socket;
        bail!("fwmark is only supported on Linux")
    }
}

// ── URL / authority helpers ───────────────────────────────────────────────────

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

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
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

pub(crate) fn bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_tcp_socket_enables_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });

        let stream = connect_tcp_socket(addr, None).await.unwrap();
        assert!(stream.nodelay().unwrap());

        drop(stream);
        server.await.unwrap();
    }
}
