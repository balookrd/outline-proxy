use super::*;
use super::connect::configure_tcp_stream;
use super::transport::{
    handle_tcp_h3_connection, handle_udp_h3_connection, is_benign_ws_disconnect,
    is_normal_h3_shutdown, metrics_handler,
};

pub(super) fn build_app(
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Router {
    let state = AppState {
        tcp_routes: tcp_routes.clone(),
        udp_routes: udp_routes.clone(),
        metrics,
        nat_table,
        udp_dns_cache,
        prefer_ipv4_upstream,
    };
    let mut router = Router::new();

    for path in tcp_routes.keys() {
        router = router.route(path, any(tcp_websocket_upgrade));
    }

    for path in udp_routes.keys() {
        router = router.route(path, any(udp_websocket_upgrade));
    }

    router.with_state(state)
}

pub(super) fn build_metrics_app(metrics: Arc<Metrics>, metrics_path: String) -> Router {
    Router::new()
        .route(&metrics_path, any(metrics_handler))
        .with_state(metrics)
}

pub(super) async fn build_h3_server(config: &Config) -> Result<H3WebSocketServer<H3Transport>> {
    let listen = config
        .effective_h3_listen()
        .ok_or_else(|| anyhow!("h3 server requested without tls configuration"))?;
    let tls_config = load_h3_tls_config(config)?;
    let ws_config = build_h3_ws_config();
    let server_config = build_h3_quinn_server_config(tls_config)?;
    let socket = bind_h3_udp_socket(listen)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .context("invalid H3 max UDP payload size")?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("failed to create HTTP/3 QUIC endpoint")?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(
        endpoint, ws_config,
    ))
}

fn build_h3_ws_config() -> H3WebSocketConfig {
    H3WebSocketConfig::builder()
        .idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS as u32)
        .ping_interval(H3_QUIC_PING_INTERVAL_SECS as u32)
        .max_backpressure(H3_MAX_BACKPRESSURE_BYTES)
        .write_buffer_size(H3_WRITE_BUFFER_BYTES)
        .http3_idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS * 1_000)
        .http3_stream_window_size(H3_STREAM_WINDOW_BYTES)
        .http3_enable_connect_protocol(true)
        .http3_max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .build()
}

fn build_h3_quinn_server_config(tls_config: rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow!("invalid HTTP/3 TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(build_h3_transport_config()?));
    Ok(server_config)
}

fn build_h3_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(H3_MAX_CONCURRENT_BIDI_STREAMS))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(H3_MAX_CONCURRENT_UNI_STREAMS))
        .max_idle_timeout(Some(
            Duration::from_secs(H3_QUIC_IDLE_TIMEOUT_SECS)
                .try_into()
                .context("invalid HTTP/3 idle timeout")?,
        ))
        .stream_receive_window(quinn::VarInt::from_u32(
            u32::try_from(H3_STREAM_WINDOW_BYTES).expect("H3_STREAM_WINDOW_BYTES exceeds u32"),
        ))
        .receive_window(quinn::VarInt::from_u32(
            u32::try_from(H3_CONNECTION_WINDOW_BYTES)
                .expect("H3_CONNECTION_WINDOW_BYTES exceeds u32"),
        ))
        .send_window(H3_CONNECTION_WINDOW_BYTES)
        .datagram_receive_buffer_size(Some(H3_CONNECTION_WINDOW_BYTES as usize))
        .datagram_send_buffer_size(H3_CONNECTION_WINDOW_BYTES as usize);
    Ok(transport)
}

fn bind_h3_udp_socket(listen: std::net::SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if listen.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create HTTP/3 UDP socket")?;
    socket
        .set_recv_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES)
        .context("failed to set HTTP/3 UDP receive buffer")?;
    if let Ok(actual) = socket.recv_buffer_size()
        && actual < H3_UDP_SOCKET_BUFFER_BYTES
    {
        tracing::warn!(
            requested = H3_UDP_SOCKET_BUFFER_BYTES,
            actual,
            "HTTP/3 UDP receive buffer capped by OS — increase net.core.rmem_max (Linux) \
             or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
        );
    }
    socket
        .set_send_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES)
        .context("failed to set HTTP/3 UDP send buffer")?;
    if let Ok(actual) = socket.send_buffer_size()
        && actual < H3_UDP_SOCKET_BUFFER_BYTES
    {
        tracing::warn!(
            requested = H3_UDP_SOCKET_BUFFER_BYTES,
            actual,
            "HTTP/3 UDP send buffer capped by OS — increase net.core.wmem_max (Linux) \
             or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
        );
    }
    socket
        .bind(&socket2::SockAddr::from(listen))
        .with_context(|| format!("failed to bind HTTP/3 UDP socket {listen}"))?;
    let socket: std::net::UdpSocket = socket.into();
    socket
        .set_nonblocking(true)
        .context("failed to set HTTP/3 UDP socket nonblocking mode")?;
    Ok(socket)
}

pub(super) async fn serve_tcp_listener(
    listener: TcpListener,
    app: Router,
    config: Arc<Config>,
) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config.as_ref())?;
        serve_tls_listener(listener, app, acceptor).await
    } else {
        serve_listener(listener, app).await
    }
}

pub(super) async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let allowed_tcp = tcp_paths.clone();
    let allowed_udp = udp_paths.clone();

    server
        .serve_with_filter(
            move |req: &H3ExtendedConnectRequest| {
                allowed_tcp.contains(req.path.as_str()) || allowed_udp.contains(req.path.as_str())
            },
            move |socket, req| {
                let tcp_routes = tcp_routes.clone();
                let udp_routes = udp_routes.clone();
                let metrics = metrics.clone();
                let tcp_paths = tcp_paths.clone();
                let udp_paths = udp_paths.clone();
                let nat_table = Arc::clone(&nat_table);
                let udp_dns_cache = Arc::clone(&udp_dns_cache);
                async move {
                    if tcp_paths.contains(req.path.as_str()) {
                        let route = tcp_routes
                            .get(&req.path)
                            .cloned()
                            .unwrap_or_else(empty_transport_route);
                        debug!(method = "CONNECT", version = "HTTP/3", path = %req.path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
                        let session = metrics
                            .open_websocket_session(Transport::Tcp, Protocol::Http3);
                        let outcome = match handle_tcp_h3_connection(
                            socket,
                            route.users,
                            metrics.clone(),
                            req.path.clone(),
                            route.candidate_users,
                            prefer_ipv4_upstream,
                        )
                        .await
                        {
                            Ok(()) => DisconnectReason::Normal,
                            Err(error) => {
                                if is_normal_h3_shutdown(&error) {
                                    debug!(?error, "tcp websocket connection closed normally");
                                    DisconnectReason::Normal
                                } else if is_benign_ws_disconnect(&error) {
                                    debug!(?error, "tcp websocket connection closed abruptly");
                                    DisconnectReason::ClientDisconnect
                                } else {
                                    warn!(?error, "tcp websocket connection terminated with error");
                                    DisconnectReason::Error
                                }
                            }
                        };
                        session.finish(outcome);
                    } else if udp_paths.contains(req.path.as_str()) {
                        let route = udp_routes
                            .get(&req.path)
                            .cloned()
                            .unwrap_or_else(empty_transport_route);
                        debug!(method = "CONNECT", version = "HTTP/3", path = %req.path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
                        let session = metrics
                            .open_websocket_session(Transport::Udp, Protocol::Http3);
                        let outcome = match handle_udp_h3_connection(
                            socket,
                            route.users,
                            metrics.clone(),
                            req.path.clone(),
                            route.candidate_users,
                            nat_table,
                            udp_dns_cache,
                            prefer_ipv4_upstream,
                        )
                        .await
                        {
                            Ok(()) => DisconnectReason::Normal,
                            Err(error) => {
                                if is_normal_h3_shutdown(&error) {
                                    debug!(?error, "udp websocket connection closed normally");
                                    DisconnectReason::Normal
                                } else if is_benign_ws_disconnect(&error) {
                                    debug!(?error, "udp websocket connection closed abruptly");
                                    DisconnectReason::ClientDisconnect
                                } else {
                                    warn!(?error, "udp websocket connection terminated with error");
                                    DisconnectReason::Error
                                }
                            }
                        };
                        session.finish(outcome);
                    }
                }
            },
        )
        .await
        .context("HTTP/3 server exited unexpectedly")
}

fn load_h3_tls_config(config: &Config) -> Result<rustls::ServerConfig> {
    let cert_path = config
        .h3_cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing h3_cert_path"))?;
    let key_path = config
        .h3_key_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing h3_key_path"))?;

    load_server_tls_config(cert_path, key_path, &[b"h3".as_slice()])
        .context("failed to build HTTP/3 TLS config")
}

fn build_tcp_tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    let cert_path = config
        .tls_cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing tls_cert_path"))?;
    let key_path = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing tls_key_path"))?;

    let tls_config = load_server_tls_config(
        cert_path,
        key_path,
        &[b"h2".as_slice(), b"http/1.1".as_slice()],
    )
    .context("failed to build TCP TLS config")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn load_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
    alpn_protocols: &[&[u8]],
) -> Result<rustls::ServerConfig> {
    ensure_rustls_provider_installed();
    let certs = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = alpn_protocols.iter().map(|alpn| alpn.to_vec()).collect();
    Ok(tls_config)
}

pub(super) fn ensure_rustls_provider_installed() {
    static RUSTLS_PROVIDER: OnceLock<()> = OnceLock::new();
    RUSTLS_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
    {
        return Ok(vec![CertificateDer::from(pem)]);
    }

    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
    {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }

    rustls_pemfile::private_key(&mut key.as_slice())
        .with_context(|| format!("failed to parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

pub(super) async fn serve_listener(listener: TcpListener, app: Router) -> Result<()> {
    let listener = listener.tap_io(|stream| {
        if let Err(error) = configure_tcp_stream(stream) {
            warn!(?error, "failed to configure accepted http connection");
        }
    });
    axum::serve(listener, app)
        .await
        .context("server exited unexpectedly")
}

pub(super) async fn serve_metrics_listener(listener: TcpListener, app: Router) -> Result<()> {
    axum::serve(listener, app)
        .await
        .context("metrics server exited unexpectedly")
}

async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(error) => {
                warn!(?error, "failed to accept TLS tcp connection");
                continue;
            }
        };
        if let Err(error) = configure_tcp_stream(&stream) {
            warn!(%peer_addr, ?error, "failed to configure TLS tcp connection");
            continue;
        }
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(?error, %peer_addr, "tls handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(app);
            let builder = build_http_server_builder();

            if let Err(error) = builder.serve_connection_with_upgrades(io, service).await
                && !is_benign_http_serve_error(error.as_ref())
            {
                warn!(?error, %peer_addr, "tls http server connection terminated with error");
            }
        });
    }
}

fn build_http_server_builder() -> HyperBuilder<TokioExecutor> {
    let mut builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .initial_stream_window_size(Some(H2_STREAM_WINDOW_BYTES))
        .initial_connection_window_size(Some(H2_CONNECTION_WINDOW_BYTES))
        .max_send_buf_size(H2_MAX_SEND_BUF_SIZE)
        .keep_alive_interval(Some(Duration::from_secs(H2_KEEPALIVE_INTERVAL_SECS)))
        .keep_alive_timeout(Duration::from_secs(H2_KEEPALIVE_TIMEOUT_SECS));
    builder
}

fn is_benign_http_serve_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    let message = error.to_string();
    message.contains("connection closed")
        || message.contains("closed before message completed")
        || message.contains("canceled")
}
