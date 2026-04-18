use super::connect::configure_tcp_stream;
use super::shutdown::ShutdownSignal;
use super::transport::{
    ROOT_HTTP_AUTH_COOKIE_NAME, ROOT_HTTP_AUTH_COOKIE_TTL_SECS, ROOT_HTTP_AUTH_MAX_FAILURES,
    escape_http_auth_realm, handle_tcp_h3_connection, handle_udp_h3_connection,
    is_benign_ws_disconnect, is_normal_h3_shutdown, metrics_handler, not_found_handler,
    parse_failed_root_auth_attempts, parse_root_http_auth_password, password_matches_any_user,
    root_http_auth_handler,
};
use super::*;
use axum::http::{self, header};
use h3::server::Connection as H3Connection;
use sockudo_ws::{Role as H3Role, build_extended_connect_error, build_extended_connect_response};

pub(super) fn build_app(
    users: Arc<[UserKey]>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    http_root_auth: bool,
    http_root_realm: String,
) -> Router {
    let state = AppState {
        users,
        tcp_routes: tcp_routes.clone(),
        udp_routes: udp_routes.clone(),
        metrics,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream,
        http_root_auth,
        http_root_realm: Arc::from(http_root_realm),
    };
    let mut router = Router::new();

    if http_root_auth {
        router = router.route("/", any(root_http_auth_handler));
    }

    for path in tcp_routes.keys() {
        router = router.route(path, any(tcp_websocket_upgrade));
    }

    for path in udp_routes.keys() {
        router = router.route(path, any(udp_websocket_upgrade));
    }

    router.fallback(any(not_found_handler)).with_state(state)
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
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(endpoint, ws_config))
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
        // Send QUIC PING frames from the server side so that NAT mappings and
        // stateful firewalls stay alive even when only the server is sending
        // data.  Without this, a one-directional idle on the client→server path
        // can expire a NAT mapping and the server's own idle timer fires after
        // H3_QUIC_IDLE_TIMEOUT_SECS, killing all multiplexed WebSocket sessions.
        .keep_alive_interval(Some(Duration::from_secs(H3_QUIC_PING_INTERVAL_SECS)))
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
    shutdown: ShutdownSignal,
) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config.as_ref())?;
        serve_tls_listener(listener, app, acceptor, shutdown).await
    } else {
        serve_listener(listener, app, shutdown).await
    }
}

pub(super) async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    users: Arc<[UserKey]>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    http_root_auth: bool,
    http_root_realm: String,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let http_root_realm: Arc<str> = Arc::from(http_root_realm);
    let (endpoint, ws_config) = server.into_parts();

    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("HTTP/3 endpoint stopping on shutdown signal");
                // Stop accepting new connections and politely close existing
                // ones. `close` is synchronous; the runtime eventually
                // reclaims the QUIC state.
                endpoint.close(quinn::VarInt::from_u32(0), b"server shutting down");
                break;
            }
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
        let users = users.clone();
        let tcp_routes = tcp_routes.clone();
        let udp_routes = udp_routes.clone();
        let metrics = metrics.clone();
        let tcp_paths = tcp_paths.clone();
        let udp_paths = udp_paths.clone();
        let nat_table = Arc::clone(&nat_table);
        let dns_cache = Arc::clone(&dns_cache);
        let http_root_realm = Arc::clone(&http_root_realm);
        let ws_config = ws_config.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_h3_connection(
                incoming,
                users,
                tcp_routes,
                udp_routes,
                metrics,
                tcp_paths,
                udp_paths,
                nat_table,
                dns_cache,
                prefer_ipv4_upstream,
                http_root_auth,
                http_root_realm,
                ws_config,
            )
            .await
                && !is_normal_h3_shutdown(&error)
            {
                warn!(?error, "HTTP/3 connection terminated with error");
            }
        });
    }

    Ok(())
}

async fn handle_h3_connection(
    incoming: quinn::Incoming,
    users: Arc<[UserKey]>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    tcp_paths: BTreeSet<String>,
    udp_paths: BTreeSet<String>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    http_root_auth: bool,
    http_root_realm: Arc<str>,
    ws_config: H3WebSocketConfig,
) -> Result<()> {
    let connection = incoming
        .await
        .context("failed to accept incoming HTTP/3 connection")?;
    let mut h3_conn: H3Connection<h3_quinn::Connection, Bytes> =
        H3Connection::new(h3_quinn::Connection::new(connection))
            .await
            .context("failed to initialize HTTP/3 connection")?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (request, stream) = match resolver.resolve_request().await {
                    Ok(parts) => parts,
                    Err(error) => {
                        let error = anyhow!(error);
                        if !is_normal_h3_shutdown(&error) {
                            warn!(?error, "failed to resolve HTTP/3 request");
                        }
                        continue;
                    },
                };

                let users = users.clone();
                let tcp_routes = tcp_routes.clone();
                let udp_routes = udp_routes.clone();
                let metrics = metrics.clone();
                let tcp_paths = tcp_paths.clone();
                let udp_paths = udp_paths.clone();
                let nat_table = Arc::clone(&nat_table);
                let dns_cache = Arc::clone(&dns_cache);
                let http_root_realm = Arc::clone(&http_root_realm);
                let ws_config = ws_config.clone();

                tokio::spawn(async move {
                    if let Err(error) = handle_h3_request(
                        request,
                        stream,
                        users,
                        tcp_routes,
                        udp_routes,
                        metrics,
                        tcp_paths,
                        udp_paths,
                        nat_table,
                        dns_cache,
                        prefer_ipv4_upstream,
                        http_root_auth,
                        http_root_realm,
                        ws_config,
                    )
                    .await
                        && !is_normal_h3_shutdown(&error)
                    {
                        warn!(?error, "HTTP/3 request terminated with error");
                    }
                });
            },
            Ok(None) => break,
            Err(error) => {
                let error = anyhow!(error);
                if is_normal_h3_shutdown(&error) {
                    break;
                }
                return Err(error).context("failed to accept HTTP/3 request");
            },
        }
    }

    Ok(())
}

async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    users: Arc<[UserKey]>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    tcp_paths: BTreeSet<String>,
    udp_paths: BTreeSet<String>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    http_root_auth: bool,
    http_root_realm: Arc<str>,
    ws_config: H3WebSocketConfig,
) -> Result<()> {
    let path = request.uri().path().to_owned();

    if request.method() != Method::CONNECT {
        let response = h3_http_response(
            users.as_ref(),
            request.method(),
            &path,
            request.headers(),
            http_root_auth,
            http_root_realm.as_ref(),
        );
        stream
            .send_response(response)
            .await
            .context("failed to send HTTP/3 plain response")?;
        return Ok(());
    }

    let protocol_header = request
        .extensions()
        .get::<h3::ext::Protocol>()
        .map(|protocol: &h3::ext::Protocol| protocol.as_str().to_owned());

    let mut ws_req = H3ExtendedConnectRequest::from_request(&request)
        .ok_or_else(|| anyhow!("invalid HTTP/3 CONNECT request"))?;
    if ws_req.protocol.is_none() {
        ws_req.protocol = protocol_header;
    }

    if !tcp_paths.contains(ws_req.path.as_str()) && !udp_paths.contains(ws_req.path.as_str()) {
        stream
            .send_response(build_extended_connect_error(StatusCode::NOT_FOUND, Some("Not Found")))
            .await
            .context("failed to send HTTP/3 not found response")?;
        return Ok(());
    }

    if let Err(status) = ws_req.validate() {
        stream
            .send_response(build_extended_connect_error(status, None))
            .await
            .context("failed to send HTTP/3 websocket error response")?;
        return Ok(());
    }

    stream
        .send_response(build_extended_connect_response(None, None))
        .await
        .context("failed to send HTTP/3 websocket response")?;

    let h3_stream = H3Stream::<H3Transport>::from_h3_server(stream);
    let socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Server, ws_config);

    if tcp_paths.contains(ws_req.path.as_str()) {
        let route = tcp_routes
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
        let session = metrics.open_websocket_session(Transport::Tcp, Protocol::Http3);
        let outcome = match handle_tcp_h3_connection(
            socket,
            route.users,
            metrics.clone(),
            Arc::from(ws_req.path.as_str()),
            route.candidate_users,
            dns_cache,
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
            },
        };
        session.finish(outcome);
    } else if udp_paths.contains(ws_req.path.as_str()) {
        let route = udp_routes
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
        let session = metrics.open_websocket_session(Transport::Udp, Protocol::Http3);
        let outcome = match handle_udp_h3_connection(
            socket,
            route.users,
            metrics.clone(),
            Arc::from(ws_req.path.as_str()),
            route.candidate_users,
            nat_table,
            dns_cache,
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
            },
        };
        session.finish(outcome);
    }

    Ok(())
}

fn h3_http_response(
    users: &[UserKey],
    method: &Method,
    path: &str,
    headers: &axum::http::HeaderMap,
    http_root_auth: bool,
    http_root_realm: &str,
) -> http::Response<()> {
    if path != "/" || !http_root_auth || !(method == Method::GET || method == Method::HEAD) {
        return h3_not_found_response();
    }

    let failed_attempts = parse_failed_root_auth_attempts(headers);
    if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
        return h3_root_http_auth_forbidden_response();
    }

    match parse_root_http_auth_password(headers) {
        Some(password) if password_matches_any_user(users, &password) => {
            h3_root_http_auth_success_response()
        },
        Some(_) => {
            let failed_attempts = failed_attempts.saturating_add(1);
            if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
                h3_root_http_auth_forbidden_response()
            } else {
                h3_root_http_auth_challenge_response(failed_attempts, http_root_realm)
            }
        },
        None => h3_root_http_auth_challenge_response(failed_attempts, http_root_realm),
    }
}

fn h3_not_found_response() -> http::Response<()> {
    http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(())
        .expect("failed to build HTTP/3 not found response")
}

fn h3_root_http_auth_success_response() -> http::Response<()> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!("{ROOT_HTTP_AUTH_COOKIE_NAME}=0; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
        )
        .body(())
        .expect("failed to build HTTP/3 root auth success response")
}

fn h3_root_http_auth_challenge_response(failed_attempts: u8, realm: &str) -> http::Response<()> {
    http::Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            header::WWW_AUTHENTICATE,
            format!("Basic realm=\"{}\"", escape_http_auth_realm(realm)),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!(
                "{ROOT_HTTP_AUTH_COOKIE_NAME}={failed_attempts}; Path=/; Max-Age={ROOT_HTTP_AUTH_COOKIE_TTL_SECS}; HttpOnly; SameSite=Lax"
            ),
        )
        .body(())
        .expect("failed to build HTTP/3 root auth challenge response")
}

fn h3_root_http_auth_forbidden_response() -> http::Response<()> {
    http::Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!(
                "{ROOT_HTTP_AUTH_COOKIE_NAME}={ROOT_HTTP_AUTH_MAX_FAILURES}; Path=/; Max-Age={ROOT_HTTP_AUTH_COOKIE_TTL_SECS}; HttpOnly; SameSite=Lax"
            ),
        )
        .body(())
        .expect("failed to build HTTP/3 root auth forbidden response")
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

    let tls_config =
        load_server_tls_config(cert_path, key_path, &[b"h2".as_slice(), b"http/1.1".as_slice()])
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
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return Ok(vec![CertificateDer::from(pem)]);
    }

    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }

    rustls_pemfile::private_key(&mut key.as_slice())
        .with_context(|| format!("failed to parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

pub(super) async fn serve_listener(
    listener: TcpListener,
    app: Router,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = listener.tap_io(|stream| {
        if let Err(error) = configure_tcp_stream(stream) {
            warn!(?error, "failed to configure accepted http connection");
        }
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("server exited unexpectedly")
}

pub(super) async fn serve_metrics_listener(
    listener: TcpListener,
    app: Router,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("metrics server exited unexpectedly")
}

async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("TLS listener stopping on shutdown signal");
                return Ok(());
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(error) => {
                    warn!(?error, "failed to accept TLS tcp connection");
                    continue;
                },
            },
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
                    if is_benign_tls_handshake_error(&error) {
                        debug!(?error, %peer_addr, "tls handshake closed before completion");
                    } else {
                        warn!(?error, %peer_addr, "tls handshake failed");
                    }
                    return;
                },
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

fn is_benign_tls_handshake_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::UnexpectedEof
        || error.to_string().contains("tls handshake eof")
}

#[cfg(test)]
mod tests {
    use super::is_benign_tls_handshake_error;

    #[test]
    fn tls_handshake_unexpected_eof_is_benign() {
        let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
        assert!(is_benign_tls_handshake_error(&error));
    }

    #[test]
    fn tls_handshake_protocol_failure_is_not_benign() {
        let error = std::io::Error::other("received corrupt message");
        assert!(!is_benign_tls_handshake_error(&error));
    }
}
