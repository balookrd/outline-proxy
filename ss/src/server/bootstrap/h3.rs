use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Context, Result, anyhow};
use axum::http::{self, Method, StatusCode};
use bytes::Bytes;
use h3::server::Connection as H3Connection;
use sockudo_ws::{
    Config as H3WebSocketConfig, ExtendedConnectRequest as H3ExtendedConnectRequest,
    Http3 as H3Transport, Role as H3Role, Stream as H3Stream, WebSocketServer as H3WebSocketServer,
    WebSocketStream as H3WebSocketStream, build_extended_connect_error,
    build_extended_connect_response,
};
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::{
    config::{Config, TuningProfile},
    crypto::UserKey,
    metrics::{Protocol, Transport},
};

use super::super::{
    auth::{
        ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response,
        build_root_http_auth_challenge_response, build_root_http_auth_forbidden_response,
        build_root_http_auth_success_response, parse_failed_root_auth_attempts,
        parse_root_http_auth_password, password_matches_any_user,
    },
    constants::{H3_MAX_UDP_PAYLOAD_SIZE, H3_QUIC_IDLE_TIMEOUT_SECS, H3_QUIC_PING_INTERVAL_SECS},
    state::{
        AuthPolicy, RoutesSnapshot, Services, empty_transport_route, empty_vless_transport_route,
    },
    transport::{
        UdpRouteCtx, UdpServerCtx, VlessWsRouteCtx, VlessWsServerCtx, WsTcpRouteCtx,
        WsTcpServerCtx, finish_ws_session, handle_tcp_h3_connection, handle_udp_h3_connection,
        handle_vless_h3_connection, is_normal_h3_shutdown,
    },
};
use super::tls::load_h3_tls_config;

pub(in crate::server) async fn build_h3_server(
    config: &Config,
) -> Result<H3WebSocketServer<H3Transport>> {
    let listen = config
        .effective_h3_listen()
        .ok_or_else(|| anyhow!("h3 server requested without tls configuration"))?;
    let profile = &config.tuning;
    let tls_config = load_h3_tls_config(config)?;
    let ws_config = build_h3_ws_config(profile);
    let server_config = build_h3_quinn_server_config(tls_config, profile)?;
    let socket = bind_h3_udp_socket(listen, profile)?;
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

fn build_h3_ws_config(profile: &TuningProfile) -> H3WebSocketConfig {
    H3WebSocketConfig::builder()
        .idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS as u32)
        .ping_interval(H3_QUIC_PING_INTERVAL_SECS as u32)
        .max_backpressure(profile.h3_max_backpressure_bytes)
        .write_buffer_size(profile.h3_write_buffer_bytes)
        .http3_idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS * 1_000)
        .http3_stream_window_size(profile.h3_stream_window_bytes)
        .http3_enable_connect_protocol(true)
        .http3_max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .build()
}

fn build_h3_quinn_server_config(
    tls_config: rustls::ServerConfig,
    profile: &TuningProfile,
) -> Result<quinn::ServerConfig> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow!("invalid HTTP/3 TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(build_h3_transport_config(profile)?));
    Ok(server_config)
}

fn build_h3_transport_config(profile: &TuningProfile) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(
            profile.h3_max_concurrent_bidi_streams,
        ))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(profile.h3_max_concurrent_uni_streams))
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
            u32::try_from(profile.h3_stream_window_bytes)
                .expect("h3_stream_window_bytes exceeds u32"),
        ))
        .receive_window(quinn::VarInt::from_u32(
            u32::try_from(profile.h3_connection_window_bytes)
                .expect("h3_connection_window_bytes exceeds u32"),
        ))
        .send_window(profile.h3_connection_window_bytes)
        .datagram_receive_buffer_size(Some(profile.h3_connection_window_bytes as usize))
        .datagram_send_buffer_size(profile.h3_connection_window_bytes as usize);
    Ok(transport)
}

fn bind_h3_udp_socket(
    listen: std::net::SocketAddr,
    profile: &TuningProfile,
) -> Result<std::net::UdpSocket> {
    let domain = if listen.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create HTTP/3 UDP socket")?;
    socket
        .set_recv_buffer_size(profile.h3_udp_socket_buffer_bytes)
        .context("failed to set HTTP/3 UDP receive buffer")?;
    if let Ok(actual) = socket.recv_buffer_size()
        && actual < profile.h3_udp_socket_buffer_bytes
    {
        tracing::warn!(
            requested = profile.h3_udp_socket_buffer_bytes,
            actual,
            "HTTP/3 UDP receive buffer capped by OS — increase net.core.rmem_max (Linux) \
             or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
        );
    }
    socket
        .set_send_buffer_size(profile.h3_udp_socket_buffer_bytes)
        .context("failed to set HTTP/3 UDP send buffer")?;
    if let Ok(actual) = socket.send_buffer_size()
        && actual < profile.h3_udp_socket_buffer_bytes
    {
        tracing::warn!(
            requested = profile.h3_udp_socket_buffer_bytes,
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

struct H3ConnectionCtx {
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    tcp_paths: Arc<BTreeSet<String>>,
    udp_paths: Arc<BTreeSet<String>>,
    vless_paths: Arc<BTreeSet<String>>,
    ws_config: H3WebSocketConfig,
    tcp_server: Arc<WsTcpServerCtx>,
    udp_server: Arc<UdpServerCtx>,
    vless_server: Arc<VlessWsServerCtx>,
}

pub(in crate::server) async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    mut shutdown: super::super::shutdown::ShutdownSignal,
) -> Result<()> {
    let initial = routes.load();
    let tcp_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.tcp.keys().cloned().collect::<BTreeSet<_>>());
    let udp_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.udp.keys().cloned().collect::<BTreeSet<_>>());
    let vless_paths: Arc<BTreeSet<String>> =
        Arc::new(initial.vless.keys().cloned().collect::<BTreeSet<_>>());
    drop(initial);
    let (endpoint, ws_config) = server.into_parts();
    let tcp_server = Arc::new(WsTcpServerCtx {
        metrics: services.metrics.clone(),
        dns_cache: Arc::clone(&services.dns_cache),
        prefer_ipv4_upstream: services.prefer_ipv4_upstream,
        outbound_ipv6: services.outbound_ipv6.clone(),
    });
    let udp_server = Arc::new(UdpServerCtx {
        metrics: services.metrics.clone(),
        nat_table: Arc::clone(&services.udp.nat_table),
        replay_store: Arc::clone(&services.udp.replay_store),
        dns_cache: Arc::clone(&services.dns_cache),
        prefer_ipv4_upstream: services.prefer_ipv4_upstream,
        relay_semaphore: services.udp.relay_semaphore.clone(),
    });
    let vless_server = Arc::new(VlessWsServerCtx {
        metrics: services.metrics.clone(),
        dns_cache: Arc::clone(&services.dns_cache),
        prefer_ipv4_upstream: services.prefer_ipv4_upstream,
        outbound_ipv6: services.outbound_ipv6.clone(),
    });

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
        let ctx = Arc::new(H3ConnectionCtx {
            routes: Arc::clone(&routes),
            services: Arc::clone(&services),
            auth: Arc::clone(&auth),
            tcp_paths: Arc::clone(&tcp_paths),
            udp_paths: Arc::clone(&udp_paths),
            vless_paths: Arc::clone(&vless_paths),
            ws_config: ws_config.clone(),
            tcp_server: Arc::clone(&tcp_server),
            udp_server: Arc::clone(&udp_server),
            vless_server: Arc::clone(&vless_server),
        });

        tokio::spawn(async move {
            if let Err(error) = handle_h3_connection(incoming, ctx).await
                && !is_normal_h3_shutdown(&error)
            {
                warn!(?error, "HTTP/3 connection terminated with error");
            }
        });
    }

    Ok(())
}

async fn handle_h3_connection(incoming: quinn::Incoming, ctx: Arc<H3ConnectionCtx>) -> Result<()> {
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

                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(error) = handle_h3_request(request, stream, ctx).await
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
    ctx: Arc<H3ConnectionCtx>,
) -> Result<()> {
    let path = request.uri().path().to_owned();

    if request.method() != Method::CONNECT {
        let users_snap = ctx.auth.users.load();
        let response = h3_http_response(
            users_snap.0.as_ref(),
            request.method(),
            &path,
            request.headers(),
            ctx.auth.http_root_auth,
            ctx.auth.http_root_realm.as_ref(),
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

    if !ctx.tcp_paths.contains(ws_req.path.as_str())
        && !ctx.udp_paths.contains(ws_req.path.as_str())
        && !ctx.vless_paths.contains(ws_req.path.as_str())
    {
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
    let socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Server, ctx.ws_config.clone());

    if ctx.tcp_paths.contains(ws_req.path.as_str()) {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .tcp
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
        let session = ctx
            .services
            .metrics
            .open_websocket_session(Transport::Tcp, Protocol::Http3);
        let route_ctx = WsTcpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
        };
        let result = handle_tcp_h3_connection(socket, Arc::clone(&ctx.tcp_server), route_ctx).await;
        finish_ws_session(session, result, "tcp");
    } else if ctx.udp_paths.contains(ws_req.path.as_str()) {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .udp
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
        let session = ctx
            .services
            .metrics
            .open_websocket_session(Transport::Udp, Protocol::Http3);
        let route_ctx = Arc::new(UdpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
        });
        let result = handle_udp_h3_connection(socket, Arc::clone(&ctx.udp_server), route_ctx).await;
        finish_ws_session(session, result, "udp");
    } else if ctx.vless_paths.contains(ws_req.path.as_str()) {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .vless
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_vless_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming vless websocket upgrade");
        let session = ctx
            .services
            .metrics
            .open_websocket_session(Transport::Tcp, Protocol::Http3);
        let route_ctx = VlessWsRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
        };
        let result =
            handle_vless_h3_connection(socket, Arc::clone(&ctx.vless_server), route_ctx).await;
        finish_ws_session(session, result, "vless");
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
        return build_not_found_response(());
    }

    let failed_attempts = parse_failed_root_auth_attempts(headers);
    if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
        return build_root_http_auth_forbidden_response(());
    }

    match parse_root_http_auth_password(headers) {
        Some(password) if password_matches_any_user(users, &password) => {
            build_root_http_auth_success_response(())
        },
        Some(_) => {
            let failed_attempts = failed_attempts.saturating_add(1);
            if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
                build_root_http_auth_forbidden_response(())
            } else {
                build_root_http_auth_challenge_response(failed_attempts, http_root_realm, ())
            }
        },
        None => build_root_http_auth_challenge_response(failed_attempts, http_root_realm, ()),
    }
}
