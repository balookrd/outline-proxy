use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::http::{self, Method, StatusCode};
use bytes::Bytes;
use h3::server::Connection as H3Connection;
use sockudo_ws::{
    ExtendedConnectRequest as H3ExtendedConnectRequest, Http3 as H3Transport, Role as H3Role,
    Stream as H3Stream, WebSocketStream as H3WebSocketStream, build_extended_connect_error,
    build_extended_connect_response,
};
use tracing::{debug, warn};

use super::H3ConnectionCtx;
use super::super::{
    auth::{
        ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response,
        build_root_http_auth_challenge_response, build_root_http_auth_forbidden_response,
        build_root_http_auth_success_response, parse_failed_root_auth_attempts,
        parse_root_http_auth_password, password_matches_any_user,
    },
    state::{empty_transport_route, empty_vless_transport_route},
    transport::{
        ResumeContext, UdpRouteCtx, VlessWsRouteCtx, WsTcpRouteCtx, finish_ws_session,
        handle_tcp_h3_connection, handle_udp_h3_connection, handle_vless_h3_connection,
        is_normal_h3_shutdown,
    },
};
use crate::crypto::UserKey;
use crate::metrics::{Protocol, Transport};

pub(super) async fn handle_h3_connection(
    connection: quinn::Connection,
    ctx: Arc<H3ConnectionCtx>,
) -> Result<()> {
    let peer_addr = connection.remote_address();
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

                // Cap the total number of in-flight stream handlers across
                // all connections.  QUIC already bounds streams per
                // connection via `max_concurrent_bidi_streams`, but without
                // a global cap an attacker with many connections could
                // force `connections * streams_per_connection` task spawns.
                let stream_permit = match ctx.stream_semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };

                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    let _stream_permit = stream_permit;
                    if let Err(error) = handle_h3_request(request, stream, ctx, peer_addr).await
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
    peer_addr: std::net::SocketAddr,
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

    // Resume negotiation. Parse `X-Outline-*` headers up-front (cheap)
    // so we can both echo the assigned Session ID in the upgrade
    // response and pass the request side into the relay path. Each
    // proxy protocol owns its own registry handle (in practice they
    // point at the same underlying `Arc<OrphanRegistry>`); we pick the
    // one that matches the path so the receiving relay queries the
    // intended registry.
    let resume = if ctx.tcp_paths.contains(ws_req.path.as_str()) {
        ResumeContext::from_request_headers(request.headers(), &ctx.tcp_server.orphan_registry)
    } else if ctx.udp_paths.contains(ws_req.path.as_str()) {
        ResumeContext::from_request_headers(request.headers(), &ctx.udp_server.orphan_registry)
    } else if ctx.vless_paths.contains(ws_req.path.as_str()) {
        ResumeContext::from_request_headers(request.headers(), &ctx.vless_server.orphan_registry)
    } else {
        ResumeContext::default()
    };
    let mut response = build_extended_connect_response(None, None);
    resume.issue_session_header(response.headers_mut());

    stream
        .send_response(response)
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
            .tcp_server
            .metrics
            .open_websocket_session(Transport::Tcp, Protocol::Http3);
        let route_ctx = WsTcpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
            peer_user_cache: Arc::clone(&route.peer_user_cache),
        };
        let result = handle_tcp_h3_connection(
            socket,
            Arc::clone(&ctx.tcp_server),
            route_ctx,
            resume,
            Some(peer_addr),
        )
        .await;
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
            .udp_server
            .metrics
            .open_websocket_session(Transport::Udp, Protocol::Http3);
        let route_ctx = Arc::new(UdpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
        });
        let result =
            handle_udp_h3_connection(socket, Arc::clone(&ctx.udp_server), route_ctx, resume).await;
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
            .vless_server
            .metrics
            .open_websocket_session(Transport::Tcp, Protocol::Http3);
        let route_ctx = VlessWsRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
        };
        let result = handle_vless_h3_connection(
            socket,
            Arc::clone(&ctx.vless_server),
            route_ctx,
            resume,
        )
        .await;
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
