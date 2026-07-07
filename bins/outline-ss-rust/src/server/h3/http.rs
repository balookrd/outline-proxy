use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::http::{self, Method, StatusCode};
use bytes::Bytes;
use h3::server::Connection as H3Connection;
use outline_wire::xhttp::{SsPathKind, decode_kind};
use tracing::{debug, warn};

use super::super::{
    auth::{
        ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response,
        build_root_http_auth_challenge_response, build_root_http_auth_forbidden_response,
        build_root_http_auth_success_response, parse_failed_root_auth_attempts,
        parse_root_http_auth_password, password_matches_any_user,
    },
    cluster::{RouteDecision, mesh::CarrierKind},
    state::{empty_transport_route, empty_vless_transport_route},
    transport::{
        ResumeContext, ResumeResponseEcho, UdpRouteCtx, VlessWsRouteCtx, WsTcpRouteCtx, XhttpH3Ctx,
        XhttpRoute, edge_route, finish_ws_session, generate_anonymous_xhttp_session_id,
        h3_fallback_handle, handle_tcp_h3_connection, handle_udp_h3_connection,
        handle_vless_h3_connection, handle_xhttp_h3_request, is_normal_h3_shutdown,
        mesh_relay::{edge_relay_h3, open_edge_relay},
    },
};
use super::H3ConnectionCtx;
use super::vendored::{
    self, H3ExtendedConnectRequest, build_extended_connect_error, build_extended_connect_response,
};
use crate::crypto::UserKey;
use crate::metrics::{AppProtocol, Protocol, Transport};

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
        // Try XHTTP first: GET/POST on `<base>/<id>` map to the
        // packet-up handler, where `<base>` is one of the known
        // xhttp paths. We do this before the plain-HTTP fallback
        // (auth challenge / 404) because XHTTP shares the GET
        // method with the root-auth handler, and confusing those
        // two would either expose the auth challenge to xhttp
        // clients or eat xhttp upgrade requests.
        if let Some((base, session_id, path_seq)) =
            match_xhttp_path(&path, ctx.xhttp_paths.as_ref())
            && let Some(route) = if ctx.xhttp_ss.contains_key(base.as_ref())
                && ctx.xhttp_ss_udp.contains_key(base.as_ref())
            {
                // Combined SS path (base in both tables): decode the hidden
                // tcp/udp bit from the session id, mirroring the axum
                // `resolve_route`. A missing / non-encoding id defaults to tcp.
                match session_id.as_deref().map(decode_kind).unwrap_or(SsPathKind::Tcp) {
                    SsPathKind::Tcp => ctx.xhttp_ss.get(base.as_ref()).cloned().map(XhttpRoute::Ss),
                    SsPathKind::Udp => {
                        ctx.xhttp_ss_udp.get(base.as_ref()).cloned().map(XhttpRoute::SsUdp)
                    },
                }
            } else {
                ctx.xhttp_vless
                    .get(base.as_ref())
                    .cloned()
                    .map(XhttpRoute::Vless)
                    .or_else(|| ctx.xhttp_ss.get(base.as_ref()).cloned().map(XhttpRoute::Ss))
                    .or_else(|| ctx.xhttp_ss_udp.get(base.as_ref()).cloned().map(XhttpRoute::SsUdp))
            }
        {
            // `match_xhttp_path` returns `session_id = None` for the
            // bare-`<base>` shape (xray's sessionless stream-one
            // form). Mint a fresh server-side id here so every code
            // path further in still sees a non-empty `String` —
            // mirrors what `xhttp_handler_no_session` does on the
            // axum side.
            let session_id = session_id.unwrap_or_else(generate_anonymous_xhttp_session_id);
            let xhttp_ctx = XhttpH3Ctx {
                registry: Arc::clone(&ctx.xhttp_registry),
                services: Arc::clone(&ctx.services),
                route,
                base_path: base,
                cluster: ctx.cluster.clone(),
            };
            return handle_xhttp_h3_request(
                request, stream, xhttp_ctx, session_id, path_seq, peer_addr,
            )
            .await;
        }

        // The auth-root challenge (when configured) takes priority
        // over the fallback for `/` — same precedence the axum router
        // applies on the TCP listener: `router.route("/", ...)` is
        // pinned ahead of the wildcard fallback. Without this, an
        // active `[http_fallback]` would swallow auth challenges.
        let is_root_auth = path == "/" && ctx.auth.http_root_auth;
        if !is_root_auth
            && let Some(fb) = ctx.http_fallback.as_ref()
            && fb.config.apply_to_h3
        {
            return h3_fallback_handle(request, stream, Arc::clone(fb), peer_addr).await;
        }

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

    let protocol_header = vendored::request_websocket_protocol(&request);

    let mut ws_req = H3ExtendedConnectRequest::from_request(&request)
        .ok_or_else(|| anyhow!("invalid HTTP/3 CONNECT request"))?;
    if ws_req.protocol.is_none() {
        ws_req.protocol = protocol_header;
    }

    // Combined WS path: an h3 CONNECT lands on `<base>/<token>`. When the
    // base is in both the tcp and udp tables, rewrite the request path to the
    // base and force the matching leg from the token's hidden bit — mirrors
    // the axum `combined_websocket_upgrade` and the XHTTP combined path above.
    let force_kind = match combined_ws_h3_base(&ws_req.path, &ctx.tcp_paths, &ctx.udp_paths) {
        Some((base, kind)) => {
            ws_req.path = base;
            Some(kind)
        },
        None => None,
    };
    let path_is_tcp = match force_kind {
        Some(kind) => kind == SsPathKind::Tcp,
        None => ctx.tcp_paths.contains(ws_req.path.as_str()),
    };
    let path_is_udp = match force_kind {
        Some(kind) => kind == SsPathKind::Udp,
        None => ctx.udp_paths.contains(ws_req.path.as_str()),
    };
    let path_is_vless = force_kind.is_none() && ctx.vless_paths.contains(ws_req.path.as_str());

    if !path_is_tcp && !path_is_udp && !path_is_vless {
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

    // Cluster edge: relay a foreign-shard SS-TCP / VLESS resume to its home
    // over the mesh. UDP has no mesh relay yet; combined-SS was already split
    // to a tcp/udp leg above. Checked before the local resume context; on relay
    // failure we fall through to a fresh local session (this edge becomes home).
    if path_is_tcp || path_is_vless {
        let registry = if path_is_tcp {
            &ctx.tcp_server.orphan_registry
        } else {
            &ctx.vless_server.orphan_registry
        };
        if let Some(cluster) = ctx.cluster.as_deref()
            && let (RouteDecision::Relay(shard), Some(advert)) =
                edge_route(request.headers(), registry.cluster_identity())
        {
            let (carrier, app_protocol, kind) = if path_is_tcp {
                (CarrierKind::SsTcp, AppProtocol::Shadowsocks, "tcp")
            } else {
                (CarrierKind::VlessTcp, AppProtocol::Vless, "vless")
            };
            if let Some(pooled) =
                open_edge_relay(cluster, shard, &advert, carrier, &ws_req.path, peer_addr).await
            {
                // Continuity: echo the id the client presented (the home parks
                // the relayed upstream under exactly that id).
                let mut response = build_extended_connect_response(None, None);
                ResumeResponseEcho {
                    session_id: Some(advert.session_id),
                    ..Default::default()
                }
                .apply(response.headers_mut());
                stream
                    .send_response(response)
                    .await
                    .context("failed to send HTTP/3 websocket response")?;
                let socket = vendored::server_ws_stream(stream, ctx.ws_config.clone());
                let metrics = if path_is_tcp {
                    &ctx.tcp_server.metrics
                } else {
                    &ctx.vless_server.metrics
                };
                let session =
                    metrics.open_websocket_session(Transport::Tcp, Protocol::Http3, app_protocol);
                let result = edge_relay_h3(socket, pooled, cluster.relay_budget).await;
                finish_ws_session(session, result, kind);
                return Ok(());
            }
            // Relay unavailable: fall through to a fresh local session.
        }
    }

    // Resume negotiation. Parse `X-Outline-*` headers up-front (cheap)
    // so we can both echo the assigned Session ID in the upgrade
    // response and pass the request side into the relay path. Each
    // proxy protocol owns its own registry handle (in practice they
    // point at the same underlying `Arc<OrphanRegistry>`); we pick the
    // one that matches the path so the receiving relay queries the
    // intended registry.
    let resume = if path_is_tcp {
        ResumeContext::from_request_headers(request.headers(), &ctx.tcp_server.orphan_registry)
    } else if path_is_udp {
        ResumeContext::from_request_headers(request.headers(), &ctx.udp_server.orphan_registry)
    } else if path_is_vless {
        ResumeContext::from_request_headers(request.headers(), &ctx.vless_server.orphan_registry)
    } else {
        ResumeContext::default()
    };
    let mut response = build_extended_connect_response(None, None);
    // Mirror the h1/h2 upgrade paths: SS-WS and VLESS-WS confirm the v1/v2
    // capabilities so the client arms its ORSM/ORDR frame consumption (the
    // relay already emits them on a resume hit regardless of carrier — an
    // unconfirmed client would misread the control frames as payload). The
    // UDP datagram path echoes only the Session ID, as on h1/h2.
    let echo = if path_is_udp {
        resume.session_echo()
    } else {
        resume.response_echo()
    };
    echo.apply(response.headers_mut());

    stream
        .send_response(response)
        .await
        .context("failed to send HTTP/3 websocket response")?;

    let socket = vendored::server_ws_stream(stream, ctx.ws_config.clone());

    if path_is_tcp {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .tcp
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
        let session = ctx.tcp_server.metrics.open_websocket_session(
            Transport::Tcp,
            Protocol::Http3,
            AppProtocol::Shadowsocks,
        );
        let route_ctx = WsTcpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
            peer_user_cache: Arc::clone(&route.peer_user_cache),
            padding: crate::server::transport::carrier_padding::scheme_for_path(
                ws_req.path.as_str(),
            ),
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
    } else if path_is_udp {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .udp
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
        let session = ctx.udp_server.metrics.open_websocket_session(
            Transport::Udp,
            Protocol::Http3,
            AppProtocol::Shadowsocks,
        );
        let route_ctx = Arc::new(UdpRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
            // For a combined-SS base, `ws_req.path` was rewritten to the base
            // above, so this resolves the same scheme as the TCP leg — the
            // combined UDP leg pads iff the base path is listed.
            padding: crate::server::transport::carrier_padding::scheme_for_path(&ws_req.path),
        });
        let result =
            handle_udp_h3_connection(socket, Arc::clone(&ctx.udp_server), route_ctx, resume).await;
        finish_ws_session(session, result, "udp");
    } else if path_is_vless {
        let routes_snap = ctx.routes.load();
        let route = routes_snap
            .vless
            .get(&ws_req.path)
            .cloned()
            .unwrap_or_else(empty_vless_transport_route);
        drop(routes_snap);
        debug!(method = "CONNECT", version = "HTTP/3", path = %ws_req.path, candidates = ?route.candidate_users, "incoming vless websocket upgrade");
        let session = ctx.vless_server.metrics.open_websocket_session(
            Transport::Tcp,
            Protocol::Http3,
            AppProtocol::Vless,
        );
        let route_ctx = VlessWsRouteCtx {
            users: Arc::clone(&route.users),
            protocol: Protocol::Http3,
            path: Arc::from(ws_req.path.as_str()),
            candidate_users: Arc::clone(&route.candidate_users),
            padding: crate::server::transport::carrier_padding::scheme_for_path(&ws_req.path),
            peer: Some(peer_addr.ip()),
        };
        let result =
            handle_vless_h3_connection(socket, Arc::clone(&ctx.vless_server), route_ctx, resume)
                .await;
        finish_ws_session(session, result, "vless");
    }

    Ok(())
}

/// Returns `Some((base, session_id, path_seq))` for any of:
/// - `<base>` or `<base>/` — `session_id = None`, `path_seq = None`.
///   xray / sing-box stream-one wire shape (the client passes
///   `sessionId=""` and the path is left at the base + optional
///   normalising slash); the caller mints a fresh server-side id.
/// - `<base>/<id>` — `path_seq = None` (every GET, every stream-one
///   POST that carries an explicit `?mode=stream-one`, and
///   packet-up POSTs from header-based-seq clients).
/// - `<base>/<id>/<seq>` — `path_seq = Some(seq)` (packet-up POSTs
///   from xray / sing-box-default clients that place `seq` in the
///   URL path, e.g. `happ`, `hiddify`, `v2rayN`).
///
/// Done with a linear scan — `xhttp_paths` is at most a few entries
/// in any realistic deployment, and the cost is dominated by the
/// per-request work that follows.
/// If `path` is `<base>/<token>` with `base` present in BOTH the tcp and udp
/// path sets (a combined WS base), returns the base and the tcp/udp kind the
/// token's first character encodes. The axum router handles this split via a
/// `/{token}` route shape; h3 matches CONNECT paths by hand, so it decodes
/// the segment here.
fn combined_ws_h3_base(
    path: &str,
    tcp_paths: &std::collections::BTreeSet<String>,
    udp_paths: &std::collections::BTreeSet<String>,
) -> Option<(String, SsPathKind)> {
    let (base, token) = path.rsplit_once('/')?;
    if base.is_empty() || token.is_empty() {
        return None;
    }
    (tcp_paths.contains(base) && udp_paths.contains(base))
        .then(|| (base.to_owned(), decode_kind(token)))
}

fn match_xhttp_path(
    path: &str,
    xhttp_paths: &std::collections::BTreeSet<String>,
) -> Option<(std::sync::Arc<str>, Option<String>, Option<u64>)> {
    for base in xhttp_paths {
        let Some(rest) = path.strip_prefix(base.as_str()) else { continue };
        if rest.is_empty() || rest == "/" {
            // `<base>` or `<base>/` — sessionless stream-one shape.
            return Some((std::sync::Arc::from(base.as_str()), None, None));
        }
        let Some(rest) = rest.strip_prefix('/') else { continue };
        if rest.is_empty() {
            continue;
        }
        match rest.split_once('/') {
            None => {
                // `<base>/<id>` — single segment after base.
                return Some((std::sync::Arc::from(base.as_str()), Some(rest.to_owned()), None));
            },
            Some((id, tail)) => {
                // `<base>/<id>/<seq>` — `seq` must be a non-empty
                // u64 with no further path segments. Anything else
                // means the URL is not an XHTTP one and the caller
                // should fall through to 404 / fallback.
                if id.is_empty() || tail.is_empty() || tail.contains('/') {
                    continue;
                }
                let Ok(seq) = tail.parse::<u64>() else { continue };
                return Some((std::sync::Arc::from(base.as_str()), Some(id.to_owned()), Some(seq)));
            },
        }
    }
    None
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

#[cfg(test)]
#[path = "tests/http.rs"]
mod tests;
