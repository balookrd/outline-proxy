use super::auth::{
    ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response, build_root_http_auth_challenge_response,
    build_root_http_auth_forbidden_response, build_root_http_auth_success_response,
    parse_failed_root_auth_attempts, parse_root_http_auth_password, password_matches_any_user,
};

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{
        ConnectInfo, OriginalUri, Path, State,
        ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, Method, StatusCode, Version},
    response::{IntoResponse, Response},
};
use outline_wire::xhttp::{SsPathKind, decode_kind};
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, DisconnectReason, Metrics, Transport, WebSocketSessionGuard};

use super::h3::vendored::H3WsError;
use super::setup::protocol_from_http_version;
use super::state::{AppState, empty_transport_route, empty_vless_transport_route};

pub(in crate::server) mod carrier_padding;
mod fallback;
// The mesh carrier adapter is consumed by the home-side relay dispatch (later
// in phase 5c); not yet constructed by the runtime.
#[allow(dead_code)]
mod mesh_carrier;
mod proxy_protocol;
mod raw_quic;
mod resume_headers;
pub(in crate::server) mod sink;
pub(in crate::server) mod sni_fallback;
mod tcp;
pub(in crate::server) mod throughput_monitor;
mod udp;
mod vless;
mod vless_mux;
mod vless_udp;
mod ws_socket;
mod ws_writer;
mod xhttp;

pub(in crate::server) use fallback::{
    HttpFallbackContext, h3_fallback_handle, http_fallback_handler,
};
pub(in crate::server) use raw_quic::{
    OversizeStream, RawQuicSsCtx, RawQuicVlessRouteCtx, RawSsConnectionCtx, RawVlessConnectionCtx,
    SsQuicConn, StreamKind, VlessQuicConn, classify_accept_bi,
    handle_raw_ss_quic_stream_with_prefix, handle_raw_vless_quic_stream_with_prefix,
    serve_raw_ss_oversize_records, serve_raw_ss_quic_datagrams, serve_raw_vless_oversize_records,
    serve_raw_vless_quic_datagrams,
};
pub(in crate::server) use resume_headers::ResumeContext;
pub(in crate::server) use sink::is_handshake_rejected;
pub(in crate::server) use tcp::{WsTcpRouteCtx, WsTcpServerCtx, handle_tcp_h3_connection};
pub(in crate::server) use udp::{UdpRouteCtx, UdpServerCtx, handle_udp_h3_connection};
pub(in crate::server) use vless::{VlessWsRouteCtx, VlessWsServerCtx, handle_vless_h3_connection};
pub(in crate::server) use xhttp::{
    XhttpAppProtocol, XhttpAxumState, XhttpH3Ctx, XhttpRegistry, XhttpRoute,
    generate_anonymous_xhttp_session_id, handle_xhttp_h3_request, xhttp_handler,
    xhttp_handler_no_session, xhttp_handler_with_path_seq,
};

pub(super) async fn tcp_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let ConnectInfo(peer_addr) = connect_info;
    tcp_upgrade_for_path(ws, state, Arc::from(uri.path()), method, version, headers, peer_addr)
        .await
}

/// Core of the TCP-WS upgrade, parameterised by base path so both the
/// split-path handler above and the combined-path handler below can drive
/// it. The path is the **base** (no `/{token}` segment): split callers pass
/// the request path verbatim, the combined caller strips the token first.
async fn tcp_upgrade_for_path(
    ws: WebSocketUpgrade,
    state: AppState,
    path: Arc<str>,
    method: Method,
    version: Version,
    headers: HeaderMap,
    peer_addr: SocketAddr,
) -> Response {
    let protocol = protocol_from_http_version(version);
    let routes_snap = state.routes.load();
    let route = routes_snap
        .tcp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    drop(routes_snap);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let server = Arc::clone(&state.services.tcp_server);
    let session =
        server
            .metrics
            .open_websocket_session(Transport::Tcp, protocol, AppProtocol::Shadowsocks);
    let resume = ResumeContext::from_request_headers(&headers, &server.orphan_registry);
    // Captured by value before `resume` moves into the upgrade closure.
    // The echoed Session ID MUST be the one the relay later parks under —
    // re-parsing the headers would mint a different ID and silently
    // desynchronise the wire-side response from the server-side park
    // lookup. The v1/v2 capability echoes were already gated at parse
    // time; the actual control-frame emits gate on the resume hit.
    let echo = resume.response_echo();
    let mut response = ws.on_upgrade(move |socket| async move {
        let padding = carrier_padding::scheme_for_path(&path);
        let route_ctx = WsTcpRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
            peer_user_cache: Arc::clone(&route.peer_user_cache),
            padding,
        };
        let result =
            tcp::handle_tcp_connection(socket, server, route_ctx, resume, Some(peer_addr)).await;
        finish_ws_session(session, result, "tcp");
    });
    echo.apply(response.headers_mut());
    response
}

pub(super) async fn vless_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let ConnectInfo(peer_addr) = connect_info;
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let routes_snap = state.routes.load();
    let route = routes_snap
        .vless
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_vless_transport_route);
    drop(routes_snap);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming vless websocket upgrade");
    let server = Arc::clone(&state.services.vless_server);
    let session =
        server
            .metrics
            .open_websocket_session(Transport::Tcp, protocol, AppProtocol::Vless);
    let resume = ResumeContext::from_request_headers(&headers, &server.orphan_registry);
    // Captured by value before `resume` moves into the closure — see the
    // matching note in `tcp_websocket_upgrade`. VLESS-WS echoes the same
    // v1/v2 capabilities as the SS-WS path (v1.1).
    let echo = resume.response_echo();
    // Resolve the carrier-padding scheme before `path` moves into the closure.
    let padding = carrier_padding::scheme_for_path(&path);
    let mut response = ws.on_upgrade(move |socket| async move {
        let route_ctx = VlessWsRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
            padding,
            peer: Some(peer_addr.ip()),
        };
        let result = vless::handle_vless_connection(socket, server, route_ctx, resume).await;
        finish_ws_session(session, result, "vless");
    });
    echo.apply(response.headers_mut());
    response
}

pub(super) async fn root_http_auth_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if !state.auth.http_root_auth || !matches!(method, Method::GET | Method::HEAD) {
        return build_not_found_response(Body::empty());
    }

    let failed_attempts = parse_failed_root_auth_attempts(&headers);
    if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
        return build_root_http_auth_forbidden_response(Body::empty());
    }

    let users_snap = state.auth.users.load();
    match parse_root_http_auth_password(&headers) {
        Some(password) if password_matches_any_user(users_snap.0.as_ref(), &password) => {
            build_root_http_auth_success_response(Body::empty())
        },
        Some(_) => {
            let failed_attempts = failed_attempts.saturating_add(1);
            if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
                build_root_http_auth_forbidden_response(Body::empty())
            } else {
                build_root_http_auth_challenge_response(
                    failed_attempts,
                    state.auth.http_root_realm.as_ref(),
                    Body::empty(),
                )
            }
        },
        None => build_root_http_auth_challenge_response(
            failed_attempts,
            state.auth.http_root_realm.as_ref(),
            Body::empty(),
        ),
    }
}

pub(super) async fn not_found_handler() -> Response {
    build_not_found_response(Body::empty())
}

pub(super) async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics.render_prometheus(),
    )
}

pub(super) async fn udp_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    udp_upgrade_for_path(ws, state, Arc::from(uri.path()), method, version, headers).await
}

/// Core of the UDP-WS upgrade, parameterised by base path so the split-path
/// and combined-path handlers share it. Applies the zero write-buffer the
/// datagram path relies on.
async fn udp_upgrade_for_path(
    ws: WebSocketUpgrade,
    state: AppState,
    path: Arc<str>,
    method: Method,
    version: Version,
    headers: HeaderMap,
) -> Response {
    let ws = ws.write_buffer_size(0);
    let protocol = protocol_from_http_version(version);
    let routes_snap = state.routes.load();
    let route = routes_snap
        .udp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    drop(routes_snap);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let server = Arc::clone(&state.services.udp_server);
    let session =
        server
            .metrics
            .open_websocket_session(Transport::Udp, protocol, AppProtocol::Shadowsocks);
    let resume = ResumeContext::from_request_headers(&headers, &server.orphan_registry);
    // UDP-WS only echoes the Session ID — the v1/v2 replay protocols are
    // TCP-stream features and are not confirmed on datagram paths.
    let echo = resume.session_echo();
    let mut response = ws.on_upgrade(move |socket| async move {
        // Resolve the per-path padding scheme before `path` is moved into the
        // ctx. For a combined-SS base this is the base path (the combined UDP
        // leg reaches here via `udp_upgrade_for_path(base_path)`), so it pads
        // iff the base path is listed — the same scheme as the TCP leg.
        let padding = carrier_padding::scheme_for_path(&path);
        let route_ctx = Arc::new(UdpRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
            padding,
        });
        let result = udp::handle_udp_connection(socket, server, route_ctx, resume).await;
        finish_ws_session(session, result, "udp");
    });
    echo.apply(response.headers_mut());
    response
}

/// Combined-path WS upgrade: TCP and UDP share one base path, and the client
/// encodes which leg it wants into the first character of the `/{token}`
/// segment (see [`outline_wire::xhttp::SsPathKind`]). Decode the bit, strip
/// the token to recover the base path, and hand off to the same per-leg core
/// the split-path handlers use.
#[allow(clippy::too_many_arguments)] // axum extractors, like the other upgrade handlers
pub(super) async fn combined_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(token): Path<String>,
    method: Method,
    version: Version,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let base_path: Arc<str> = Arc::from(combined_base_path(uri.path(), &token));
    match decode_kind(&token) {
        SsPathKind::Tcp => {
            let ConnectInfo(peer_addr) = connect_info;
            tcp_upgrade_for_path(ws, state, base_path, method, version, headers, peer_addr).await
        },
        SsPathKind::Udp => {
            udp_upgrade_for_path(ws, state, base_path, method, version, headers).await
        },
    }
}

/// Strips the trailing `/{token}` segment from a combined-path request URI
/// to recover the base path the route maps are keyed on.
fn combined_base_path(full: &str, token: &str) -> String {
    full.strip_suffix(token)
        .and_then(|base| base.strip_suffix('/'))
        .unwrap_or(full)
        .to_string()
}

pub(super) fn finish_ws_session(
    session: WebSocketSessionGuard,
    result: anyhow::Result<()>,
    kind: &'static str,
) {
    let outcome = match result {
        Ok(()) => DisconnectReason::Normal,
        Err(error) => {
            if is_normal_h3_shutdown(&error) {
                debug!(?error, "{kind} websocket connection closed normally");
                DisconnectReason::Normal
            } else if is_expected_ws_close(&error) {
                debug!(?error, "{kind} websocket connection closed abruptly");
                DisconnectReason::ClientDisconnect
            } else if sink::is_handshake_rejected(&error) {
                debug!(?error, "{kind} websocket session rejected at handshake");
                DisconnectReason::HandshakeRejected
            } else {
                warn!(?error, "{kind} websocket connection terminated with error");
                DisconnectReason::Error
            }
        },
    };
    session.finish(outcome);
}

/// A benign cause for a WebSocket/QUIC connection to end without having to
/// log it as an error. Derived from the cause chain by downcasting to concrete
/// error types so that renaming a `Display` impl upstream cannot silently
/// demote a real error to a benign close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenignClose {
    /// Peer went away without completing the close handshake (TCP reset,
    /// broken pipe, UnexpectedEof on the socket, etc.).
    PeerAbort,
    /// Graceful HTTP/3 shutdown: `H3_NO_ERROR` from either side.
    H3NoError,
    /// QUIC idle timeout. Benign when a client simply stops talking.
    QuicTimeout,
}

fn classify_cause(cause: &(dyn std::error::Error + 'static)) -> Option<BenignClose> {
    if let Some(io) = cause.downcast_ref::<std::io::Error>() {
        return classify_io(io);
    }
    if let Some(ts) = cause.downcast_ref::<tungstenite::Error>() {
        return classify_tungstenite(ts);
    }
    if let Some(hy) = cause.downcast_ref::<hyper::Error>() {
        return classify_hyper(hy);
    }
    if let Some(qc) = cause.downcast_ref::<quinn::ConnectionError>() {
        return classify_quinn(qc);
    }
    if let Some(h3) = cause.downcast_ref::<h3::error::ConnectionError>() {
        return classify_h3_connection(h3);
    }
    if let Some(h3) = cause.downcast_ref::<h3::error::StreamError>() {
        return classify_h3_stream(h3);
    }

    if let Some(sw) = cause.downcast_ref::<H3WsError>() {
        return classify_sockudo(sw);
    }
    None
}

fn classify_io(err: &std::io::Error) -> Option<BenignClose> {
    use std::io::ErrorKind::*;
    match err.kind() {
        ConnectionReset | BrokenPipe | UnexpectedEof | ConnectionAborted => {
            Some(BenignClose::PeerAbort)
        },
        // sockudo-ws collapses h3 errors to `io::Error::other(e.to_string())`
        // (see vendor/sockudo-ws/src/http3/stream.rs), erasing the typed
        // source. Recover the H3_NO_ERROR / Timeout signal from the message.
        Other => classify_stringified_h3(&err.to_string()),
        _ => None,
    }
}

fn classify_tungstenite(err: &tungstenite::Error) -> Option<BenignClose> {
    use tungstenite::error::ProtocolError;
    match err {
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            Some(BenignClose::PeerAbort)
        },
        tungstenite::Error::Protocol(
            ProtocolError::ResetWithoutClosingHandshake | ProtocolError::SendAfterClosing,
        ) => Some(BenignClose::PeerAbort),
        tungstenite::Error::Io(io) => classify_io(io),
        _ => None,
    }
}

fn classify_hyper(err: &hyper::Error) -> Option<BenignClose> {
    if err.is_canceled() || err.is_incomplete_message() || err.is_closed() {
        Some(BenignClose::PeerAbort)
    } else {
        None
    }
}

fn classify_quinn(err: &quinn::ConnectionError) -> Option<BenignClose> {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0 => {
            Some(BenignClose::H3NoError)
        },
        quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::Reset => {
            Some(BenignClose::PeerAbort)
        },
        quinn::ConnectionError::TimedOut => Some(BenignClose::QuicTimeout),
        _ => None,
    }
}

fn classify_h3_connection(err: &h3::error::ConnectionError) -> Option<BenignClose> {
    if err.is_h3_no_error() {
        return Some(BenignClose::H3NoError);
    }
    // h3::error::ConnectionError has `#[non_exhaustive]` variants so we cannot
    // match on `Timeout` directly; fall back to its Display string, which is
    // part of the public surface we already depend on.
    classify_stringified_h3(&err.to_string())
}

fn classify_h3_stream(err: &h3::error::StreamError) -> Option<BenignClose> {
    // `StreamError` exposes no public accessor and its variants are
    // `#[non_exhaustive]`; the Display impl is the only stable surface.
    classify_stringified_h3(&err.to_string())
}

// sockudo-ws collapses h3/quinn errors into `Http3(String)` (see
// `vendor/sockudo-ws/src/error.rs`), so for that variant we have to parse the
// display string. Every other sockudo-ws variant carries a typed source that
// `classify_cause` will have already visited via the anyhow cause chain, so we
// only handle the stringy h3 case here.
fn classify_sockudo(err: &H3WsError) -> Option<BenignClose> {
    match err {
        H3WsError::ConnectionClosed | H3WsError::ConnectionReset => Some(BenignClose::PeerAbort),
        H3WsError::Http3(msg) => classify_stringified_h3(msg),
        _ => None,
    }
}

fn classify_stringified_h3(msg: &str) -> Option<BenignClose> {
    if msg.contains("ApplicationClose: H3_NO_ERROR") || msg.contains("ApplicationClose: 0x0") {
        Some(BenignClose::H3NoError)
    } else if msg.contains("Connection error: Timeout") {
        Some(BenignClose::QuicTimeout)
    } else {
        None
    }
}

fn classify_error(error: &anyhow::Error) -> Option<BenignClose> {
    error.chain().find_map(classify_cause)
}

pub(super) fn is_expected_ws_close(error: &anyhow::Error) -> bool {
    classify_error(error).is_some() || has_tls_close_notify(error)
}

pub(super) fn is_normal_h3_shutdown(error: &anyhow::Error) -> bool {
    matches!(classify_error(error), Some(BenignClose::H3NoError))
}

// rustls 0.23 signals this condition via an opaque `io::Error` whose kind is
// `Other` and whose message is the only distinguishing marker, so we keep a
// narrow string check here rather than downcasting.
fn has_tls_close_notify(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .contains("peer closed connection without sending TLS close_notify")
    })
}

#[cfg(test)]
mod tests;
