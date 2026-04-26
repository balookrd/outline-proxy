use super::auth::{
    ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response, build_root_http_auth_challenge_response,
    build_root_http_auth_forbidden_response, build_root_http_auth_success_response,
    parse_failed_root_auth_attempts, parse_root_http_auth_password, password_matches_any_user,
};

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{
        OriginalUri, State,
        ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, Method, StatusCode, Version},
    response::{IntoResponse, Response},
};
use tracing::{debug, warn};

use crate::metrics::{DisconnectReason, Metrics, Transport, WebSocketSessionGuard};

use super::setup::protocol_from_http_version;
use super::state::{AppState, empty_transport_route, empty_vless_transport_route};

mod raw_quic;
pub(in crate::server) mod sink;
mod tcp;
mod udp;
mod vless;
mod vless_mux;
mod vless_udp;
mod ws_socket;
mod ws_writer;

pub(in crate::server) use sink::is_handshake_rejected;
pub(in crate::server) use raw_quic::{
    OversizeStream, RawQuicSsCtx, RawQuicVlessRouteCtx, SsQuicConn, StreamKind, VlessQuicConn,
    classify_accept_bi, handle_raw_ss_quic_stream, handle_raw_ss_quic_stream_with_prefix,
    handle_raw_vless_quic_stream, handle_raw_vless_quic_stream_with_prefix,
    serve_raw_ss_oversize_records, serve_raw_ss_quic_datagrams,
    serve_raw_vless_oversize_records, serve_raw_vless_quic_datagrams,
};
pub(in crate::server) use tcp::{
    ResumeContext, WsTcpRouteCtx, WsTcpServerCtx, handle_tcp_h3_connection,
};
pub(in crate::server) use udp::{UdpRouteCtx, UdpServerCtx, handle_udp_h3_connection};
pub(in crate::server) use vless::{VlessWsRouteCtx, VlessWsServerCtx, handle_vless_h3_connection};

pub(super) async fn tcp_websocket_upgrade(
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
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let routes_snap = state.routes.load();
    let route = routes_snap
        .tcp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    drop(routes_snap);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let server = Arc::clone(&state.services.tcp_server);
    let session = server
        .metrics
        .open_websocket_session(Transport::Tcp, protocol);
    let resume = ResumeContext::from_request_headers(&headers, &server.orphan_registry);
    let mut response = ws.on_upgrade(move |socket| async move {
        let route_ctx = WsTcpRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
        };
        let result = tcp::handle_tcp_connection(socket, server, route_ctx, resume).await;
        finish_ws_session(session, result, "tcp");
    });
    // The `ResumeContext` was moved into the upgrade closure, so we re-
    // parse the header set here to attach the response side. This is
    // strictly cheaper than threading a clone through the upgrade
    // future, and the lookup is on a 0-or-1 element span.
    let response_resume =
        ResumeContext::from_request_headers(&headers, &state.services.orphan_registry);
    response_resume.issue_session_header(response.headers_mut());
    response
}

pub(super) async fn vless_websocket_upgrade(
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
    let session = server
        .metrics
        .open_websocket_session(Transport::Tcp, protocol);
    let resume = ResumeContext::from_request_headers(&headers, &server.orphan_registry);
    let mut response = ws.on_upgrade(move |socket| async move {
        let route_ctx = VlessWsRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
        };
        let result = vless::handle_vless_connection(socket, server, route_ctx, resume).await;
        finish_ws_session(session, result, "vless");
    });
    let response_resume =
        ResumeContext::from_request_headers(&headers, &state.services.orphan_registry);
    response_resume.issue_session_header(response.headers_mut());
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
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let ws = ws.write_buffer_size(0);
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let routes_snap = state.routes.load();
    let route = routes_snap
        .udp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    drop(routes_snap);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let server = Arc::clone(&state.services.udp_server);
    let session = server
        .metrics
        .open_websocket_session(Transport::Udp, protocol);
    ws.on_upgrade(move |socket| async move {
        let route_ctx = Arc::new(UdpRouteCtx {
            users: Arc::clone(&route.users),
            protocol,
            path,
            candidate_users: Arc::clone(&route.candidate_users),
        });
        let result = udp::handle_udp_connection(socket, server, route_ctx).await;
        finish_ws_session(session, result, "udp");
    })
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

    if let Some(sw) = cause.downcast_ref::<sockudo_ws::Error>() {
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
fn classify_sockudo(err: &sockudo_ws::Error) -> Option<BenignClose> {
    match err {
        sockudo_ws::Error::ConnectionClosed | sockudo_ws::Error::ConnectionReset => {
            Some(BenignClose::PeerAbort)
        },
        sockudo_ws::Error::Http3(msg) => classify_stringified_h3(msg),
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
