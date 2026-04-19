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

use crate::metrics::{DisconnectReason, Metrics, Transport};

use super::setup::protocol_from_http_version;
use super::state::{AppState, empty_transport_route};

mod tcp;
mod udp;
mod ws_socket;
mod ws_writer;

pub(super) use tcp::handle_tcp_h3_connection;
pub(super) use udp::handle_udp_h3_connection;

pub(super) async fn tcp_websocket_upgrade(
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
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let route = state
        .routes
        .tcp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let session = state.services.metrics.open_websocket_session(Transport::Tcp, protocol);
    ws.on_upgrade(move |socket| async move {
        let outcome = match tcp::handle_tcp_connection(
            socket,
            Arc::clone(&route.users),
            state.services.metrics.clone(),
            protocol,
            Arc::clone(&path),
            Arc::clone(&route.candidate_users),
            Arc::clone(&state.services.dns_cache),
            state.services.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "tcp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_expected_ws_close(&error) {
                    debug!(?error, "tcp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "tcp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            },
        };
        session.finish(outcome);
    })
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

    match parse_root_http_auth_password(&headers) {
        Some(password) if password_matches_any_user(state.auth.users.as_ref(), &password) => {
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
    let route = state
        .routes
        .udp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let session = state.services.metrics.open_websocket_session(Transport::Udp, protocol);
    let nat_table = Arc::clone(&state.services.nat_table);
    ws.on_upgrade(move |socket| async move {
        let outcome = match udp::handle_udp_connection(
            socket,
            Arc::clone(&route.users),
            state.services.metrics.clone(),
            protocol,
            Arc::clone(&path),
            Arc::clone(&route.candidate_users),
            nat_table,
            Arc::clone(&state.services.dns_cache),
            state.services.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "udp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_expected_ws_close(&error) {
                    debug!(?error, "udp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "udp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            },
        };
        session.finish(outcome);
    })
}

pub(super) fn is_expected_ws_close(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("Connection reset without closing handshake")
            || message.contains("Connection reset by peer")
            || message.contains("Broken pipe")
            || message.contains("connection closed before message completed")
            || message.contains("Sending after closing is not allowed")
            || message.contains("peer closed connection without sending TLS close_notify")
            || message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
            || message.contains("ApplicationClose: 0x0")
            || message.contains(
                "InternalError in the quic trait implementation: internal error in the http stack",
            )
            || message.contains("Connection error: Timeout")
    })
}

pub(super) fn is_normal_h3_shutdown(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
            || message.contains("ApplicationClose: 0x0")
    })
}
