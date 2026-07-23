//! Startup exposure warning and the optional credential gate for the dashboard.

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;
use tracing::warn;

use super::DashboardState;

/// Sent so a browser opening the dashboard gets a login prompt instead of a
/// bare 401. Scripted clients may use `Authorization: Bearer <token>` instead.
const CHALLENGE: &str = "Basic realm=\"outline-ss-rust dashboard\"";

/// The dashboard proxies to every configured control instance with their bearer
/// tokens injected server-side, so reaching this listener is equivalent to
/// holding all of those tokens. Off loopback and without credentials of its own
/// that authority is open to anyone who can route to the socket.
pub(super) fn warn_if_unauthenticated_exposure(listen: SocketAddr, auth_configured: bool) {
    if auth_configured || listen.ip().is_loopback() {
        return;
    }
    warn!(
        listen = %listen,
        "dashboard is not bound to loopback and has no credentials configured: it exposes \
         unauthenticated full-fleet user CRUD; bind it to loopback, set dashboard.token / \
         dashboard.token_file, or put it behind an authenticating proxy"
    );
}

/// Guards every dashboard route once `dashboard.token` is configured. Only
/// layered on then, so loopback deployments keep their existing workflow.
pub(super) async fn require_dashboard_auth(
    State(state): State<DashboardState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return next.run(request).await;
    };
    match request.headers().get(header::AUTHORIZATION) {
        Some(presented) if credentials_match(presented, expected) => next.run(request).await,
        _ => {
            let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
            let headers = response.headers_mut();
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        },
    }
}

/// Accepts either `Bearer <token>` or HTTP Basic whose password is the token;
/// the Basic username is ignored, browsers just need something to submit.
fn credentials_match(header: &HeaderValue, expected: &str) -> bool {
    let Ok(value) = header.to_str() else { return false };
    if let Some(presented) = value.strip_prefix("Bearer ") {
        return secret_matches(presented.trim().as_bytes(), expected);
    }
    let Some(encoded) = value.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else { return false };
    let Ok(decoded) = std::str::from_utf8(&decoded) else { return false };
    let Some((_username, password)) = decoded.split_once(':') else { return false };
    secret_matches(password.as_bytes(), expected)
}

fn secret_matches(presented: &[u8], expected: &str) -> bool {
    presented.ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
#[path = "tests/auth.rs"]
mod tests;
