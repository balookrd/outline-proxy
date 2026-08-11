//! Startup exposure warning and the optional credential gate for the dashboard.

use std::net::SocketAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, WWW_AUTHENTICATE};
use http::{HeaderValue, Request, StatusCode};
use tracing::warn;

use super::response::{DashboardResponse, plain_response};
use crate::http::constant_time_eq;

/// Sent so a browser opening the dashboard gets a login prompt instead of a
/// bare 401. Scripted clients may use `Authorization: Bearer <token>` instead.
const CHALLENGE: &str = "Basic realm=\"outline-ws-rust dashboard\"";

/// The dashboard proxies to every configured instance with their bearer tokens
/// injected server-side, so reaching this listener is equivalent to holding all
/// of those tokens — including the authority to activate uplinks and rewrite
/// the instances' configs. Off loopback and without credentials of its own that
/// authority is open to anyone who can route to the socket.
pub(super) fn warn_if_unauthenticated_exposure(listen: SocketAddr, auth_configured: bool) {
    if auth_configured || listen.ip().is_loopback() {
        return;
    }
    warn!(
        %listen,
        "dashboard is not bound to loopback and has no credentials configured: it exposes \
         unauthenticated uplink activation and config apply on every configured instance; bind \
         it to loopback, set [dashboard].token / token_file, or put it behind an authenticating \
         proxy"
    );
}

/// Guards every dashboard route once `[dashboard].token` is configured, and is
/// applied before any routing so a new route cannot be added past it. Returns
/// the refusal to send; `None` lets the request reach routing. With no token
/// configured the listener stays open, as it has always been.
pub(super) fn reject_unauthorized<B>(
    request: &Request<B>,
    expected: Option<&str>,
) -> Option<DashboardResponse> {
    let expected = expected?;
    match request.headers().get(AUTHORIZATION) {
        Some(presented) if credentials_match(presented, expected) => None,
        _ => Some(unauthorized_response()),
    }
}

/// Accepts either `Bearer <token>` or HTTP Basic whose password is the token;
/// the Basic username is ignored, browsers just need something to submit.
fn credentials_match(header: &HeaderValue, expected: &str) -> bool {
    let Ok(value) = header.to_str() else { return false };
    if let Some(presented) = value.strip_prefix("Bearer ") {
        return constant_time_eq(presented.trim().as_bytes(), expected.as_bytes());
    }
    let Some(encoded) = value.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else { return false };
    let Ok(decoded) = std::str::from_utf8(&decoded) else { return false };
    let Some((_username, password)) = decoded.split_once(':') else { return false };
    constant_time_eq(password.as_bytes(), expected.as_bytes())
}

fn unauthorized_response() -> DashboardResponse {
    let mut response = plain_response(
        StatusCode::UNAUTHORIZED,
        "text/plain; charset=utf-8",
        Bytes::from_static(b"unauthorized\n"),
    );
    let headers = response.headers_mut();
    headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
    // The refusal carries a challenge, so no cache between the operator and
    // this listener may replay it in place of a later authorized answer.
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
#[path = "tests/auth.rs"]
mod tests;
