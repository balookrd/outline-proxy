//! Credential gate for the whole listener.
//!
//! Reaching this service is equivalent to holding every instance token it is
//! configured with — the tokens are injected server-side on every proxied
//! request. So the gate is mandatory (see `config.rs`) and runs before routing,
//! not inside individual handlers: a route added later must not be able to sit
//! outside the check by simply not asking for it.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct AuthState {
    pub token_hash: [u8; 32],
}

impl AuthState {
    pub fn new(token: &str) -> Self {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes());
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(digest.as_ref());
        Self { token_hash }
    }
}

/// Constant-time token comparison over fixed-size SHA-256 digests.
///
/// Hashing both inputs to a 32-byte digest eliminates early-exit timing leaks on
/// mismatched token lengths before `subtle::ConstantTimeEq` checks the bytes.
fn constant_time_eq_token(presented: &str, expected_hash: &[u8; 32]) -> bool {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, presented.as_bytes());
    digest.as_ref().ct_eq(expected_hash).into()
}

/// Accepts `Bearer <token>` for scripted clients and `Basic <base64>` for
/// browsers, where any username is allowed and the password carries the token.
fn presented_token(header_value: &str) -> Option<String> {
    if let Some(rest) = header_value.strip_prefix("Bearer ") {
        return Some(rest.trim().to_string());
    }
    let encoded = header_value.strip_prefix("Basic ")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_user, password) = decoded.split_once(':')?;
    Some(password.to_string())
}

pub async fn require_auth(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(presented_token);

    match presented {
        Some(token) if constant_time_eq_token(&token, &state.token_hash) => next.run(request).await,
        _ => unauthorized(),
    }
}

/// `WWW-Authenticate` makes a browser show a login prompt instead of a bare 401
/// the operator cannot answer.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"outline-ui\"")],
        "unauthorized\n",
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/auth.rs"]
mod tests;
