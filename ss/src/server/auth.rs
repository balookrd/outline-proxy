use axum::http::{self, HeaderMap, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::crypto::UserKey;

pub(super) const ROOT_HTTP_AUTH_COOKIE_NAME: &str = "outline_ss_root_auth";
pub(super) const ROOT_HTTP_AUTH_MAX_FAILURES: u8 = 3;
pub(super) const ROOT_HTTP_AUTH_COOKIE_TTL_SECS: u32 = 300;

pub(super) fn parse_root_http_auth_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}

pub(super) fn parse_failed_root_auth_attempts(headers: &HeaderMap) -> u8 {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_cookie(value, ROOT_HTTP_AUTH_COOKIE_NAME))
        .and_then(|value| value.parse::<u8>().ok())
        .map(|attempts| attempts.min(ROOT_HTTP_AUTH_MAX_FAILURES))
        .unwrap_or(0)
}

fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|entry| {
        let (cookie_name, cookie_value) = entry.trim().split_once('=')?;
        (cookie_name == name).then_some(cookie_value)
    })
}

pub(super) fn password_matches_any_user(users: &[UserKey], password: &str) -> bool {
    users
        .iter()
        .any(|user| matches!(user.matches_password(password), Ok(true)))
}

pub(super) fn escape_http_auth_realm(realm: &str) -> String {
    realm.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(super) fn build_not_found_response<T>(body: T) -> http::Response<T> {
    http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body)
        .expect("failed to build not found response")
}

pub(super) fn build_root_http_auth_success_response<T>(body: T) -> http::Response<T> {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!("{ROOT_HTTP_AUTH_COOKIE_NAME}=0; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
        )
        .body(body)
        .expect("failed to build root auth success response")
}

pub(super) fn build_root_http_auth_challenge_response<T>(
    failed_attempts: u8,
    realm: &str,
    body: T,
) -> http::Response<T> {
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
        .body(body)
        .expect("failed to build root auth challenge response")
}

pub(super) fn build_root_http_auth_forbidden_response<T>(body: T) -> http::Response<T> {
    http::Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!(
                "{ROOT_HTTP_AUTH_COOKIE_NAME}={ROOT_HTTP_AUTH_MAX_FAILURES}; Path=/; Max-Age={ROOT_HTTP_AUTH_COOKIE_TTL_SECS}; HttpOnly; SameSite=Lax"
            ),
        )
        .body(body)
        .expect("failed to build root auth forbidden response")
}
