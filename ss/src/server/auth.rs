use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) fn parse_root_http_auth_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}
