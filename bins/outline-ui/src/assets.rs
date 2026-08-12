//! Static assets and HTML templating.
//!
//! Both UIs address their APIs absolutely (`/dashboard/api/...`). Mounted under
//! `/ws` and `/ss` those URLs would miss, and the two would collide on the same
//! paths, so each page learns its own prefix through `__BASE__`, substituted
//! here at response time.
//!
//! `<base href>` would have been shorter and was rejected: it silently rewrites
//! every relative URL and anchor on the page, fixing the fetches by changing
//! things nobody audited.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const INDEX_TEMPLATE: &str = include_str!("index.html");
const LOGO: &[u8] = include_bytes!("outline-logo.png");

/// Fills a page template with its mount prefix and refresh interval. Both
/// placeholders are substituted here so a handler cannot forget one of them.
pub fn render(template: &str, base: &str, refresh_ms: u64) -> String {
    template
        .replace("__BASE__", base)
        .replace("__DASHBOARD_REFRESH_MS__", &refresh_ms.to_string())
}

pub fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

pub fn logo() -> Response {
    ([(header::CONTENT_TYPE, "image/png")], LOGO).into_response()
}

pub fn index() -> Response {
    html(INDEX_TEMPLATE.to_string())
}

/// JSON body with an explicit status. Used by both trees, so the shape of an
/// API answer does not drift between them.
pub fn json_response(status: StatusCode, value: &serde_json::Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], value.to_string()).into_response()
}

/// The error shape the dashboards' JS already expects: `{"error": "..."}`.
pub fn json_error(status: StatusCode, message: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": message }))
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

#[cfg(test)]
#[path = "tests/assets.rs"]
mod tests;
