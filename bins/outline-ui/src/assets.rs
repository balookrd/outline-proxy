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
//!
//! Everything above serves the legacy HTML dashboards baked into this binary;
//! they stay until the trees below them are cut over. `spa_index` and `asset`
//! below serve their replacement, the Svelte bundle, embedded from
//! `frontend/dist` behind the `embed-assets` feature — without the feature
//! they answer with a stub so the default (node-less) build keeps its Rust
//! gate green.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

// `index`/`INDEX_TEMPLATE` lost their only caller when `/` switched to
// `spa_index` below. `#[allow(dead_code)]` keeps them compiled-but-unused
// rather than deleted: the legacy HTML dashboards they belong to (and these
// two helpers with them) are removed in a follow-up task, not this one.
#[allow(dead_code)]
const INDEX_TEMPLATE: &str = include_str!("index.html");
const LOGO: &[u8] = include_bytes!("outline-logo.png");

#[cfg(feature = "embed-assets")]
mod embedded {
    use rust_embed::RustEmbed;

    /// The built Svelte bundle: `index.html`, hashed JS/CSS, and the
    /// fontsource woff2 subset. Populated by `pnpm build`; nothing constructs
    /// this type unless `embed-assets` is on, so an unbuilt `frontend/dist`
    /// never affects the default build.
    #[derive(RustEmbed)]
    #[folder = "frontend/dist"]
    pub struct Assets;
}

/// SPA entry point: `index.html` for `/` and for every client-side route that
/// falls through routing (e.g. a deep link to `/ws/uplinks` reloaded fresh).
pub fn spa_index() -> Response {
    #[cfg(feature = "embed-assets")]
    if let Some(f) = embedded::Assets::get("index.html") {
        return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], f.data.into_owned())
            .into_response();
    }
    // Stub keeps the default (node-less) build — and its Rust CI gate — green
    // even though nothing was ever `pnpm build`t.
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><title>outline-ui</title>\
         <p>assets not embedded (build with --features embed-assets)",
    )
        .into_response()
}

/// One embedded asset (JS/CSS/font/icon) under the `/ui-assets` prefix Vite
/// was configured to emit (`base: '/ui-assets/'`).
pub fn asset(path: &str) -> Response {
    #[cfg(feature = "embed-assets")]
    if let Some(f) = embedded::Assets::get(path) {
        let mime = f.metadata.mimetype();
        return ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response();
    }
    #[cfg(not(feature = "embed-assets"))]
    let _ = path;
    not_found()
}

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

// See the `#[allow(dead_code)]` note on `INDEX_TEMPLATE` above.
#[allow(dead_code)]
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
