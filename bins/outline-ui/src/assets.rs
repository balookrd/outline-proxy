//! Static assets and JSON response helpers.
//!
//! `spa_index` and `asset` serve the Svelte bundle embedded from
//! `frontend/dist` behind the `embed-assets` feature — without the feature
//! they answer with a stub so the default (node-less) build keeps its Rust
//! gate green. `json_response`/`json_error` are the JSON envelope both
//! dashboard API trees (`/ws`, `/ss`) answer with.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

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
    (StatusCode::NOT_FOUND, "not found\n").into_response()
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
