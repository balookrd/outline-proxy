//! Shared building blocks for control endpoints that edit `config.toml`
//! in place (`uplinks_crud`, `routes_crud`). Keeps the atomic-write,
//! round-trip-render and error→status conventions identical across both so a
//! second editor can't drift from the first on subtle TOML details (nested
//! `ArrayOfTables` header rendering in particular).

use std::path::Path;

use anyhow::Context;
use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Serialize;
use serde::de::DeserializeOwned;
use toml_edit::{DocumentMut, Table};

use crate::http::body::read_limited_body;
use crate::http::control::{ControlResponse, json_response};

/// Bounded-body read + JSON deserialize. `label` is the metrics/path tag
/// forwarded to `read_limited_body` (413 on over-limit, 400 on read error).
pub(crate) async fn read_json<T: DeserializeOwned>(
    request: Request<Incoming>,
    label: &'static str,
) -> Result<T, ControlResponse> {
    let body = read_limited_body(request.into_body(), label).await?;
    serde_json::from_slice::<T>(&body)
        .map_err(|e| json_error_owned(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
}

/// Owned-`String` error responder (counterpart to `json_error`'s `&'static str`).
pub(crate) fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}

/// Serialize `doc` and write it over `path` atomically at 0600, offloading the
/// blocking write. `config.toml` holds secrets, so a plain write+rename would
/// widen mode to the umask and open a world-readable window.
pub(crate) async fn write_document_atomic(path: &Path, doc: &DocumentMut) -> anyhow::Result<()> {
    let contents = doc.to_string();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::fs_util::atomic_write(&path, contents.as_bytes()))
        .await
        .context("config write task panicked")?
}

/// Render a standalone `Table` to TOML text with nested `ArrayOfTables`
/// headers intact. `Table::to_string()` alone can't render array-of-tables
/// items because their headers need the parent path, which a detached table
/// doesn't know — so wrap it in a fresh document first.
pub(crate) fn render_table_with_arrays(tbl: &Table) -> String {
    let mut doc = DocumentMut::new();
    let root = doc.as_table_mut();
    for (key, item) in tbl.iter() {
        root.insert(key, item.clone());
    }
    doc.to_string()
}

/// Round-trip a `Table` to a `serde_json::Value` (via TOML text). `None` on
/// round-trip failure — callers surface it as "config unreadable" rather than
/// an error.
pub(crate) fn table_to_json(tbl: &Table) -> Option<serde_json::Value> {
    let text = render_table_with_arrays(tbl);
    let toml_value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(toml_value).ok()
}

/// Map a mutator closure's `Err(String)` to an HTTP status by substring
/// convention: `"not found"`→404, `"already exists"`→409, else 400.
pub(crate) fn status_for_mutator_error(msg: &str) -> StatusCode {
    if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else if msg.contains("already exists") {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    }
}
