//! CRUD for canonical `[[outline.uplinks]]` entries in the running config file.
//!
//! These endpoints edit the on-disk TOML document in place (via `toml_edit`
//! to preserve comments and formatting). Changes are staged on disk: call
//! `/control/apply` to reload the file and hot-swap the live `UplinkRegistry`.
//! If a control state was built without an apply handle, a process restart is
//! the fallback activation path.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;

use super::server::ControlState;
use super::{ControlResponse, plain_response};

mod list;
mod mutate;
mod payload;

pub(crate) async fn handle_uplinks(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        Method::GET => list::handle_list(state.clone(), request.uri().query()).await,
        Method::POST => mutate::handle_create(request, state).await,
        Method::PATCH => mutate::handle_update(request, state).await,
        Method::DELETE => mutate::handle_delete(request, state).await,
        _ => plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use GET, POST, PATCH, or DELETE"}"#),
        ),
    }
}

/// `POST /control/uplinks/reorder` — move one uplink within its group. Split
/// from `handle_uplinks` (like `/control/routes/reorder` is split from
/// `/control/routes`) because reorder takes a distinct `{group, name, to}`
/// body rather than the CRUD shapes.
pub(crate) async fn handle_uplinks_reorder(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    if *request.method() != Method::POST {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use POST"}"#),
        );
    }
    mutate::handle_reorder(request, state).await
}

#[cfg(test)]
#[path = "tests/uplinks_crud.rs"]
mod tests;
