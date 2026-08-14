//! CRUD for `[[uplink_group]]` policy sections in the running config file.
//!
//! Edits the on-disk TOML document in place (via `toml_edit`, preserving
//! comments/formatting). Changes are staged on disk: call `/control/apply` to
//! reload the file and hot-swap the live `UplinkRegistry`. If a control state
//! was built without an apply handle, a process restart is the fallback.
//! Addressed by `name` (identity): create appends, delete removes an empty
//! group, update merges policy in place — no reorder, no `revision`-guard.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;

use super::server::ControlState;
use super::{ControlResponse, plain_response};

mod list;
mod mutate;
mod payload;

pub(crate) use mutate::handle_groups;

/// `POST /control/uplink_groups/reorder` — move one group to a new position.
/// Split from `handle_groups` (like `/control/uplinks/reorder`) because reorder
/// takes a distinct `{name, to}` body rather than the CRUD shapes.
pub(crate) async fn handle_groups_reorder(
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
