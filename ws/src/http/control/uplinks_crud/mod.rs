//! CRUD for `[[uplink_group.uplinks]]` entries in the running config file.
//!
//! These endpoints edit the on-disk TOML document in place (via `toml_edit`
//! to preserve comments and formatting) and return `restart_required: true`
//! — the running `UplinkRegistry` is not mutated, so changes take effect
//! only after the process is restarted. This is Stage 1 of the control-
//! plane CRUD; Stage 2 will swap the registry under an `ArcSwap` for live
//! application.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;

use super::{ControlResponse, plain_response};
use super::server::ControlState;

mod io;
mod list;
mod mutate;
mod payload;

pub(crate) use mutate::find_group_mut;
pub(crate) use payload::UplinkPayload;

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

#[cfg(test)]
#[path = "tests/uplinks_crud.rs"]
mod tests;
