//! CRUD for `[[uplink_group]]` policy sections in the running config file.
//!
//! Edits the on-disk TOML document in place (via `toml_edit`, preserving
//! comments/formatting). Changes are staged on disk: call `/control/apply` to
//! reload the file and hot-swap the live `UplinkRegistry`. If a control state
//! was built without an apply handle, a process restart is the fallback.
//! Addressed by `name` (identity): create appends, delete removes an empty
//! group, update merges policy in place — no reorder, no `revision`-guard.

// Every item in this module tree (payload.rs + mutate.rs) is exercised by
// this module's own unit tests, but in a plain (non-`cfg(test)`) build
// nothing in the crate calls `handle_groups`/`handle_groups_reorder` yet:
// `/control/uplink_groups` isn't dispatched from `server.rs` (Task 5) and
// `handle_groups`'s GET arm doesn't yet delegate to a `list` module (Task 4,
// `groups_crud/list.rs`). Without a real caller, the whole reachability graph
// below `handle_groups`/`handle_groups_reorder` — down through
// `apply_create`/`apply_update`/`apply_delete`/`apply_reorder` and every
// `payload.rs` type/fn — reports `dead_code`/`unused_imports` under
// `-D warnings` (verified: `cargo clippy --all-targets` fails with exactly
// this set, 32 errors on the plain `lib` target). Drop this allow once Task 5
// registers `handle_groups`/`handle_groups_reorder` in `server.rs`'s dispatch
// (list.rs landing first, in Task 4, is not itself sufficient — the dispatch
// registration is what supplies the missing caller).
#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;

use super::server::ControlState;
use super::{ControlResponse, plain_response};

// TODO(Task 4): `mod list;` lands with `groups_crud/list.rs` (GET listing +
// uplink_count). Until then, `handle_groups`'s GET arm (in `mutate.rs`)
// answers 501 instead of dispatching to a list handler.
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
