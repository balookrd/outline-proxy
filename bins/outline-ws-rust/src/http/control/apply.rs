//! `/control/apply` — hot-apply pending `[[outline.uplinks]]` and `[[route]]`
//! changes.
//!
//! Re-runs [`crate::config::load_config`] against the on-disk file (with
//! the same CLI `Args` the process was launched with, so CLI overrides
//! still apply), validates, and then swaps the new group list into the
//! live [`UplinkRegistry`] via [`UplinkRegistry::apply_new_groups`]. When
//! routing was configured at startup, the reloaded `[[route]]` rules are
//! also compiled and hot-swapped into the live [`outline_routing::SharedRoutingTable`]
//! (see [`rebuild_routing`]).
//!
//! Only the `groups` and `routing` fields of the reloaded config are
//! applied. Other fields (`listen`, `socks5_auth`, `tun`, `metrics`,
//! `dashboard`, `h2`, `udp_*_buf_bytes`, `tcp_timeouts`, `direct_fwmark`)
//! continue to reflect the values from process startup; changing them
//! requires a full restart. Routing itself is hot-applied only when
//! `[[route]]` was already present at process startup — enabling it for
//! the first time still requires a restart, since there is no live table
//! to swap into. A successful apply is reported in the response.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use outline_uplink::UplinkRegistry;

use crate::config::{Args, load_config};
use crate::http::control::config_edit::json_error_owned;

use super::{ControlResponse, json_response, plain_response};

/// Cross-cutting runtime state needed to re-read the config file and swap
/// the live registry. Constructed in `bootstrap::run_with_config` and
/// threaded into [`super::server::ControlState`].
pub struct ApplyHandle {
    pub config_path: PathBuf,
    pub args: Args,
    pub dns_cache: Arc<outline_transport::DnsCache>,
    pub state_store: Option<Arc<outline_uplink::StateStore>>,
    pub registry: UplinkRegistry,
    /// Present when `[[route]]` was configured at startup; `None` means routing
    /// changes are restart-only (first-time enable can't hot-swap into a table
    /// that never existed).
    pub shared_routing: Option<Arc<outline_routing::SharedRoutingTable>>,
    /// The live per-rule file watchers. Replaced on every routing apply so a
    /// new table's files get watched and the old table's watchers stop.
    pub route_watchers: Arc<tokio::sync::Mutex<Option<outline_routing::RouteWatchersGuard>>>,
    /// Serialises concurrent `/control/apply` requests. Reloading config
    /// and swapping the registry is not safe to run twice in parallel —
    /// the second caller could see a half-swapped state.
    pub lock: Mutex<()>,
}

#[derive(Debug, Serialize)]
struct ApplyResponse {
    applied: bool,
    groups: usize,
    total_uplinks: usize,
    default_group: String,
    /// Non-default rule count of the newly-applied routing table. `None`
    /// when routing was not hot-applied (not configured at startup, or the
    /// reloaded config has no `[[route]]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    routes_applied: Option<usize>,
}

/// Compile `cfg` into a fresh table, publish it into `shared` (preserving the
/// version counter), and respawn the file watchers on the new table. Returns
/// the non-default rule count for the response. On compile error the live
/// table is left untouched.
pub(super) async fn rebuild_routing(
    shared: &outline_routing::SharedRoutingTable,
    cfg: &outline_routing::config::RoutingTableConfig,
    watchers: &tokio::sync::Mutex<Option<outline_routing::RouteWatchersGuard>>,
) -> anyhow::Result<usize> {
    let table = outline_routing::RoutingTable::compile(cfg)
        .await
        .context("failed to compile routing table")?;
    let rule_count = cfg.rules.len();
    // Stop the OLD table's file watchers BEFORE the swap. Those watchers bump
    // the old table's `version` on mtime change, and `swap_preserving_version`
    // reads that version (non-atomically) to seed the new table's. If a watcher
    // bumped it in the read→store window, the new table could be stamped with a
    // version a per-association cache already holds — the cache would then look
    // current and skip re-resolution against the new table. Dropping the guard
    // here narrows that window to effectively nothing — but it only sends a
    // `watch` shutdown signal, not a synchronous join: a watcher already woken
    // from its poll sleep and mid-reload will not observe the signal until its
    // next loop iteration, so it could still land a version bump after the
    // drop returns. That residual window needs a watched file's mtime to
    // change in the same instant as this apply, which does not happen in
    // practice, but is not structurally impossible. `/control/apply` is
    // serialized by its own mutex, so no second apply races this; the watcher
    // is the only other writer.
    let mut slot = watchers.lock().await;
    *slot = None; // drop old guard → old watchers stop bumping the old version
    let new_arc = shared.swap_preserving_version(table);
    *slot = Some(outline_routing::spawn_route_watchers(new_arc));
    Ok(rule_count)
}

/// Whether `/control/apply` can hot-apply routing: only when routing was
/// configured at startup (a `SharedRoutingTable` exists to swap into) AND the
/// reloaded config still declares routing. Otherwise routing changes are
/// restart-only and `routes_applied` is None.
fn routing_hot_apply_possible(
    shared: Option<&Arc<outline_routing::SharedRoutingTable>>,
    reloaded_routing: Option<&outline_routing::config::RoutingTableConfig>,
) -> bool {
    shared.is_some() && reloaded_routing.is_some()
}

pub(crate) async fn handle_apply(
    request: Request<Incoming>,
    handle: Arc<ApplyHandle>,
) -> ControlResponse {
    if request.method() != Method::POST {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use POST"}"#),
        );
    }

    let _guard = handle.lock.lock().await;

    // Re-read & re-validate the on-disk config using the same CLI Args
    // the process was launched with. This catches bad edits (e.g. TOML
    // errors, unknown groups referenced by [[route]]) before touching the
    // live registry.
    let new_config = match load_config(&handle.config_path, &handle.args).await {
        Ok(cfg) => cfg,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "apply aborted: config reload failed");
            return json_error_owned(
                StatusCode::BAD_REQUEST,
                format!("config reload failed: {error:#}"),
            );
        },
    };

    // Swap the uplink groups. Other config fields besides `routing` (handled
    // below) are ignored for hot-apply; changing them requires a restart.
    if let Err(error) = handle
        .registry
        .apply_new_groups(
            new_config.groups,
            Arc::clone(&handle.dns_cache),
            handle.state_store.clone(),
        )
        .await
    {
        warn!(error = %format!("{error:#}"), "apply aborted: registry swap failed");
        return json_error_owned(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry swap failed: {error:#}"),
        );
    }

    // Hot-apply routing when it was configured at startup. The reloaded
    // `new_config.routing` is already in scope. The match pattern below is the
    // real runtime gate; the `routing_hot_apply_possible` guard is redundant
    // with it by construction (both bindings are already `Some` in this arm).
    // It is kept deliberately so the documented, unit-tested predicate stays
    // referenced from production — arm pattern and predicate encode the same
    // "routing configured at startup AND still declared" condition on purpose.
    let routes_applied = match (&handle.shared_routing, &new_config.routing) {
        (Some(shared), Some(routing_cfg))
            if routing_hot_apply_possible(Some(shared), Some(routing_cfg)) =>
        {
            match rebuild_routing(shared, routing_cfg, &handle.route_watchers).await {
                Ok(n) => Some(n),
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "apply aborted: routing rebuild failed");
                    return json_error_owned(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("routing apply failed: {e:#}"),
                    );
                },
            }
        },
        // routing not configured at startup, or removed from config → nothing
        // to hot-swap (first-time enable / full disable stays restart-only).
        _ => None,
    };

    let default_group = handle.registry.default_group_name();
    let groups = handle.registry.group_count();
    let total_uplinks = handle.registry.total_uplinks();
    info!(
        groups,
        total_uplinks,
        %default_group,
        ?routes_applied,
        "uplink registry hot-applied via /control/apply"
    );

    json_response(
        StatusCode::OK,
        &ApplyResponse {
            applied: true,
            groups,
            total_uplinks,
            default_group,
            routes_applied,
        },
    )
}

#[cfg(test)]
#[path = "tests/apply_routing.rs"]
mod tests;
