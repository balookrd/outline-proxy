//! Read→mutate→validate→write for `[[route]]`, addressed by array index.

use std::path::Path;
use std::sync::Arc;

use http::{Request, StatusCode};
use hyper::body::Incoming;
use toml_edit::{ArrayOfTables, DocumentMut, Item};
use tracing::info;

use outline_routing::RoutingTable;

use crate::config::{RouteSection, load_routing_config};
use crate::http::control::config_edit::{
    json_error_owned, read_json, status_for_mutator_error, write_document_atomic,
};
use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::payload::{
    CreateBody, DeleteBody, MutationResponse, ReorderBody, RoutePayload, UpdateBody,
    payload_to_table, route_revision, table_is_default,
};

const LABEL: &str = "/control/routes";

/// Read-only accessor to the `route` array (empty when absent).
fn route_array(doc: &DocumentMut) -> Option<&ArrayOfTables> {
    doc.get("route").and_then(Item::as_array_of_tables)
}

fn route_array_mut(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if doc.get("route").and_then(Item::as_array_of_tables).is_none() {
        doc.insert("route", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["route"].as_array_of_tables_mut().expect("just ensured")
}

/// Names of every `[[uplink_group]]` declared on disk — the set `via` may
/// reference, mirroring what `load_config` would pass the validator.
pub(super) fn group_names_in_doc(doc: &DocumentMut) -> Vec<String> {
    let Some(groups) = doc.get("uplink_group").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(str::to_string))
        .collect()
}

/// Index of the `default = true` rule, if any.
fn default_index(arr: &ArrayOfTables) -> Option<usize> {
    arr.iter().position(table_is_default)
}

pub(super) fn apply_create(
    doc: &mut DocumentMut,
    rule: &RoutePayload,
    at_index: Option<usize>,
) -> Result<usize, String> {
    let mut table = Some(payload_to_table(rule));
    let arr = route_array_mut(doc);
    // Default insert position: just before the default rule (so it stays the
    // catch-all), or at the end when there is no default yet.
    let pos = match at_index {
        Some(i) if i <= arr.len() => i,
        Some(_) => return Err("at_index out of range".to_string()),
        None => default_index(arr).unwrap_or(arr.len()),
    };
    // ArrayOfTables has no insert-at; rebuild with the new table spliced in.
    // `table` is moved exactly once: `i == pos` matches at most one loop
    // iteration (i is unique per iteration), and the post-loop push only
    // fires when that iteration never happened (pos >= arr.len()).
    let mut rebuilt = ArrayOfTables::new();
    for (i, t) in arr.iter().enumerate() {
        if i == pos {
            rebuilt.push(table.take().expect("i == pos matches at most once"));
        }
        rebuilt.push(t.clone());
    }
    if let Some(table) = table {
        rebuilt.push(table);
    }
    *arr = rebuilt;
    Ok(pos)
}

pub(super) fn apply_update(
    doc: &mut DocumentMut,
    index: usize,
    rule: &RoutePayload,
) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let existing = arr.get(index).ok_or_else(|| "route index not found".to_string())?;
    let was_default = table_is_default(existing);
    let now_default = rule.default.unwrap_or(false);
    // The default rule is positional-catch-all and unique; the UI edits only
    // its via/fallback. Refuse structural changes to it here so a staged edit
    // can't produce a second default or a default with matchers.
    if was_default && !now_default {
        return Err("cannot clear `default` on the default rule".to_string());
    }
    if was_default
        && (rule.prefixes.is_some()
            || rule.file.is_some()
            || rule.files.is_some()
            || rule.domains.is_some()
            || rule.domain_file.is_some()
            || rule.domain_files.is_some())
    {
        return Err("the default rule must not set matchers".to_string());
    }
    let table = payload_to_table(rule);
    // Full replace (not merge): a field the drawer cleared must disappear.
    *arr.get_mut(index).expect("checked above") = table;
    Ok(())
}

pub(super) fn apply_delete(doc: &mut DocumentMut, index: usize) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let target = arr.get(index).ok_or_else(|| "route index not found".to_string())?;
    if table_is_default(target) {
        return Err("cannot delete the `default` rule".to_string());
    }
    let mut rebuilt = ArrayOfTables::new();
    for (i, t) in arr.iter().enumerate() {
        if i != index {
            rebuilt.push(t.clone());
        }
    }
    *arr = rebuilt;
    Ok(())
}

pub(super) fn apply_reorder(doc: &mut DocumentMut, from: usize, to: usize) -> Result<(), String> {
    let arr = route_array_mut(doc);
    let len = arr.len();
    if from >= len || to >= len {
        return Err("reorder index not found".to_string());
    }
    let mut tables: Vec<_> = arr.iter().cloned().collect();
    let moved = tables.remove(from);
    tables.insert(to, moved);
    let mut rebuilt = ArrayOfTables::new();
    for t in tables {
        rebuilt.push(t);
    }
    *arr = rebuilt;
    Ok(())
}

/// Whole-list semantic validation: render the `route` array back to sections,
/// run the same validator the config loader uses, and then compile it exactly
/// as boot does. Guarantees a staged config still boots: exactly one default,
/// `via`→known group, invert⊕domains, ≤1 fallback (all from
/// `load_routing_config`) — AND every CIDR/domain actually parses and every
/// `file`/`domain_file` is readable (from [`RoutingTable::compile`]).
/// `load_routing_config` alone only validates structure and resolves paths;
/// it never parses a prefix string or opens a file, so without the compile
/// step here a rule like `prefixes = ["garbage"]` would pass validation, get
/// written to disk, and then fail `RoutingTable::compile` at the next boot —
/// this closes that gap.
pub(super) async fn validate_route_array(
    doc: &DocumentMut,
    group_names: &[&str],
    config_dir: &Path,
) -> anyhow::Result<()> {
    let Some(arr) = route_array(doc) else {
        return Ok(()); // no [[route]] section at all is valid (routing disabled)
    };
    #[derive(serde::Deserialize)]
    struct Wrapper {
        route: Vec<RouteSection>,
    }
    let mut wrap_doc = DocumentMut::new();
    let mut aot = ArrayOfTables::new();
    for t in arr.iter() {
        aot.push(t.clone());
    }
    wrap_doc.insert("route", Item::ArrayOfTables(aot));
    let sections = toml::from_str::<Wrapper>(&wrap_doc.to_string())
        .map_err(|e| anyhow::anyhow!("route rule is invalid: {e}"))?
        .route;
    if let Some(cfg) = load_routing_config(Some(&sections), group_names, config_dir)? {
        RoutingTable::compile(&cfg)
            .await
            .map_err(|e| anyhow::anyhow!("route rule would fail to compile: {e:#}"))?;
    }
    Ok(())
}

/// Method dispatch for `/control/routes`.
pub(crate) async fn handle_routes(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        http::Method::GET => super::list::handle_list(state).await,
        http::Method::POST => mutate(request, state, MutateKind::Create).await,
        http::Method::PATCH => mutate(request, state, MutateKind::Update).await,
        http::Method::DELETE => mutate(request, state, MutateKind::Delete).await,
        _ => json_error(StatusCode::METHOD_NOT_ALLOWED, "use GET, POST, PATCH, or DELETE"),
    }
}

pub(crate) async fn handle_routes_reorder(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    if *request.method() != http::Method::POST {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
    }
    mutate(request, state, MutateKind::Reorder).await
}

enum MutateKind {
    Create,
    Update,
    Delete,
    Reorder,
}

async fn mutate(
    request: Request<Incoming>,
    state: Arc<ControlState>,
    kind: MutateKind,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD needs on-disk config",
        );
    };
    // Unlike uplinks_crud (where any apply-handle means hot-apply works),
    // routing hot-apply also needs a live table to swap into — which only
    // exists when `[[route]]` was already configured at process startup (see
    // `ApplyHandle::shared_routing`). A node that started with no routing
    // section has `apply: Some(_)` but `shared_routing: None`, so checking
    // handle existence alone would wrongly promise a hot-apply that
    // `/control/apply` cannot perform; report `restart_required: true` for it
    // instead.
    let hot_apply_available =
        state.apply.as_ref().and_then(|h| h.shared_routing.as_ref()).is_some();
    let config_dir = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();

    // Deserialize the kind-specific body.
    enum Parsed {
        Create(CreateBody),
        Update(UpdateBody),
        Delete(DeleteBody),
        Reorder(ReorderBody),
    }
    let parsed = match kind {
        MutateKind::Create => match read_json::<CreateBody>(request, LABEL).await {
            Ok(b) => Parsed::Create(b),
            Err(r) => return r,
        },
        MutateKind::Update => match read_json::<UpdateBody>(request, LABEL).await {
            Ok(b) => Parsed::Update(b),
            Err(r) => return r,
        },
        MutateKind::Delete => match read_json::<DeleteBody>(request, LABEL).await {
            Ok(b) => Parsed::Delete(b),
            Err(r) => return r,
        },
        MutateKind::Reorder => match read_json::<ReorderBody>(request, LABEL).await {
            Ok(b) => Parsed::Reorder(b),
            Err(r) => return r,
        },
    };
    let client_revision = match &parsed {
        Parsed::Create(b) => &b.revision,
        Parsed::Update(b) => &b.revision,
        Parsed::Delete(b) => &b.revision,
        Parsed::Reorder(b) => &b.revision,
    }
    .clone();

    let _guard = state.config_write_lock.lock().await;
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {e}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {e}"),
            );
        },
    };

    // Optimistic-concurrency check against the current on-disk array.
    let current_revision = route_array(&doc).map(route_revision).unwrap_or_default();
    if current_revision != client_revision {
        return json_error(
            StatusCode::CONFLICT,
            "config changed since it was read; reload and retry",
        );
    }

    let (action, index) = match &parsed {
        Parsed::Create(b) => match apply_create(&mut doc, &b.rule, b.at_index) {
            Ok(i) => ("created", i),
            Err(msg) => return json_error_owned(StatusCode::BAD_REQUEST, msg),
        },
        Parsed::Update(b) => match apply_update(&mut doc, b.index, &b.rule) {
            Ok(()) => ("updated", b.index),
            Err(msg) => return json_error_owned(status_for_mutator_error(&msg), msg),
        },
        Parsed::Delete(b) => match apply_delete(&mut doc, b.index) {
            Ok(()) => ("deleted", b.index),
            Err(msg) => return json_error_owned(status_for_mutator_error(&msg), msg),
        },
        Parsed::Reorder(b) => match apply_reorder(&mut doc, b.from, b.to) {
            Ok(()) => ("reordered", b.to),
            Err(msg) => return json_error_owned(status_for_mutator_error(&msg), msg),
        },
    };

    // Whole-list validation before writing: never stage a config that won't boot.
    let groups = group_names_in_doc(&doc);
    let group_refs: Vec<&str> = groups.iter().map(String::as_str).collect();
    if let Err(e) = validate_route_array(&doc, &group_refs, &config_dir).await {
        return json_error_owned(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }

    if let Err(e) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"));
    }

    let new_revision = route_array(&doc).map(route_revision).unwrap_or_default();
    info!(action, index, "route staged");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse::staged(action, index, hot_apply_available, new_revision),
    )
}

#[cfg(test)]
#[path = "tests/mutate.rs"]
mod tests;
