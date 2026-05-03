//! Mutating handlers (POST/PATCH/DELETE) plus the on-disk config-file
//! mutation primitives they share.

use std::path::Path;
use std::sync::Arc;

use http::{Request, StatusCode};
use hyper::body::Incoming;
use tokio::fs;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};
use tracing::{info, warn};

use crate::config::validate_uplink_section;
use crate::http::control::{ControlResponse, json_error, json_response};
use crate::http::control::server::ControlState;

use super::io::{json_error_owned, read_json};
use super::payload::{
    CreateBody, DeleteBody, MutationResponse, UpdateBody, merge_patch_into_table,
    payload_to_section, payload_to_table, table_to_section,
};

pub(super) async fn handle_create(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let body: CreateBody = match read_json(request).await {
        Ok(v) => v,
        Err(err) => return err,
    };
    let Some(name) = body.uplink.name.clone() else {
        return json_error(StatusCode::BAD_REQUEST, "uplink.name is required");
    };
    if name.trim().is_empty() || body.group.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "group and uplink.name must be non-empty");
    }

    // Validate the payload in isolation before writing.
    let section = match payload_to_section(&body.uplink, Some(&body.group)) {
        Ok(s) => s,
        Err(msg) => return json_error_owned(StatusCode::BAD_REQUEST, msg),
    };
    if let Err(err) = validate_uplink_section(&section, 0) {
        return json_error_owned(StatusCode::BAD_REQUEST, format!("{err:#}"));
    }

    // Global uniqueness: uplink names are unique across all groups.
    let snapshots = state.uplinks.snapshots().await;
    for snap in &snapshots {
        for u in &snap.uplinks {
            if u.name == name {
                return json_error_owned(
                    StatusCode::CONFLICT,
                    format!("uplink \"{name}\" already exists in group \"{}\"", snap.group),
                );
            }
        }
    }

    let _guard = state.config_write_lock.lock().await;
    let result = mutate_config_file(&path, |doc| {
        if find_group_mut(doc, &body.group).is_none() {
            return Err(format!("uplink_group \"{}\" not found", body.group));
        }
        let arr = get_or_init_outline_uplinks(doc);
        if find_outline_uplink_index(arr, &body.group, &name).is_some() {
            return Err(format!(
                "uplink \"{name}\" already exists in group \"{}\" on disk",
                body.group
            ));
        }
        let mut tbl = payload_to_table(&body.uplink);
        // Persist the group discriminator alongside the uplink fields.
        tbl.insert("group", Item::Value(Value::from(body.group.as_str())));
        arr.push(tbl);
        Ok(())
    })
    .await;

    match result {
        Ok(()) => {
            info!(group = %body.group, uplink = %name, "uplink created via /control/uplinks");
            json_response(
                StatusCode::ACCEPTED,
                &MutationResponse {
                    group: body.group,
                    name,
                    action: "created",
                    restart_required: true,
                },
            )
        },
        Err((status, msg)) => json_error_owned(status, msg),
    }
}

pub(super) async fn handle_update(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let body: UpdateBody = match read_json(request).await {
        Ok(v) => v,
        Err(err) => return err,
    };
    if body.group.trim().is_empty() || body.name.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "group and name must be non-empty");
    }

    let _guard = state.config_write_lock.lock().await;

    // Read existing and merge, then validate as a full section.
    let raw = match fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(error) => {
            warn!(error = %error, "failed to read config for PATCH");
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {error}"),
            );
        },
    };
    let mut doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(error) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {error}"),
            );
        },
    };

    if find_group_mut(&mut doc, &body.group).is_none() {
        return json_error_owned(
            StatusCode::NOT_FOUND,
            format!("uplink_group \"{}\" not found", body.group),
        );
    }
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = match find_outline_uplink_index(arr, &body.group, &body.name) {
        Some(i) => i,
        None => {
            return json_error_owned(
                StatusCode::NOT_FOUND,
                format!("uplink \"{}\" not found in group \"{}\"", body.name, body.group),
            );
        },
    };

    merge_patch_into_table(arr.get_mut(idx).expect("index in bounds"), &body.patch);

    // Round-trip validation: parse the target table back as UplinkSection.
    let validated_section = match table_to_section(arr.get(idx).expect("in bounds")) {
        Ok(s) => s,
        Err(msg) => {
            return json_error_owned(
                StatusCode::BAD_REQUEST,
                format!("patched uplink is invalid: {msg}"),
            );
        },
    };
    if let Err(err) = validate_uplink_section(&validated_section, idx) {
        return json_error_owned(StatusCode::BAD_REQUEST, format!("{err:#}"));
    }

    if let Err(error) = write_document_atomic(&path, &doc).await {
        return json_error_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }

    info!(group = %body.group, uplink = %body.name, "uplink updated via /control/uplinks");
    json_response(
        StatusCode::ACCEPTED,
        &MutationResponse {
            group: body.group,
            name: body.name,
            action: "updated",
            restart_required: true,
        },
    )
}

pub(super) async fn handle_delete(
    request: Request<Incoming>,
    state: Arc<ControlState>,
) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let body: DeleteBody = match read_json(request).await {
        Ok(v) => v,
        Err(err) => return err,
    };

    let _guard = state.config_write_lock.lock().await;
    let group_name = body.group.clone();
    let uplink_name = body.name.clone();
    let result = mutate_config_file(&path, |doc| {
        if find_group_mut(doc, &group_name).is_none() {
            return Err(format!("uplink_group \"{group_name}\" not found"));
        }
        let arr = get_or_init_outline_uplinks(doc);
        let idx = find_outline_uplink_index(arr, &group_name, &uplink_name)
            .ok_or_else(|| format!("uplink \"{uplink_name}\" not found in group \"{group_name}\""))?;
        if count_uplinks_in_group(arr, &group_name) <= 1 {
            return Err(format!(
                "cannot delete last uplink in group \"{group_name}\"; \
                 a group must contain at least one uplink"
            ));
        }
        arr.remove(idx);
        Ok(())
    })
    .await;

    match result {
        Ok(()) => {
            info!(group = %body.group, uplink = %body.name, "uplink deleted via /control/uplinks");
            json_response(
                StatusCode::ACCEPTED,
                &MutationResponse {
                    group: body.group,
                    name: body.name,
                    action: "deleted",
                    restart_required: true,
                },
            )
        },
        Err((status, msg)) => json_error_owned(status, msg),
    }
}

/// Read → mutate → validate-round-trip → atomic-write. `mutator` edits the
/// in-memory document; return `Err(msg)` to abort with 400/404.
async fn mutate_config_file<F>(
    path: &Path,
    mutator: F,
) -> Result<(), (StatusCode, String)>
where
    F: FnOnce(&mut DocumentMut) -> Result<(), String>,
{
    let raw = fs::read_to_string(path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read config: {e}")))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("config is not valid TOML: {e}")))?;

    mutator(&mut doc).map_err(|msg| {
        // Message-level errors map to 400 by default; callers needing a
        // specific status (e.g. 404) can set it via json_error_owned directly
        // before invoking mutate_config_file.
        if msg.contains("not found") {
            (StatusCode::NOT_FOUND, msg)
        } else if msg.contains("already exists") {
            (StatusCode::CONFLICT, msg)
        } else {
            (StatusCode::BAD_REQUEST, msg)
        }
    })?;

    write_document_atomic(path, &doc)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    Ok(())
}

async fn write_document_atomic(path: &Path, doc: &DocumentMut) -> anyhow::Result<()> {
    let contents = doc.to_string();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("config.toml")
    ));
    fs::write(&tmp, contents.as_bytes()).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

/// Find `[[uplink_group]]` table where `name == group`.
pub(crate) fn find_group_mut<'a>(doc: &'a mut DocumentMut, group: &str) -> Option<&'a mut Table> {
    let aot = doc.get_mut("uplink_group")?.as_array_of_tables_mut()?;
    for tbl in aot.iter_mut() {
        if tbl.get("name").and_then(|v| v.as_str()) == Some(group) {
            return Some(tbl);
        }
    }
    None
}

/// Get or init the canonical `[[outline.uplinks]]` array-of-tables. The
/// loader treats this top-level array as the source of truth: each entry
/// carries a `group = "..."` discriminator that links it to a
/// `[[uplink_group]]` table by name.
pub(super) fn get_or_init_outline_uplinks(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if !doc.contains_key("outline") {
        let mut t = Table::new();
        t.set_implicit(true);
        doc.insert("outline", Item::Table(t));
    }
    let outline_tbl = doc
        .get_mut("outline")
        .and_then(Item::as_table_mut)
        .expect("[outline] must be a table");
    if !outline_tbl.contains_key("uplinks") {
        outline_tbl.insert("uplinks", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    outline_tbl
        .get_mut("uplinks")
        .and_then(Item::as_array_of_tables_mut)
        .expect("outline.uplinks must be array-of-tables after insert")
}

/// Locate an entry inside `[[outline.uplinks]]` matching both `group` and
/// `name`. Uplink names are globally unique, but we also constrain on the
/// group field to keep the API symmetric (delete/patch always supply both).
pub(super) fn find_outline_uplink_index(arr: &ArrayOfTables, group: &str, name: &str) -> Option<usize> {
    arr.iter().position(|t| {
        t.get("group").and_then(|v| v.as_str()) == Some(group)
            && t.get("name").and_then(|v| v.as_str()) == Some(name)
    })
}

pub(super) fn count_uplinks_in_group(arr: &ArrayOfTables, group: &str) -> usize {
    arr.iter()
        .filter(|t| t.get("group").and_then(|v| v.as_str()) == Some(group))
        .count()
}
