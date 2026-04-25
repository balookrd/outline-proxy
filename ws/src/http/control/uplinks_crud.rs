//! CRUD for `[[uplink_group.uplinks]]` entries in the running config file.
//!
//! These endpoints edit the on-disk TOML document in place (via `toml_edit`
//! to preserve comments and formatting) and return `restart_required: true`
//! — the running `UplinkRegistry` is not mutated, so changes take effect
//! only after the process is restarted. This is Stage 1 of the control-
//! plane CRUD; Stage 2 will swap the registry under an `ArcSwap` for live
//! application.

use std::path::Path;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tokio::fs;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};
use tracing::{info, warn};

use crate::config::UplinkSection;
use crate::config::validate_uplink_section;

use super::server::ControlState;
use super::{ControlResponse, json_error, json_response, plain_response};

// ─── wire types ──────────────────────────────────────────────────────────

/// JSON payload accepted by the CRUD endpoints. Intentionally mirrors
/// `UplinkSection` so users can round-trip config fields. Field semantics
/// match the TOML config (see `config::schema::UplinkSection`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UplinkPayload {
    pub(crate) name: Option<String>,
    pub(crate) transport: Option<String>,
    pub(crate) tcp_ws_url: Option<String>,
    pub(crate) tcp_ws_mode: Option<String>,
    pub(crate) udp_ws_url: Option<String>,
    pub(crate) udp_ws_mode: Option<String>,
    pub(crate) tcp_addr: Option<String>,
    pub(crate) udp_addr: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) weight: Option<f64>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) ipv6_first: Option<bool>,
    pub(crate) uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateBody {
    group: String,
    uplink: UplinkPayload,
}

#[derive(Debug, Deserialize)]
struct UpdateBody {
    group: String,
    name: String,
    patch: UplinkPayload,
}

#[derive(Debug, Deserialize)]
struct DeleteBody {
    group: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct MutationResponse {
    group: String,
    name: String,
    action: &'static str,
    restart_required: bool,
}

#[derive(Debug, Serialize)]
struct UplinkListEntry {
    group: String,
    name: String,
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct UplinkListResponse {
    uplinks: Vec<UplinkListEntry>,
}

// ─── entry points ────────────────────────────────────────────────────────

pub(crate) async fn handle_uplinks(
    request: Request<Incoming>,
    state: std::sync::Arc<ControlState>,
) -> ControlResponse {
    match *request.method() {
        Method::GET => handle_list(state.clone(), request.uri().query()).await,
        Method::POST => handle_create(request, state).await,
        Method::PATCH => handle_update(request, state).await,
        Method::DELETE => handle_delete(request, state).await,
        _ => plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "application/json; charset=utf-8",
            Bytes::from_static(br#"{"error":"use GET, POST, PATCH, or DELETE"}"#),
        ),
    }
}

async fn handle_list(
    state: std::sync::Arc<ControlState>,
    query: Option<&str>,
) -> ControlResponse {
    let mut filter_group: Option<String> = None;
    let mut filter_name: Option<String> = None;
    if let Some(q) = query {
        for (key, value) in url::form_urlencoded::parse(q.as_bytes()) {
            match key.as_ref() {
                "group" => filter_group = Some(value.into_owned()),
                "name" => filter_name = Some(value.into_owned()),
                _ => {},
            }
        }
    }

    let snapshots = state.uplinks.snapshots().await;
    let mut entries = Vec::new();
    for snap in &snapshots {
        if let Some(g) = &filter_group {
            if snap.group != *g {
                continue;
            }
        }
        for uplink in &snap.uplinks {
            if let Some(n) = &filter_name {
                if uplink.name != *n {
                    continue;
                }
            }
            entries.push(UplinkListEntry {
                group: snap.group.clone(),
                name: uplink.name.clone(),
                index: uplink.index,
                config: None,
            });
        }
    }

    // Best-effort enrichment: when the on-disk config is reachable, attach
    // each uplink's full TOML table as a JSON object so editors can pre-fill
    // forms. We swallow read/parse errors — the entries still carry the
    // identifying triple (group, name, index).
    if let Some(path) = &state.config_path {
        if let Ok(raw) = fs::read_to_string(path).await {
            if let Ok(mut doc) = raw.parse::<DocumentMut>() {
                for entry in entries.iter_mut() {
                    let Some(group_tbl) = find_group_mut(&mut doc, &entry.group) else {
                        continue;
                    };
                    let arr = get_or_init_uplinks_array(group_tbl);
                    let Some(idx) = find_uplink_index(arr, &entry.name) else {
                        continue;
                    };
                    if let Some(tbl) = arr.get(idx) {
                        entry.config = table_to_json(tbl);
                    }
                }
            }
        }
    }

    // Single-item GET with both filters set: 404 if missing.
    if filter_group.is_some() && filter_name.is_some() && entries.is_empty() {
        return json_error(StatusCode::NOT_FOUND, "uplink not found");
    }

    json_response(StatusCode::OK, &UplinkListResponse { uplinks: entries })
}

/// Convert a `toml_edit` table into a `serde_json::Value` by round-tripping
/// through a TOML string. Returns `None` if the round-trip fails (which
/// would be a surprising bug, not a normal user error).
fn table_to_json(tbl: &Table) -> Option<serde_json::Value> {
    let text = tbl.to_string();
    let value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(value).ok()
}

async fn handle_create(
    request: Request<Incoming>,
    state: std::sync::Arc<ControlState>,
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
    let section: UplinkSection = match payload_to_section(&body.uplink, Some(&body.group)) {
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
        let group_tbl = find_group_mut(doc, &body.group)
            .ok_or_else(|| format!("uplink_group \"{}\" not found", body.group))?;
        let arr = get_or_init_uplinks_array(group_tbl);
        if find_uplink_index(arr, &name).is_some() {
            return Err(format!(
                "uplink \"{name}\" already exists in group \"{}\" on disk",
                body.group
            ));
        }
        arr.push(payload_to_table(&body.uplink));
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

async fn handle_update(
    request: Request<Incoming>,
    state: std::sync::Arc<ControlState>,
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

    let group_tbl = match find_group_mut(&mut doc, &body.group) {
        Some(t) => t,
        None => {
            return json_error_owned(
                StatusCode::NOT_FOUND,
                format!("uplink_group \"{}\" not found", body.group),
            );
        },
    };
    let arr = get_or_init_uplinks_array(group_tbl);
    let idx = match find_uplink_index(arr, &body.name) {
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

async fn handle_delete(
    request: Request<Incoming>,
    state: std::sync::Arc<ControlState>,
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
        let group_tbl = find_group_mut(doc, &group_name)
            .ok_or_else(|| format!("uplink_group \"{group_name}\" not found"))?;
        let arr = get_or_init_uplinks_array(group_tbl);
        let idx = find_uplink_index(arr, &uplink_name)
            .ok_or_else(|| format!("uplink \"{uplink_name}\" not found in group \"{group_name}\""))?;
        if arr.len() <= 1 {
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

// ─── config-file mutation primitives ─────────────────────────────────────

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

fn get_or_init_uplinks_array(group_tbl: &mut Table) -> &mut ArrayOfTables {
    if !group_tbl.contains_key("uplinks") {
        group_tbl.insert("uplinks", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    group_tbl
        .get_mut("uplinks")
        .and_then(Item::as_array_of_tables_mut)
        .expect("uplinks must be array-of-tables after insert")
}

fn find_uplink_index(arr: &ArrayOfTables, name: &str) -> Option<usize> {
    arr.iter()
        .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
}

// ─── payload <-> table conversion ────────────────────────────────────────

fn payload_to_table(payload: &UplinkPayload) -> Table {
    let mut tbl = Table::new();
    fn set_str(tbl: &mut Table, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            tbl.insert(key, Item::Value(Value::from(v)));
        }
    }
    set_str(&mut tbl, "name", payload.name.as_deref());
    set_str(&mut tbl, "transport", payload.transport.as_deref());
    set_str(&mut tbl, "tcp_ws_url", payload.tcp_ws_url.as_deref());
    set_str(&mut tbl, "tcp_ws_mode", payload.tcp_ws_mode.as_deref());
    set_str(&mut tbl, "udp_ws_url", payload.udp_ws_url.as_deref());
    set_str(&mut tbl, "udp_ws_mode", payload.udp_ws_mode.as_deref());
    set_str(&mut tbl, "tcp_addr", payload.tcp_addr.as_deref());
    set_str(&mut tbl, "udp_addr", payload.udp_addr.as_deref());
    set_str(&mut tbl, "method", payload.method.as_deref());
    set_str(&mut tbl, "password", payload.password.as_deref());
    if let Some(w) = payload.weight {
        tbl.insert("weight", Item::Value(Value::from(w)));
    }
    if let Some(fw) = payload.fwmark {
        tbl.insert("fwmark", Item::Value(Value::from(fw as i64)));
    }
    if let Some(v) = payload.ipv6_first {
        tbl.insert("ipv6_first", Item::Value(Value::from(v)));
    }
    set_str(&mut tbl, "uuid", payload.uuid.as_deref());
    tbl
}

fn merge_patch_into_table(tbl: &mut Table, patch: &UplinkPayload) {
    fn set_str(tbl: &mut Table, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            tbl.insert(key, Item::Value(Value::from(v)));
        }
    }
    // `name` is deliberately *not* merged: the identity key lives in the URL
    // body, so a patch cannot rename an uplink. This keeps the write-locked
    // find → mutate path stable.
    if let Some(v) = patch.transport.as_deref() {
        set_str(tbl, "transport", Some(v));
    }
    if let Some(v) = patch.tcp_ws_url.as_deref() {
        set_str(tbl, "tcp_ws_url", Some(v));
    }
    if let Some(v) = patch.tcp_ws_mode.as_deref() {
        set_str(tbl, "tcp_ws_mode", Some(v));
    }
    if let Some(v) = patch.udp_ws_url.as_deref() {
        set_str(tbl, "udp_ws_url", Some(v));
    }
    if let Some(v) = patch.udp_ws_mode.as_deref() {
        set_str(tbl, "udp_ws_mode", Some(v));
    }
    if let Some(v) = patch.tcp_addr.as_deref() {
        set_str(tbl, "tcp_addr", Some(v));
    }
    if let Some(v) = patch.udp_addr.as_deref() {
        set_str(tbl, "udp_addr", Some(v));
    }
    if let Some(v) = patch.method.as_deref() {
        set_str(tbl, "method", Some(v));
    }
    if let Some(v) = patch.password.as_deref() {
        set_str(tbl, "password", Some(v));
    }
    if let Some(w) = patch.weight {
        tbl.insert("weight", Item::Value(Value::from(w)));
    }
    if let Some(fw) = patch.fwmark {
        tbl.insert("fwmark", Item::Value(Value::from(fw as i64)));
    }
    if let Some(v) = patch.ipv6_first {
        tbl.insert("ipv6_first", Item::Value(Value::from(v)));
    }
    if let Some(v) = patch.uuid.as_deref() {
        set_str(tbl, "uuid", Some(v));
    }
}

/// Convert the JSON payload to an `UplinkSection` for validation. We go via
/// TOML text so the serde shapes (e.g. `CipherKind`, `ServerAddr`) get
/// parsed through their existing `Deserialize` impls.
fn payload_to_section(
    payload: &UplinkPayload,
    fallback_group: Option<&str>,
) -> Result<UplinkSection, String> {
    let mut tbl = payload_to_table(payload);
    if !tbl.contains_key("group") {
        if let Some(g) = fallback_group {
            tbl.insert("group", Item::Value(Value::from(g)));
        }
    }
    table_to_section(&tbl)
}

fn table_to_section(tbl: &Table) -> Result<UplinkSection, String> {
    let text = tbl.to_string();
    toml::from_str::<UplinkSection>(&text).map_err(|e| e.to_string())
}

// ─── small helpers ───────────────────────────────────────────────────────

async fn read_json<T: for<'de> Deserialize<'de>>(
    request: Request<Incoming>,
) -> Result<T, ControlResponse> {
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            warn!(error = %e, "failed to read control request body");
            json_error(StatusCode::BAD_REQUEST, "failed to read request body")
        })?
        .to_bytes();
    serde_json::from_slice::<T>(&body).map_err(|e| {
        json_error_owned(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"))
    })
}

fn json_error_owned(status: StatusCode, message: String) -> ControlResponse {
    #[derive(Serialize)]
    struct Owned {
        error: String,
    }
    json_response(status, &Owned { error: message })
}

// Compile-time hint: `Array` is exported so downstream tests compile even
// when toml_edit's re-exports shift between minor versions.
#[allow(dead_code)]
fn _toml_edit_array_unused() -> Array {
    Array::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> &'static str {
        r#"# Test config
[[uplink_group]]
name = "core"

  [[uplink_group.uplinks]]
  name = "u1"
  transport = "shadowsocks"
  tcp_addr = "1.2.3.4:8388"
  method = "chacha20-ietf-poly1305"
  password = "secret-password-1"

  [[uplink_group.uplinks]]
  name = "u2"
  transport = "shadowsocks"
  tcp_addr = "5.6.7.8:8388"
  method = "chacha20-ietf-poly1305"
  password = "secret-password-2"
"#
    }

    #[test]
    fn finds_group_by_name() {
        let mut doc = sample_config().parse::<DocumentMut>().unwrap();
        assert!(find_group_mut(&mut doc, "core").is_some());
        assert!(find_group_mut(&mut doc, "missing").is_none());
    }

    #[test]
    fn finds_uplink_index_by_name() {
        let mut doc = sample_config().parse::<DocumentMut>().unwrap();
        let group = find_group_mut(&mut doc, "core").unwrap();
        let arr = get_or_init_uplinks_array(group);
        assert_eq!(find_uplink_index(arr, "u1"), Some(0));
        assert_eq!(find_uplink_index(arr, "u2"), Some(1));
        assert_eq!(find_uplink_index(arr, "u3"), None);
    }

    #[test]
    fn insert_appends_uplink_table() {
        let mut doc = sample_config().parse::<DocumentMut>().unwrap();
        let group = find_group_mut(&mut doc, "core").unwrap();
        let arr = get_or_init_uplinks_array(group);
        let payload = UplinkPayload {
            name: Some("u3".into()),
            transport: Some("shadowsocks".into()),
            tcp_addr: Some("9.9.9.9:8388".into()),
            method: Some("chacha20-ietf-poly1305".into()),
            password: Some("secret-password-3".into()),
            ..Default::default()
        };
        arr.push(payload_to_table(&payload));
        let rendered = doc.to_string();
        assert!(rendered.contains("\"u3\""), "missing inserted uplink:\n{rendered}");
        assert!(rendered.contains("9.9.9.9:8388"));
    }

    #[test]
    fn merge_patch_updates_existing_fields_only() {
        let mut doc = sample_config().parse::<DocumentMut>().unwrap();
        let group = find_group_mut(&mut doc, "core").unwrap();
        let arr = get_or_init_uplinks_array(group);
        let idx = find_uplink_index(arr, "u1").unwrap();
        let patch = UplinkPayload {
            password: Some("new-password".into()),
            weight: Some(2.5),
            ..Default::default()
        };
        merge_patch_into_table(arr.get_mut(idx).unwrap(), &patch);
        let rendered = doc.to_string();
        assert!(rendered.contains("new-password"));
        assert!(rendered.contains("2.5"));
        // Unmodified field survives.
        assert!(rendered.contains("1.2.3.4:8388"));
    }

    #[test]
    fn remove_drops_entry() {
        let mut doc = sample_config().parse::<DocumentMut>().unwrap();
        let group = find_group_mut(&mut doc, "core").unwrap();
        let arr = get_or_init_uplinks_array(group);
        let idx = find_uplink_index(arr, "u1").unwrap();
        arr.remove(idx);
        let rendered = doc.to_string();
        assert!(!rendered.contains("\"u1\""));
        assert!(rendered.contains("\"u2\""));
    }

    #[test]
    fn payload_round_trip_validates_as_section() {
        let payload = UplinkPayload {
            name: Some("u9".into()),
            transport: Some("shadowsocks".into()),
            tcp_addr: Some("1.1.1.1:8388".into()),
            method: Some("chacha20-ietf-poly1305".into()),
            password: Some("some-long-password".into()),
            ..Default::default()
        };
        let section = payload_to_section(&payload, Some("core")).unwrap();
        assert_eq!(section.name.as_deref(), Some("u9"));
        validate_uplink_section(&section, 0).unwrap();
    }

    #[test]
    fn validation_rejects_missing_password_for_shadowsocks() {
        let payload = UplinkPayload {
            name: Some("u9".into()),
            transport: Some("shadowsocks".into()),
            tcp_addr: Some("1.1.1.1:8388".into()),
            method: Some("chacha20-ietf-poly1305".into()),
            // password intentionally missing
            ..Default::default()
        };
        let section = payload_to_section(&payload, Some("core")).unwrap();
        assert!(validate_uplink_section(&section, 0).is_err());
    }
}
