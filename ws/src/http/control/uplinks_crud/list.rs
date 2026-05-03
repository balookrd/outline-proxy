//! Read-only `GET /control/uplinks` handler.

use std::sync::Arc;

use http::StatusCode;
use tokio::fs;
use toml_edit::DocumentMut;

use crate::http::control::{ControlResponse, json_error, json_response};
use crate::http::control::server::ControlState;

use super::mutate::{find_outline_uplink_index, get_or_init_outline_uplinks};
use super::payload::{UplinkListEntry, UplinkListResponse, table_to_json};

pub(super) async fn handle_list(
    state: Arc<ControlState>,
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
                let arr = get_or_init_outline_uplinks(&mut doc);
                for entry in entries.iter_mut() {
                    let Some(idx) = find_outline_uplink_index(arr, &entry.group, &entry.name)
                    else {
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
