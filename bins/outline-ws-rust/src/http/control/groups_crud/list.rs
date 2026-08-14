//! Read-only `GET /control/uplink_groups` handler.

use std::sync::Arc;

use http::StatusCode;
use tokio::fs;
use toml_edit::{DocumentMut, Item};

use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::mutate::count_uplinks_for_group;
use super::payload::{GroupListEntry, GroupsListResponse, table_to_json};

/// Extract one `GroupListEntry` per `[[uplink_group]]` on disk: name, uplink
/// count (across canonical + legacy uplink arrays), and the group's TOML table
/// as JSON for pre-filling the editor.
pub(super) fn group_entries_from_doc(doc: &DocumentMut) -> Vec<GroupListEntry> {
    let Some(groups) = doc.get("uplink_group").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|tbl| {
            let name = tbl.get("name").and_then(|v| v.as_str())?.to_string();
            let uplink_count = count_uplinks_for_group(doc, &name);
            Some(GroupListEntry {
                name,
                uplink_count,
                config: table_to_json(tbl),
            })
        })
        .collect()
}

pub(super) async fn handle_list(state: Arc<ControlState>, query: Option<&str>) -> ControlResponse {
    let Some(path) = &state.config_path else {
        return json_error(
            StatusCode::CONFLICT,
            "config file path unknown; CRUD endpoints need on-disk config",
        );
    };
    let mut filter_name: Option<String> = None;
    if let Some(q) = query {
        for (key, value) in url::form_urlencoded::parse(q.as_bytes()) {
            if key.as_ref() == "name" {
                filter_name = Some(value.into_owned());
            }
        }
    }

    let raw = match fs::read_to_string(path).await {
        Ok(s) => s,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to read config");
        },
    };
    let doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "config is not valid TOML"),
    };

    let mut entries = group_entries_from_doc(&doc);
    if let Some(name) = &filter_name {
        entries.retain(|e| &e.name == name);
        if entries.is_empty() {
            return json_error(StatusCode::NOT_FOUND, "uplink group not found");
        }
    }
    json_response(StatusCode::OK, &GroupsListResponse { groups: entries })
}

#[cfg(test)]
#[path = "tests/list.rs"]
mod tests;
