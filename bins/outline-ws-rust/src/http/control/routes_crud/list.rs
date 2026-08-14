//! `GET /control/routes` — reads the on-disk `[[route]]` array (staged state),
//! indexes each rule, and reports the declared group names for the `via`
//! picker. There is no live routing snapshot to read, so this reflects the
//! config file, which is exactly what the editor needs.

use std::sync::Arc;

use http::StatusCode;
use toml_edit::{DocumentMut, Item};

use crate::http::control::config_edit::{json_error_owned, table_to_json};
use crate::http::control::server::ControlState;
use crate::http::control::{ControlResponse, json_error, json_response};

use super::mutate::group_names_in_doc;
use super::payload::{RouteListEntry, RoutesListResponse, route_revision, table_is_default};

pub(super) async fn handle_list(state: Arc<ControlState>) -> ControlResponse {
    let Some(path) = state.config_path.clone() else {
        return json_error(StatusCode::CONFLICT, "config file path unknown");
    };
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read config: {e}"),
            );
        },
    };
    let doc = match raw.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return json_error_owned(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config is not valid TOML: {e}"),
            );
        },
    };
    let arr = doc.get("route").and_then(Item::as_array_of_tables);
    let routes = arr
        .map(|a| {
            a.iter()
                .enumerate()
                .map(|(index, t)| RouteListEntry {
                    index,
                    is_default: table_is_default(t),
                    config: table_to_json(t),
                })
                .collect()
        })
        .unwrap_or_default();
    let revision = arr.map(route_revision).unwrap_or_default();
    json_response(
        StatusCode::OK,
        &RoutesListResponse {
            routes,
            groups: group_names_in_doc(&doc),
            revision,
        },
    )
}
