//! `/ss/dashboard/api/*` handlers — user CRUD proxied to instance control APIs.
//!
//! Every route takes `?instance=<name>`, resolves it in the configured list and
//! forwards to that instance's `/control/users*` with its bearer token injected
//! server-side. The browser never sees a control token, and `control_url` is
//! never advertised to it either.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use bytes::Bytes;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assets::{json_error, json_response};

use super::SsState;
use super::cluster::{ClusterSummaryView, build_access_keys_path, parse_nodes_query};

#[derive(Debug, Deserialize)]
pub struct InstanceQuery {
    instance: String,
}

#[derive(Debug, Deserialize)]
pub struct UserAccessKeysQuery {
    instance: String,
    #[serde(default)]
    nodes: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstancesResponse {
    instances: Vec<InstanceView>,
    clusters: Vec<ClusterSummaryView>,
    refresh_interval_secs: u64,
}

#[derive(Debug, Serialize)]
struct InstanceView {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mesh_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,
}

pub async fn list_instances(State(state): State<SsState>) -> Response {
    // Only the display name reaches the browser. `control_url` is a server-side
    // routing detail (and, with per-instance tokens, a target worth not
    // advertising); the UI selects instances by name.
    let mut membership: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for c in state.clusters.iter() {
        for m in &c.members {
            membership.insert(m.as_str(), c.name.as_str());
        }
    }

    let payload = InstancesResponse {
        instances: state
            .instances
            .iter()
            .map(|server| InstanceView {
                name: server.name.clone(),
                public_host: server.public_host.clone(),
                mesh_addr: server.mesh_addr.clone(),
                cluster: membership.get(server.name.as_str()).map(|s| (*s).to_owned()),
            })
            .collect(),
        clusters: state
            .clusters
            .iter()
            .map(|c| ClusterSummaryView {
                name: c.name.clone(),
                source: "config",
                members: c.members.clone(),
                subscription_nodes: c.subscription_nodes.clone(),
            })
            .collect(),
        refresh_interval_secs: state.refresh_ms / 1000,
    };
    json_response(StatusCode::OK, &serde_json::to_value(payload).unwrap_or_default())
}

pub async fn list_users(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    forward(&state, &query.instance, Method::GET, "/control/users", None).await
}

/// Effective server-wide default (the cipher) of one instance. The clone form
/// needs it to fill a user that carries none of its own: without the method it
/// cannot generate a password. Since the endpoint-model refactor this is the
/// only default the server exposes — users no longer carry per-user paths.
pub async fn defaults(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    forward(&state, &query.instance, Method::GET, "/control/defaults", None).await
}

pub async fn get_config(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    forward(&state, &query.instance, Method::GET, "/control/config", None).await
}

pub async fn patch_config(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    body: Bytes,
) -> Response {
    forward(&state, &query.instance, Method::PATCH, "/control/config", Some(body)).await
}

pub async fn create_user(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    body: Bytes,
) -> Response {
    forward(&state, &query.instance, Method::POST, "/control/users", Some(body)).await
}

pub async fn update_user(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}", encode_path_segment(&id));
    forward(&state, &query.instance, Method::PATCH, &path, Some(body)).await
}

pub async fn delete_user(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}", encode_path_segment(&id));
    forward(&state, &query.instance, Method::DELETE, &path, None).await
}

pub async fn block_user(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}/block", encode_path_segment(&id));
    forward(&state, &query.instance, Method::POST, &path, None).await
}

pub async fn unblock_user(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}/unblock", encode_path_segment(&id));
    forward(&state, &query.instance, Method::POST, &path, None).await
}

pub async fn regenerate_access_keys(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
    body: Bytes,
) -> Response {
    let payload = if body.is_empty() {
        Bytes::from_static(b"{}")
    } else {
        body
    };
    forward(
        &state,
        &query.instance,
        Method::POST,
        "/control/access-keys/regenerate",
        Some(payload),
    )
    .await
}

pub async fn get_user_access_keys(
    State(state): State<SsState>,
    Query(query): Query<UserAccessKeysQuery>,
    Path(id): Path<String>,
) -> Response {
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let nodes = parse_nodes_query(query.nodes.as_deref());
    let path = build_access_keys_path(&id, nodes.as_deref());
    forward(&state, &query.instance, Method::GET, &path, None).await
}

pub(super) fn is_valid_user_id(id: &str) -> bool {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return false;
    }
    if id.contains('/') || id.contains('\\') {
        return false;
    }
    true
}

/// Resolves the instance and passes the call through, mirroring the control
/// API's status and body back to the browser. An unreachable instance becomes a
/// 502 with the reason, so the UI can show which node failed.
async fn forward(
    state: &SsState,
    instance_name: &str,
    method: Method,
    path: &str,
    body: Option<Bytes>,
) -> Response {
    let Some(instance) = state.instances.iter().find(|i| i.name == instance_name) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };
    match state.backend.request(instance, method, path, body).await {
        Ok(response) => json_response(response.status, &parse_or_raw(&response.body)),
        Err(error) => json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({ "error": format!("{error:#}") }),
        ),
    }
}

/// Percent-encodes everything outside the unreserved set, so a user id can never
/// inject a path segment or a query into the control URL.
pub(super) fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                encoded.push(byte as char);
            },
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Control APIs answer JSON, but a proxy or a panic can put anything on the
/// wire. Non-JSON is handed to the browser as `{"raw": "..."}` rather than
/// turned into an error, so the operator sees what actually came back.
pub(super) fn parse_or_raw(body: &Bytes) -> Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(body) }))
}

#[cfg(test)]
#[path = "tests/api.rs"]
mod tests;
