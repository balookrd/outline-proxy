//! HTTP route handlers for the browser-facing dashboard.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::DashboardState;
use super::proxy;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const OUTLINE_LOGO_PNG: &[u8] = include_bytes!("outline-logo.png");

#[derive(Debug, Deserialize)]
pub(super) struct InstanceQuery {
    pub(super) instance: String,
}

#[derive(Debug, Serialize)]
struct InstancesResponse {
    instances: Vec<InstanceView>,
    refresh_interval_secs: u64,
}

#[derive(Debug, Serialize)]
struct InstanceView {
    name: String,
    control_url: String,
}

pub(super) async fn dashboard_page() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(DASHBOARD_HTML),
    )
}

pub(super) async fn dashboard_logo() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "public, max-age=604800"),
            (header::CONTENT_TYPE, "image/png"),
        ],
        OUTLINE_LOGO_PNG,
    )
}

pub(super) async fn list_instances(State(state): State<DashboardState>) -> impl IntoResponse {
    Json(InstancesResponse {
        instances: state
            .instances
            .iter()
            .map(|server| InstanceView {
                name: server.name.clone(),
                control_url: server.control_url.clone(),
            })
            .collect(),
        refresh_interval_secs: state.refresh_interval_secs,
    })
}

pub(super) async fn list_users(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    proxy::forward(state, query, Method::GET, "/control/users", None).await
}

pub(super) async fn create_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Json(body): Json<Value>,
) -> Response {
    proxy::forward_json(state, query, Method::POST, "/control/users", body).await
}

pub(super) async fn update_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let path = format!("/control/users/{}", encode_path_segment(&id));
    proxy::forward_json(state, query, Method::PATCH, &path, body).await
}

pub(super) async fn delete_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}", encode_path_segment(&id));
    proxy::forward(state, query, Method::DELETE, &path, None).await
}

pub(super) async fn get_user_access_urls(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/access-urls", encode_path_segment(&id));
    proxy::forward(state, query, Method::GET, &path, None).await
}

pub(super) async fn block_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/block", encode_path_segment(&id));
    proxy::forward(state, query, Method::POST, &path, None).await
}

pub(super) async fn unblock_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/unblock", encode_path_segment(&id));
    proxy::forward(state, query, Method::POST, &path, None).await
}

pub(super) async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            },
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_path_segment_escapes_slashes_and_spaces() {
        assert_eq!(encode_path_segment("team a/b"), "team%20a%2Fb");
    }
}
