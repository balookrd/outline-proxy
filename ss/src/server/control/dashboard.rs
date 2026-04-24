//! Separate browser dashboard for managing users on configured control servers.
//!
//! The browser talks only to this listener. Per-server bearer tokens stay in
//! the process config and are injected server-side when proxying to `/control`.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Method;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, time::timeout};
use tracing::{info, warn};

use crate::config::{DashboardConfig, DashboardServerConfig};

use super::{super::shutdown::ShutdownSignal, ui};

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Clone)]
struct DashboardState {
    request_timeout_secs: u64,
    servers: Arc<[DashboardServerConfig]>,
    client: HttpClient,
}

#[derive(Debug, Deserialize)]
struct ServerQuery {
    server: String,
}

#[derive(Debug, Serialize)]
struct ServersResponse {
    servers: Vec<ServerView>,
}

#[derive(Debug, Serialize)]
struct ServerView {
    name: String,
    control_url: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub(in crate::server) fn spawn_dashboard_server(config: DashboardConfig, shutdown: ShutdownSignal) {
    tokio::spawn(async move {
        if let Err(error) = run(config, shutdown).await {
            warn!(error = %format!("{error:#}"), "dashboard server stopped");
        }
    });
}

async fn run(config: DashboardConfig, mut shutdown: ShutdownSignal) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind dashboard listener {}", config.listen))?;
    info!(
        listen = %config.listen,
        servers = config.servers.len(),
        "dashboard server started"
    );

    let state = DashboardState {
        request_timeout_secs: config.request_timeout_secs,
        servers: Arc::from(config.servers),
        client: Client::builder(TokioExecutor::new()).build_http(),
    };

    let router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/api/servers", get(list_servers))
        .route("/dashboard/api/users", get(list_users).post(create_user))
        .route("/dashboard/api/users/{id}", delete(delete_user))
        .route("/dashboard/api/users/{id}/block", post(block_user))
        .route("/dashboard/api/users/{id}/unblock", post(unblock_user))
        .fallback(not_found)
        .with_state(state);

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("dashboard server exited unexpectedly")
}

async fn dashboard_page() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], Html(ui::dashboard_html()))
}

async fn list_servers(State(state): State<DashboardState>) -> impl IntoResponse {
    Json(ServersResponse {
        servers: state
            .servers
            .iter()
            .map(|server| ServerView {
                name: server.name.clone(),
                control_url: server.control_url.clone(),
            })
            .collect(),
    })
}

async fn list_users(
    State(state): State<DashboardState>,
    Query(query): Query<ServerQuery>,
) -> Response {
    proxy_empty(state, query, Method::GET, "/control/users").await
}

async fn create_user(
    State(state): State<DashboardState>,
    Query(query): Query<ServerQuery>,
    Json(body): Json<Value>,
) -> Response {
    proxy_json(state, query, Method::POST, "/control/users", body).await
}

async fn delete_user(
    State(state): State<DashboardState>,
    Query(query): Query<ServerQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}", encode_path_segment(&id));
    proxy_empty(state, query, Method::DELETE, &path).await
}

async fn block_user(
    State(state): State<DashboardState>,
    Query(query): Query<ServerQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/block", encode_path_segment(&id));
    proxy_empty(state, query, Method::POST, &path).await
}

async fn unblock_user(
    State(state): State<DashboardState>,
    Query(query): Query<ServerQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/unblock", encode_path_segment(&id));
    proxy_empty(state, query, Method::POST, &path).await
}

async fn proxy_empty(
    state: DashboardState,
    query: ServerQuery,
    method: Method,
    path: &str,
) -> Response {
    proxy(state, query, method, path, None).await
}

async fn proxy_json(
    state: DashboardState,
    query: ServerQuery,
    method: Method,
    path: &str,
    body: Value,
) -> Response {
    match serde_json::to_vec(&body) {
        Ok(body) => proxy(state, query, method, path, Some(body)).await,
        Err(error) => json_error(StatusCode::BAD_REQUEST, format!("invalid JSON: {error}")),
    }
}

async fn proxy(
    state: DashboardState,
    query: ServerQuery,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Response {
    let Some(server) = state.servers.iter().find(|server| server.name == query.server) else {
        return json_error(StatusCode::NOT_FOUND, "unknown server");
    };
    match send_control_request(&state, server, method, path, body).await {
        Ok((status, body)) => response_with_body(status, body),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, format!("{error:#}")),
    }
}

async fn send_control_request(
    state: &DashboardState,
    server: &DashboardServerConfig,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, Bytes)> {
    timeout(
        Duration::from_secs(state.request_timeout_secs),
        send_control_request_inner(state, server, method, path, body),
    )
    .await
    .context("control request timed out")?
}

async fn send_control_request_inner(
    state: &DashboardState,
    server: &DashboardServerConfig,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, Bytes)> {
    let uri = instance_uri(&server.control_url, path)?;
    let request = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", server.token))
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .context("failed to build control request")?;

    let response = state
        .client
        .request(request)
        .await
        .context("control request failed")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed to read control response body")?
        .to_bytes();
    Ok((status, body))
}

fn instance_uri(base: &str, path: &str) -> Result<Uri> {
    let base_uri = base.parse::<Uri>().context("invalid control_url")?;
    if base_uri.scheme_str() != Some("http") {
        bail!("only http:// control URLs are supported");
    }
    let authority = base_uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("control_url has no authority"))?;
    let prefix = base_uri.path().trim_end_matches('/');
    let suffix = path.strip_prefix('/').unwrap_or(path);
    let full_path = if prefix.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{prefix}/{suffix}")
    };
    let uri = format!("http://{authority}{full_path}");
    uri.parse::<Uri>().context("failed to build control request URI")
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

fn response_with_body(status: StatusCode, body: Bytes) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn json_error(status: StatusCode, error: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { error: error.into() })).into_response()
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_uri_preserves_base_path_prefix() {
        let uri = instance_uri("http://127.0.0.1:7001/admin", "/control/users").unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:7001/admin/control/users");
    }

    #[test]
    fn encode_path_segment_escapes_slashes_and_spaces() {
        assert_eq!(encode_path_segment("team a/b"), "team%20a%2Fb");
    }
}
