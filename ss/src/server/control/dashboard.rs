//! Separate browser dashboard for managing users on configured control instances.
//!
//! The browser talks only to this listener. Per-instance bearer tokens stay in
//! the process config and are injected server-side when proxying to `/control`.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, Uri, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, patch, post},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::{DashboardConfig, DashboardInstanceConfig};

use super::super::shutdown::ShutdownSignal;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Clone)]
struct DashboardState {
    request_timeout_secs: u64,
    refresh_interval_secs: u64,
    instances: Arc<[DashboardInstanceConfig]>,
    tls_connector: TlsConnector,
}

#[derive(Debug, Deserialize)]
struct InstanceQuery {
    instance: String,
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
        instances = config.instances.len(),
        "dashboard server started"
    );

    let state = DashboardState {
        request_timeout_secs: config.request_timeout_secs,
        refresh_interval_secs: config.refresh_interval_secs,
        instances: Arc::from(config.instances),
        tls_connector: tls_connector(),
    };

    let router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(dashboard_page))
        .route("/dashboard/api/instances", get(list_instances))
        .route("/dashboard/api/users", get(list_users).post(create_user))
        .route("/dashboard/api/users/{id}", patch(update_user).delete(delete_user))
        .route("/dashboard/api/users/{id}/access-urls", get(get_user_access_urls))
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
    ([(header::CACHE_CONTROL, "no-store")], Html(DASHBOARD_HTML))
}

async fn list_instances(State(state): State<DashboardState>) -> impl IntoResponse {
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

async fn list_users(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    proxy_empty(state, query, Method::GET, "/control/users").await
}

async fn create_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Json(body): Json<Value>,
) -> Response {
    proxy_json(state, query, Method::POST, "/control/users", body).await
}

async fn update_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let path = format!("/control/users/{}", encode_path_segment(&id));
    proxy_json(state, query, Method::PATCH, &path, body).await
}

async fn delete_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}", encode_path_segment(&id));
    proxy_empty(state, query, Method::DELETE, &path).await
}

async fn get_user_access_urls(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/access-urls", encode_path_segment(&id));
    proxy_empty(state, query, Method::GET, &path).await
}

async fn block_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/block", encode_path_segment(&id));
    proxy_empty(state, query, Method::POST, &path).await
}

async fn unblock_user(
    State(state): State<DashboardState>,
    Query(query): Query<InstanceQuery>,
    Path(id): Path<String>,
) -> Response {
    let path = format!("/control/users/{}/unblock", encode_path_segment(&id));
    proxy_empty(state, query, Method::POST, &path).await
}

async fn proxy_empty(
    state: DashboardState,
    query: InstanceQuery,
    method: Method,
    path: &str,
) -> Response {
    proxy(state, query, method, path, None).await
}

async fn proxy_json(
    state: DashboardState,
    query: InstanceQuery,
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
    query: InstanceQuery,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Response {
    let Some(server) = state.instances.iter().find(|server| server.name == query.instance) else {
        return json_error(StatusCode::NOT_FOUND, "unknown instance");
    };
    match send_control_request(&state, server, method, path, body).await {
        Ok((status, body)) => response_with_body(status, body),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, format!("{error:#}")),
    }
}

async fn send_control_request(
    state: &DashboardState,
    server: &DashboardInstanceConfig,
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
    server: &DashboardInstanceConfig,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(StatusCode, Bytes)> {
    let target = ControlTarget::new(&server.control_url, path)?;
    let request = hyper::Request::builder()
        .method(method)
        .uri(target.path_and_query())
        .header(header::HOST, target.host_header())
        .header(header::AUTHORIZATION, format!("Bearer {}", server.token))
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .context("failed to build control request")?;

    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("failed to connect to {}:{}", target.host, target.port))?;

    match target.scheme {
        ControlScheme::Http => exchange(tcp, request).await,
        ControlScheme::Https => {
            let server_name =
                ServerName::try_from(target.host.clone()).context("invalid TLS server name")?;
            let tls = state
                .tls_connector
                .connect(server_name, tcp)
                .await
                .context("TLS handshake with control API failed")?;
            exchange(tls, request).await
        },
    }
}

async fn exchange<T>(io: T, request: hyper::Request<Full<Bytes>>) -> Result<(StatusCode, Bytes)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1 handshake with control API failed")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let response = sender.send_request(request).await.context("control request failed")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed to read control response body")?
        .to_bytes();
    Ok((status, body))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ControlScheme {
    Http,
    Https,
}

struct ControlTarget {
    scheme: ControlScheme,
    host: String,
    port: u16,
    path_and_query: String,
}

impl ControlTarget {
    fn new(base: &str, path: &str) -> Result<Self> {
        let uri = instance_uri(base, path)?;
        let scheme = match uri.scheme_str() {
            Some("http") => ControlScheme::Http,
            Some("https") => ControlScheme::Https,
            Some(other) => bail!("unsupported control_url scheme {other:?}"),
            None => bail!("control_url has no scheme"),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("control_url has no authority"))?;
        let host = authority.host().to_owned();
        let port = authority.port_u16().unwrap_or(match scheme {
            ControlScheme::Http => 80,
            ControlScheme::Https => 443,
        });
        let path_and_query = uri
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        Ok(Self { scheme, host, port, path_and_query })
    }

    fn host_header(&self) -> String {
        let default_port = match self.scheme {
            ControlScheme::Http => 80,
            ControlScheme::Https => 443,
        };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn path_and_query(&self) -> &str {
        &self.path_and_query
    }
}

fn instance_uri(base: &str, path: &str) -> Result<Uri> {
    let base_uri = base.parse::<Uri>().context("invalid control_url")?;
    let scheme = match base_uri.scheme_str() {
        Some("http" | "https") => base_uri.scheme_str().expect("matched above"),
        Some(other) => bail!("unsupported control_url scheme {other:?}"),
        None => bail!("control_url has no scheme"),
    };
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
    let uri = format!("{scheme}://{authority}{full_path}");
    uri.parse::<Uri>().context("failed to build control request URI")
}

fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
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
    fn instance_uri_supports_https() {
        let uri = instance_uri("https://edge.example.com:7443/admin", "/control/users").unwrap();
        assert_eq!(uri.to_string(), "https://edge.example.com:7443/admin/control/users");
    }

    #[test]
    fn encode_path_segment_escapes_slashes_and_spaces() {
        assert_eq!(encode_path_segment("team a/b"), "team%20a%2Fb");
    }
}
