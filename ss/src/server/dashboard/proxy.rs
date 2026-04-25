//! Forwards dashboard requests to the selected control-API instance.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::{
    Json,
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};

use crate::config::DashboardInstanceConfig;

use super::DashboardState;
use super::handlers::InstanceQuery;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub(super) async fn forward(
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

pub(super) async fn forward_json(
    state: DashboardState,
    query: InstanceQuery,
    method: Method,
    path: &str,
    body: Value,
) -> Response {
    match serde_json::to_vec(&body) {
        Ok(body) => forward(state, query, method, path, Some(body)).await,
        Err(error) => json_error(StatusCode::BAD_REQUEST, format!("invalid JSON: {error}")),
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
}
