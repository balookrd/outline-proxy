//! Built-in dashboard for monitoring and switching configured instances.
//!
//! The browser talks only to this listener. Instance bearer tokens stay in the
//! process config and are used server-side when proxying to each control API.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::header::{HeaderValue, CONTENT_TYPE, LOCATION};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::{DashboardConfig, DashboardInstanceConfig};

type DashboardResponse = Response<Full<Bytes>>;

#[derive(Clone)]
struct DashboardState {
    refresh_interval_secs: u64,
    request_timeout_secs: u64,
    instances: Vec<DashboardInstanceConfig>,
}

pub fn spawn_dashboard_server(config: DashboardConfig) {
    let listen = config.listen;
    let state = DashboardState {
        refresh_interval_secs: config.refresh_interval_secs,
        request_timeout_secs: config.request_timeout_secs,
        instances: config.instances,
    };
    tokio::spawn(async move {
        if let Err(error) = run_dashboard_server(listen, state).await {
            warn!(error = %format!("{error:#}"), "dashboard server stopped");
        }
    });
}

async fn run_dashboard_server(listen: std::net::SocketAddr, state: DashboardState) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind dashboard listener {listen}"))?;
    info!(%listen, instances = state.instances.len(), "dashboard server started");

    loop {
        let (stream, peer) = listener.accept().await.context("dashboard accept failed")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, state).await {
                warn!(%peer, error = %format!("{error:#}"), "dashboard request failed");
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, state: DashboardState) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .serve_connection(
            io,
            service_fn(move |request: Request<Incoming>| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_request(request, state).await) }
            }),
        )
        .await
        .context("failed to serve dashboard HTTP connection")?;
    Ok(())
}

async fn handle_request(request: Request<Incoming>, state: DashboardState) -> DashboardResponse {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => redirect_response("/dashboard"),
        (&Method::GET, "/dashboard") => html_response(dashboard_html(state.refresh_interval_secs)),
        (&Method::GET, "/dashboard/api/topology") => handle_topology(state).await,
        (&Method::POST, "/dashboard/api/activate") => handle_activate(request, state).await,
        _ => plain_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found\n"),
        ),
    }
}

#[derive(Debug, Serialize)]
struct DashboardTopologyResponse {
    refresh_interval_secs: u64,
    instances: Vec<DashboardInstanceView>,
}

#[derive(Debug, Serialize)]
struct DashboardInstanceView {
    name: String,
    ok: bool,
    topology: Option<Value>,
    error: Option<String>,
}

async fn handle_topology(state: DashboardState) -> DashboardResponse {
    let mut instances = Vec::with_capacity(state.instances.len());
    for instance in &state.instances {
        let view = match fetch_instance_topology(instance, state.request_timeout_secs).await {
            Ok(topology) => DashboardInstanceView {
                name: instance.name.clone(),
                ok: true,
                topology: Some(topology),
                error: None,
            },
            Err(error) => DashboardInstanceView {
                name: instance.name.clone(),
                ok: false,
                topology: None,
                error: Some(format!("{error:#}")),
            },
        };
        instances.push(view);
    }

    json_response(
        StatusCode::OK,
        &DashboardTopologyResponse {
            refresh_interval_secs: state.refresh_interval_secs,
            instances,
        },
    )
}

#[derive(Debug, Deserialize)]
struct DashboardActivateRequest {
    targets: Vec<DashboardActivateTarget>,
    #[serde(default)]
    transport: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DashboardActivateTarget {
    instance: String,
    group: String,
    uplink: String,
}

#[derive(Debug, Serialize)]
struct DashboardActivateResponse {
    results: Vec<DashboardActivateResult>,
}

#[derive(Debug, Serialize)]
struct DashboardActivateResult {
    target: DashboardActivateTarget,
    ok: bool,
    status: Option<u16>,
    body: Option<Value>,
    error: Option<String>,
}

async fn handle_activate(request: Request<Incoming>, state: DashboardState) -> DashboardResponse {
    let body = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to read dashboard activate body");
            return json_error(StatusCode::BAD_REQUEST, "invalid request body");
        },
    };
    let payload: DashboardActivateRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            let msg = format!("invalid JSON: {error}");
            return json_response(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": msg }));
        },
    };
    if payload.targets.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "targets must not be empty");
    }
    if let Some(transport) = payload.transport.as_deref() {
        if !matches!(transport, "tcp" | "udp" | "both") {
            return json_error(StatusCode::BAD_REQUEST, "transport must be tcp, udp, or both");
        }
    }

    let mut results = Vec::with_capacity(payload.targets.len());
    for target in payload.targets {
        let instance = state
            .instances
            .iter()
            .find(|instance| instance.name == target.instance);
        let result = match instance {
            Some(instance) => {
                match activate_instance(
                    instance,
                    &target,
                    payload.transport.as_deref(),
                    state.request_timeout_secs,
                )
                .await
                {
                    Ok((status, body)) => DashboardActivateResult {
                        target,
                        ok: status.is_success(),
                        status: Some(status.as_u16()),
                        body: Some(body),
                        error: None,
                    },
                    Err(error) => DashboardActivateResult {
                        target,
                        ok: false,
                        status: None,
                        body: None,
                        error: Some(format!("{error:#}")),
                    },
                }
            },
            None => DashboardActivateResult {
                target,
                ok: false,
                status: None,
                body: None,
                error: Some("unknown instance".to_string()),
            },
        };
        results.push(result);
    }

    json_response(StatusCode::OK, &DashboardActivateResponse { results })
}

async fn fetch_instance_topology(
    instance: &DashboardInstanceConfig,
    request_timeout_secs: u64,
) -> Result<Value> {
    let url = instance_url(&instance.control_url, "/control/topology")?;
    let (status, body) =
        send_instance_request(instance, Method::GET, url, None, request_timeout_secs).await?;
    if !status.is_success() {
        bail!("{} returned HTTP {status}", instance.name);
    }
    serde_json::from_slice(&body).context("invalid topology JSON")
}

async fn activate_instance(
    instance: &DashboardInstanceConfig,
    target: &DashboardActivateTarget,
    transport: Option<&str>,
    request_timeout_secs: u64,
) -> Result<(StatusCode, Value)> {
    let url = instance_url(&instance.control_url, "/control/activate")?;
    let mut payload = serde_json::json!({
        "group": target.group,
        "uplink": target.uplink,
    });
    if let Some(transport) = transport {
        payload["transport"] = Value::String(transport.to_string());
    }
    let body = serde_json::to_vec(&payload)?;
    let (status, response_body) = send_instance_request(
        instance,
        Method::POST,
        url,
        Some(body),
        request_timeout_secs,
    )
    .await?;
    let parsed = serde_json::from_slice(&response_body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&response_body) }));
    Ok((status, parsed))
}

fn instance_url(base: &Url, path: &str) -> Result<Url> {
    let mut url = base.clone();
    let base_path = base.path().trim_end_matches('/');
    let suffix = path.strip_prefix('/').unwrap_or(path);
    let full_path = if base_path.is_empty() {
        format!("/{suffix}")
    } else {
        format!("{base_path}/{suffix}")
    };
    url.set_path(&full_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

async fn send_instance_request(
    instance: &DashboardInstanceConfig,
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
    request_timeout_secs: u64,
) -> Result<(StatusCode, Vec<u8>)> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http:// and https:// control URLs are supported");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("control_url has no host"))?;
    let port = url.port_or_known_default().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let body = body.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        instance.token,
        body.len()
    );

    let response = timeout(Duration::from_secs(request_timeout_secs), async {
        let stream = TcpStream::connect((host, port)).await?;
        if url.scheme() == "https" {
            let tls = dashboard_tls_connector();
            let server_name = ServerName::try_from(host.to_string())
                .context("invalid TLS server name")?;
            let tls_stream = tls.connect(server_name, stream).await?;
            send_raw_http_request(tls_stream, request.as_bytes(), &body).await
        } else {
            send_raw_http_request(stream, request.as_bytes(), &body).await
        }
    }).await.context("instance request timed out")??;

    parse_http_response(&response)
}

fn dashboard_tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(std::sync::Arc::new(config))
}

async fn send_raw_http_request<T>(
    mut stream: T,
    head: &[u8],
    body: &[u8],
) -> Result<Vec<u8>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(head).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    let mut response = Vec::new();
    let mut header_end = None;
    while header_end.is_none() {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            bail!("invalid HTTP response");
        }
        response.extend_from_slice(&buf[..n]);
        header_end = response.windows(4).position(|window| window == b"\r\n\r\n");
    }

    let header_end = header_end.expect("header_end just checked");
    let head = std::str::from_utf8(&response[..header_end]).context("invalid response headers")?;
    let mut content_length = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("Transfer-Encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let body_start = header_end + 4;
    if let Some(content_length) = content_length {
        while response.len() < body_start + content_length {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                bail!("truncated HTTP response body");
            }
            response.extend_from_slice(&buf[..n]);
        }
        response.truncate(body_start + content_length);
        return Ok(response);
    }

    if chunked {
        while !has_complete_chunked_body(&response[body_start..])? {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                bail!("truncated chunked HTTP response body");
            }
            response.extend_from_slice(&buf[..n]);
        }
        let decoded = decode_chunked_body(&response[body_start..])?;
        let mut out = response[..body_start].to_vec();
        out.extend_from_slice(&decoded);
        return Ok(out);
    }

    stream.read_to_end(&mut response).await?;
    Ok(response)
}

fn parse_http_response(response: &[u8]) -> Result<(StatusCode, Vec<u8>)> {
    let split_at = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?;
    let head = std::str::from_utf8(&response[..split_at]).context("invalid response headers")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP status"))?;
    Ok((status, response[split_at + 4..].to_vec()))
}

fn has_complete_chunked_body(body: &[u8]) -> Result<bool> {
    let mut offset = 0usize;
    loop {
        let Some(line_end_rel) = body[offset..].windows(2).position(|window| window == b"\r\n")
        else {
            return Ok(false);
        };
        let line_end = offset + line_end_rel;
        let size_line = std::str::from_utf8(&body[offset..line_end]).context("invalid chunk size")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).context("invalid chunk size")?;
        offset = line_end + 2;
        if body.len() < offset + size + 2 {
            return Ok(false);
        }
        offset += size;
        if &body[offset..offset + 2] != b"\r\n" {
            bail!("invalid chunk terminator");
        }
        offset += 2;
        if size == 0 {
            return Ok(true);
        }
    }
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let line_end_rel = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| anyhow::anyhow!("invalid chunked body"))?;
        let line_end = offset + line_end_rel;
        let size_line = std::str::from_utf8(&body[offset..line_end]).context("invalid chunk size")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).context("invalid chunk size")?;
        offset = line_end + 2;
        if size == 0 {
            break;
        }
        out.extend_from_slice(&body[offset..offset + size]);
        offset += size + 2;
    }
    Ok(out)
}

fn redirect_response(location: &'static str) -> DashboardResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::FOUND;
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static(location));
    response
}

fn html_response(body: String) -> DashboardResponse {
    plain_response(StatusCode::OK, "text/html; charset=utf-8", Bytes::from(body))
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> DashboardResponse {
    match serde_json::to_vec(payload) {
        Ok(body) => plain_response(status, "application/json; charset=utf-8", Bytes::from(body)),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "failed to serialize dashboard JSON response");
            plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                Bytes::from_static(br#"{"error":"internal server error"}"#),
            )
        },
    }
}

fn json_error(status: StatusCode, message: &'static str) -> DashboardResponse {
    json_response(status, &serde_json::json!({ "error": message }))
}

fn plain_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> DashboardResponse {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn dashboard_html(refresh_interval_secs: u64) -> String {
    format!(
        r##"<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Dashboard</title>
<style>
:root {{
  color-scheme: light;
  --nav: #0f172a;
  --nav-2: #1e293b;
  --nav-3: #273449;
  --nav-text: #cbd5e1;
  --nav-muted: #94a3b8;
  --text: #0f172a;
  --muted: #64748b;
  --line: #e2e8f0;
  --line-strong: #cbd5e1;
  --soft: #f1f5f9;
  --soft-2: #f8fafc;
  --panel: #ffffff;
  --panel-tint: #f8fafc;
  --green: #22c55e;
  --green-strong: #15803d;
  --green-soft: #dcfce7;
  --amber: #f59e0b;
  --amber-soft: #fef3c7;
  --gray-soft: #f1f5f9;
  --blue: #6366f1;
  --blue-soft: #eef2ff;
  --red: #dc2626;
  --red-soft: #fee2e2;
  --shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--text); background: #fff; font-size: 14px; }}
.shell {{ min-height: 100vh; display: grid; grid-template-columns: 220px 1fr; }}
.nav {{ background: var(--nav); color: var(--nav-text); display: flex; flex-direction: column; min-height: 100vh; }}
.brand {{ height: 64px; display: flex; gap: 10px; align-items: center; padding: 0 18px; font-weight: 600; color: #fff; font-size: 15px; }}
.logo {{ width: 30px; height: 30px; border-radius: 8px; background: linear-gradient(135deg, #6366f1, #4f46e5); display: grid; place-items: center; color: #fff; font-size: 14px; font-weight: 700; }}
.menu {{ padding: 8px 10px; display: grid; gap: 2px; }}
.item {{ height: 38px; width: 100%; border: 0; border-radius: 8px; display: flex; align-items: center; gap: 10px; padding: 0 12px; color: var(--nav-text); background: transparent; text-align: left; font-size: 13.5px; cursor: pointer; }}
.item:hover {{ background: rgba(255,255,255,0.04); }}
.item.active {{ background: var(--blue); color: #fff; }}
.item-icon {{ width: 16px; display: inline-grid; place-items: center; font-size: 14px; opacity: .85; }}
.spacer {{ flex: 1; }}
.nav-footer {{ padding: 10px; display: grid; gap: 8px; }}
.nav-card {{ border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 10px 12px; display: grid; gap: 4px; background: rgba(255,255,255,0.02); }}
.nav-card-title {{ color: var(--nav-muted); font-size: 11.5px; }}
.nav-card-value {{ display: flex; align-items: center; gap: 8px; color: #fff; font-size: 12.5px; }}
.nav-card-value .dot {{ width: 7px; height: 7px; border-radius: 99px; background: var(--green); }}
main {{ padding: 22px 28px; min-width: 0; background: #fff; }}
.topbar {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 20px; }}
.topbar-copy {{ display: grid; gap: 4px; }}
h1 {{ margin: 0; font-size: 22px; line-height: 1.2; font-weight: 600; }}
.subtitle {{ color: var(--muted); font-size: 13px; }}
.toolbar {{ display: flex; align-items: center; gap: 10px; }}
.updated-inline {{ color: var(--muted); font-size: 12.5px; display: flex; align-items: center; gap: 6px; }}
.refresh {{ border: 1px solid var(--line); background: #fff; border-radius: 8px; padding: 6px 10px; display: flex; align-items: center; gap: 6px; color: #334155; font-size: 12.5px; cursor: pointer; }}
.refresh.off {{ color: var(--muted); background: var(--soft-2); }}
.dot {{ width: 8px; height: 8px; border-radius: 99px; background: var(--green); display: inline-block; }}
.refresh.off .dot {{ background: #cbd5e1; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }}
.summary-card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; box-shadow: var(--shadow); display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; }}
.summary-copy {{ display: grid; gap: 6px; min-width: 0; }}
.summary-label {{ color: var(--muted); font-size: 12px; font-weight: 500; }}
.summary-value {{ font-size: 26px; font-weight: 700; line-height: 1; }}
.summary-value.good {{ color: var(--green); }}
.summary-icon {{ width: 32px; height: 32px; border-radius: 8px; display: grid; place-items: center; background: var(--soft); color: var(--blue); font-size: 15px; flex: 0 0 auto; }}
.summary-icon.good {{ background: var(--green-soft); color: var(--green-strong); }}
.summary-icon.warn {{ background: var(--blue-soft); color: var(--blue); }}
.summary-icon.muted {{ background: var(--gray-soft); color: var(--muted); }}
.stack {{ display: grid; gap: 10px; }}
.instance-panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; box-shadow: var(--shadow); }}
.instance-panel.collapsed .instance-panel-body {{ display: none; }}
.instance-panel-header {{ min-height: 54px; display: flex; align-items: center; gap: 12px; padding: 14px 18px; cursor: pointer; user-select: none; }}
.instance-panel:not(.collapsed) .instance-panel-header {{ border-bottom: 1px solid var(--line); }}
.panel-title {{ display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }}
.panel-title strong {{ font-size: 15px; font-weight: 600; }}
.collapse-chev {{ color: var(--muted); font-size: 14px; transition: transform .15s; }}
.instance-panel.collapsed .collapse-chev {{ transform: rotate(180deg); }}
.instance-panel-body {{ padding: 14px 18px 18px; display: grid; gap: 12px; background: var(--panel); }}
.section-title {{ font-size: 13px; font-weight: 600; color: #334155; }}
.group-table {{ border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: var(--panel); }}
.group-table-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 14px; background: var(--panel-tint); border-bottom: 1px solid var(--line); cursor: pointer; user-select: none; }}
.group-table.collapsed .rows {{ display: none; }}
.group-table.collapsed .group-table-head {{ border-bottom: 0; }}
.group-table-title {{ display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13.5px; }}
.group-count {{ padding: 2px 8px; border-radius: 999px; background: var(--gray-soft); color: var(--muted); font-size: 11.5px; font-weight: 500; }}
.group-table-meta {{ display: flex; align-items: center; gap: 10px; color: var(--green-strong); font-size: 12px; flex-wrap: wrap; justify-content: flex-end; }}
.cfg-chips {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
.cfg-chip {{ display: inline-flex; align-items: center; gap: 5px; border-radius: 6px; padding: 3px 8px; font-size: 11.5px; font-weight: 500; background: var(--soft); color: #334155; border: 1px solid var(--line); }}
.cfg-chip .cfg-key {{ color: var(--muted); font-weight: 500; }}
.cfg-chip.mode {{ background: var(--blue-soft); color: #3730a3; border-color: #e0e7ff; }}
.cfg-chip.scope {{ background: #ecfeff; color: #155e75; border-color: #cffafe; }}
.cfg-chip.fb-on {{ background: var(--green-soft); color: var(--green-strong); border-color: #bbf7d0; }}
.cfg-chip.fb-off {{ background: var(--gray-soft); color: var(--muted); border-color: var(--line); }}
.cfg-active {{ color: var(--green-strong); font-weight: 600; white-space: nowrap; }}
.rows {{ width: 100%; }}
.rows-head,.row {{ display: grid; grid-template-columns: minmax(120px, 1.3fr) minmax(90px, .8fr) minmax(90px, .8fr) minmax(80px, .7fr) minmax(120px, 1fr) 100px; gap: 12px; align-items: center; padding: 10px 14px; }}
.rows-head {{ color: var(--muted); font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--line); }}
.row {{ border-bottom: 1px solid var(--line); font-size: 13px; }}
.row:last-child {{ border-bottom: 0; }}
.uplink-cell {{ display: flex; align-items: center; gap: 8px; font-weight: 500; }}
.status-pill {{ display: inline-flex; align-items: center; gap: 5px; border-radius: 999px; padding: 2px 8px; font-size: 11.5px; font-weight: 500; background: var(--gray-soft); color: var(--muted); }}
.status-pill.good {{ background: var(--green-soft); color: var(--green-strong); }}
.status-pill.warn {{ background: var(--amber-soft); color: #b45309; }}
.status-pill.bad {{ background: var(--gray-soft); color: var(--muted); }}
.status-dot {{ width: 8px; height: 8px; border-radius: 99px; background: #cbd5e1; flex: 0 0 auto; }}
.status-dot.good {{ background: var(--green); }}
.status-dot.warn {{ background: var(--amber); }}
.status-dot.bad {{ background: #cbd5e1; }}
.muted-cell {{ color: var(--muted); }}
.action-btn {{ height: 28px; padding: 0 12px; border-radius: 6px; border: 1px solid var(--line-strong); background: #fff; color: #334155; font-weight: 500; font-size: 12px; cursor: pointer; display: inline-flex; align-items: center; gap: 4px; }}
.action-btn.primary {{ background: var(--blue); border-color: var(--blue); color: #fff; }}
.action-btn.primary:hover {{ background: #4f46e5; }}
.action-btn:disabled {{ opacity: .5; cursor: default; }}
.error {{ border: 1px solid #fecaca; background: #fef2f2; color: #991b1b; border-radius: 8px; padding: 10px 14px; font-size: 13px; }}
@media (max-width: 1100px) {{
  .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
}}
@media (max-width: 900px) {{
  .shell {{ grid-template-columns: 1fr; }}
  .nav {{ min-height: auto; }}
  .menu,.nav-footer {{ display: none; }}
  main {{ padding: 18px 14px; }}
  .summary-grid {{ grid-template-columns: 1fr 1fr; }}
  .rows-head {{ display: none; }}
  .row {{ grid-template-columns: 1fr; gap: 6px; }}
  .topbar {{ flex-direction: column; align-items: stretch; }}
}}
</style>
</head>
<body>
<div class="shell">
  <aside class="nav">
    <div class="brand"><span class="logo">◆</span><span>Network Dashboard</span></div>
    <nav class="menu">
      <button class="item active" type="button"><span class="item-icon">▣</span><span>Instances</span></button>
      <button class="item" type="button"><span class="item-icon">◉</span><span>Alerts</span></button>
      <button class="item" type="button"><span class="item-icon">▤</span><span>Logs</span></button>
      <button class="item" type="button"><span class="item-icon">⚙</span><span>Settings</span></button>
    </nav>
    <div class="spacer"></div>
    <div class="nav-footer">
      <div class="nav-card">
        <div class="nav-card-title">System status</div>
        <div class="nav-card-value"><span class="dot" id="systemDot"></span><span id="systemStatus">All systems operational</span></div>
      </div>
      <div class="nav-card">
        <div class="nav-card-title">Control Service</div>
        <div class="nav-card-value" style="color: var(--blue); font-weight: 600;">/control</div>
      </div>
    </div>
  </aside>
  <main>
    <div class="topbar">
      <div class="topbar-copy">
        <h1>Instances</h1>
        <div class="subtitle">Overview of all instances, uplink groups and uplinks</div>
      </div>
      <div class="toolbar">
        <div class="updated-inline">↻ Last updated: <span id="updatedAtInline">-</span></div>
        <button class="refresh" id="refreshBtn" type="button"><span class="dot"></span><span id="refreshLabel">Auto</span></button>
      </div>
    </div>
    <section class="summary-grid" id="summaryGrid"></section>
    <div id="errors"></div>
    <section class="stack" id="groups"></section>
  </main>
</div>
<script>
const refreshMs = {refresh_ms};
let timer = null;
let autoRefreshEnabled = true;
const state = {{ instances: [], collapsedInstances: new Set(), collapsedGroups: new Set(), errors: [] }};

function healthy(u) {{ return u.tcp_healthy !== false && u.udp_healthy !== false; }}
function isActive(u) {{ return Boolean(u.active_global || u.active_tcp || u.active_udp); }}
function computeStats() {{
  const healthyInstances = state.instances.filter(i => i.ok).length;
  const totalInstances = state.instances.length;
  let totalGroups = 0, activeUplinks = 0, inactiveUplinks = 0;
  for (const inst of state.instances) {{
    for (const g of inst.groups || []) {{
      totalGroups += 1;
      for (const u of g.uplinks || []) {{
        if (isActive(u)) activeUplinks += 1; else inactiveUplinks += 1;
      }}
    }}
  }}
  return {{ totalInstances, healthyInstances, totalGroups, activeUplinks, inactiveUplinks }};
}}
function statusTone(ok, groups) {{
  if (!ok) return "bad";
  const uplinks = groups.flatMap(g => g.uplinks || []);
  if (uplinks.length === 0) return "warn";
  const healthyCount = uplinks.filter(healthy).length;
  const activeCount = uplinks.filter(isActive).length;
  if (healthyCount === uplinks.length && activeCount > 0) return "good";
  if (healthyCount > 0) return "warn";
  return "bad";
}}
function statusLabel(tone) {{ return tone === "good" ? "Healthy" : tone === "warn" ? "Degraded" : "Offline"; }}
function prettyMode(value) {{
  const v = String(value || "").toLowerCase();
  if (v === "active_passive") return "Active / Passive";
  if (v === "active_active") return "Active / Active";
  if (v === "round_robin") return "Round-robin";
  if (v === "weighted") return "Weighted";
  return value || "—";
}}
function prettyScope(value) {{
  const v = String(value || "").toLowerCase();
  if (v === "global") return "Global";
  if (v === "tcp") return "TCP only";
  if (v === "udp") return "UDP only";
  if (v === "per_transport") return "Per transport";
  return value || "—";
}}
function groupConfigChips(group) {{
  const mode = prettyMode(group.load_balancing_mode);
  const scope = prettyScope(group.routing_scope);
  const failback = group.auto_failback;
  const fbCls = failback ? "fb-on" : "fb-off";
  const fbLabel = failback ? "On" : "Off";
  return `
    <span class="cfg-chip mode" title="load_balancing_mode"><span>⚖</span><span class="cfg-key">Mode:</span><span>${{escapeHtml(mode)}}</span></span>
    <span class="cfg-chip scope" title="routing_scope"><span>⌘</span><span class="cfg-key">Scope:</span><span>${{escapeHtml(scope)}}</span></span>
    <span class="cfg-chip ${{fbCls}}" title="auto_failback"><span>↺</span><span class="cfg-key">Auto-failback:</span><span>${{fbLabel}}</span></span>`;
}}
function uplinkRole(u) {{
  const parts = [];
  if (u.active_global) parts.push("global");
  if (u.active_tcp) parts.push("tcp");
  if (u.active_udp) parts.push("udp");
  return parts.length ? parts.join(", ") : "standby";
}}
function summaryCards(stats) {{
  return [
    {{ label: "Total Instances", value: stats.totalInstances, icon: "▣", tone: "" }},
    {{ label: "Healthy Instances", value: stats.healthyInstances, icon: "♥", tone: "good" }},
    {{ label: "Total Uplink Groups", value: stats.totalGroups, icon: "◎", tone: "warn" }},
    {{ label: "Active Uplinks", value: stats.activeUplinks, icon: "↗", tone: "good", good: true }},
    {{ label: "Inactive Uplinks", value: stats.inactiveUplinks, icon: "⊘", tone: "muted" }},
  ];
}}
function renderSummary(stats) {{
  const root = document.getElementById("summaryGrid");
  root.innerHTML = summaryCards(stats).map(c => `
    <article class="summary-card">
      <div class="summary-copy">
        <div class="summary-label">${{c.label}}</div>
        <div class="summary-value ${{c.good ? "good" : ""}}">${{c.value}}</div>
      </div>
      <div class="summary-icon ${{c.tone}}">${{c.icon}}</div>
    </article>`).join("");
}}
function rebuild(raw) {{
  state.instances = [];
  state.errors = [];
  for (const inst of raw.instances) {{
    if (!inst.ok) {{
      state.errors.push(inst.name + ": " + inst.error);
      state.instances.push({{ name: inst.name, ok: false, error: inst.error, groups: [] }});
      continue;
    }}
    const groups = inst.topology?.instance?.groups || [];
    state.instances.push({{ name: inst.name, ok: true, error: null, groups }});
  }}
}}
function renderErrors() {{
  const box = document.getElementById("errors");
  box.innerHTML = state.errors.map(e => `<div class="error">${{escapeHtml(e)}}</div>`).join("");
}}
function render() {{
  renderErrors();
  const stats = computeStats();
  renderSummary(stats);
  const root = document.getElementById("groups");
  root.innerHTML = "";
  for (const instance of state.instances) {{
    const panel = document.createElement("article");
    const collapsed = state.collapsedInstances.has(instance.name);
    panel.className = "instance-panel" + (collapsed ? " collapsed" : "");
    const groups = instance.groups || [];
    const tone = statusTone(instance.ok, groups);
    panel.innerHTML = `
      <header class="instance-panel-header">
        <div class="status-dot ${{tone}}"></div>
        <div class="panel-title">
          <strong>${{escapeHtml(instance.name)}}</strong>
          <span class="status-pill ${{tone}}">${{statusLabel(tone)}}</span>
        </div>
        <span class="collapse-chev">⌃</span>
      </header>`;
    panel.querySelector(".instance-panel-header").addEventListener("click", () => toggleInstance(instance.name));
    if (!instance.ok) {{
      const body = document.createElement("div");
      body.className = "instance-panel-body";
      body.innerHTML = `<div class="error">${{escapeHtml(instance.error || "instance недоступен")}}</div>`;
      panel.appendChild(body);
      root.appendChild(panel);
      continue;
    }}
    const body = document.createElement("div");
    body.className = "instance-panel-body";
    body.innerHTML = `<div class="section-title">Uplink Groups</div>`;
    for (const group of groups) {{
      const groupEl = document.createElement("section");
      const groupKey = instance.name + "\u0000" + group.name;
      const groupCollapsed = state.collapsedGroups.has(groupKey);
      const activeInGroup = (group.uplinks || []).filter(isActive).length;
      groupEl.className = "group-table" + (groupCollapsed ? " collapsed" : "");
      groupEl.innerHTML = `
        <div class="group-table-head">
          <div class="group-table-title">
            <span>${{escapeHtml(group.name)}}</span>
            <span class="group-count">${{(group.uplinks || []).length}} uplinks</span>
          </div>
          <div class="group-table-meta">
            <div class="cfg-chips">${{groupConfigChips(group)}}</div>
            <span class="cfg-active">${{activeInGroup}} active</span>
            <span class="collapse-chev">⌃</span>
          </div>
        </div>
        <div class="rows">
          <div class="rows-head">
            <div>Uplink</div>
            <div>Status</div>
            <div>TCP</div>
            <div>UDP</div>
            <div>Role</div>
            <div>Action</div>
          </div>
        </div>`;
      groupEl.querySelector(".group-table-head").addEventListener("click", () => toggleGroup(groupKey));
      const rows = groupEl.querySelector(".rows");
      for (const uplink of group.uplinks || []) {{
        const entry = {{ instance: instance.name, group: group.name, uplink }};
        const rowTone = isActive(uplink) ? "good" : (healthy(uplink) ? "warn" : "bad");
        const label = rowTone === "good" ? "Active" : rowTone === "warn" ? "Ready" : "Inactive";
        const row = document.createElement("div");
        row.className = "row";
        row.innerHTML = `
          <div class="uplink-cell"><span class="status-dot ${{rowTone}}"></span><span>${{escapeHtml(uplink.name)}}</span></div>
          <div><span class="status-pill ${{rowTone}}">${{label}}</span></div>
          <div class="${{uplink.tcp_healthy === false ? "muted-cell" : ""}}">${{uplink.tcp_healthy === false ? "down" : "ok"}}</div>
          <div class="${{uplink.udp_healthy === false ? "muted-cell" : ""}}">${{uplink.udp_healthy === false ? "down" : "ok"}}</div>
          <div class="muted-cell">${{escapeHtml(uplinkRole(uplink))}}</div>
          <div>${{rowTone === "good" ? `<button class="action-btn" type="button" disabled>Active</button>` : `<button class="action-btn primary" type="button">▶ Activate</button>`}}</div>`;
        if (rowTone !== "good") {{
          row.querySelector("button").addEventListener("click", ev => {{ ev.stopPropagation(); activateEntries([entry]); }});
        }}
        rows.appendChild(row);
      }}
      body.appendChild(groupEl);
    }}
    panel.appendChild(body);
    root.appendChild(panel);
  }}
  const now = new Date().toLocaleTimeString();
  document.getElementById("updatedAtInline").textContent = now;
  const hasErrors = state.errors.length > 0;
  document.getElementById("systemStatus").textContent = hasErrors ? "Connection issues" : "All systems operational";
  document.getElementById("systemDot").style.background = hasErrors ? "var(--amber)" : "var(--green)";
  renderRefreshButton();
}}
function renderRefreshButton() {{
  const btn = document.getElementById("refreshBtn");
  const label = document.getElementById("refreshLabel");
  btn.classList.toggle("off", !autoRefreshEnabled);
  btn.setAttribute("aria-pressed", String(autoRefreshEnabled));
  label.textContent = autoRefreshEnabled ? "Auto" : "Paused";
}}
function stopAutoRefresh() {{ if (timer !== null) {{ clearInterval(timer); timer = null; }} }}
function startAutoRefresh() {{
  stopAutoRefresh();
  if (!autoRefreshEnabled) return;
  timer = setInterval(() => load().catch(err => {{ state.errors = [String(err)]; render(); }}), refreshMs);
}}
function toggleAutoRefresh() {{
  autoRefreshEnabled = !autoRefreshEnabled;
  renderRefreshButton();
  startAutoRefresh();
}}
function toggleInstance(name) {{
  if (state.collapsedInstances.has(name)) state.collapsedInstances.delete(name);
  else state.collapsedInstances.add(name);
  render();
}}
function toggleGroup(key) {{
  if (state.collapsedGroups.has(key)) state.collapsedGroups.delete(key);
  else state.collapsedGroups.add(key);
  render();
}}
async function load() {{
  const res = await fetch("/dashboard/api/topology", {{ cache: "no-store" }});
  const raw = await res.json();
  rebuild(raw);
  render();
}}
async function activateEntries(entries) {{
  const targets = entries.map(e => ({{ instance: e.instance, group: e.group, uplink: e.uplink.name }}));
  await fetch("/dashboard/api/activate", {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{ targets, transport: "both" }})
  }});
  await load();
}}
function escapeHtml(value) {{
  return String(value).replace(/[&<>"']/g, c => ({{ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }}[c]));
}}
document.getElementById("refreshBtn").addEventListener("click", toggleAutoRefresh);
renderRefreshButton();
load().catch(err => {{ state.errors = [String(err)]; render(); }});
startAutoRefresh();
</script>
</body>
</html>"##,
        refresh_ms = refresh_interval_secs.saturating_mul(1000)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_status_and_body() {
        let (status, body) =
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"{}");
    }

    #[test]
    fn instance_url_preserves_base_path_prefix() {
        let base = Url::parse("https://cloud1.beerloga.su/rust-ws-exporter").unwrap();
        let url = instance_url(&base, "/control/summary").unwrap();
        assert_eq!(
            url.as_str(),
            "https://cloud1.beerloga.su/rust-ws-exporter/control/summary"
        );
    }

    #[test]
    fn detects_complete_chunked_body() {
        assert!(has_complete_chunked_body(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap());
        assert!(!has_complete_chunked_body(b"4\r\nWiki\r\n5\r\nped").unwrap());
    }

    #[test]
    fn decodes_chunked_body() {
        let decoded = decode_chunked_body(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap();
        assert_eq!(decoded, b"Wikipedia");
    }
}
