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
    instances: Vec<DashboardInstanceConfig>,
}

pub fn spawn_dashboard_server(config: DashboardConfig) {
    let listen = config.listen;
    let state = DashboardState {
        refresh_interval_secs: config.refresh_interval_secs,
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
        let view = match fetch_instance_topology(instance).await {
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
                match activate_instance(instance, &target, payload.transport.as_deref()).await {
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

async fn fetch_instance_topology(instance: &DashboardInstanceConfig) -> Result<Value> {
    let url = instance_url(&instance.control_url, "/control/topology")?;
    let (status, body) = send_instance_request(instance, Method::GET, url, None).await?;
    if !status.is_success() {
        bail!("{} returned HTTP {status}", instance.name);
    }
    serde_json::from_slice(&body).context("invalid topology JSON")
}

async fn activate_instance(
    instance: &DashboardInstanceConfig,
    target: &DashboardActivateTarget,
    transport: Option<&str>,
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
    let (status, response_body) =
        send_instance_request(instance, Method::POST, url, Some(body)).await?;
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

    let response = timeout(Duration::from_secs(5), async {
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
<title>Uplink Monitor</title>
<style>
:root {{
  color-scheme: light;
  --nav: #111827;
  --nav-2: #1b2435;
  --nav-3: #2a3752;
  --text: #101828;
  --muted: #667085;
  --line: #d9e0ea;
  --line-strong: #c6d0dd;
  --soft: #f3f6fa;
  --soft-2: #f8fafc;
  --panel: #ffffff;
  --panel-tint: #f7f9fc;
  --green: #22c55e;
  --green-strong: #15803d;
  --green-soft: #eaf8ef;
  --amber: #f59e0b;
  --amber-soft: #fff7e8;
  --gray-soft: #eef2f6;
  --blue: #4f46e5;
  --blue-soft: #eef0ff;
  --red: #d92d20;
  --red-soft: #fff2f1;
  --shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--text); background: #fff; }}
.shell {{ min-height: 100vh; display: grid; grid-template-columns: 244px 1fr; }}
.nav {{ background: var(--nav); color: #d7deeb; display: flex; flex-direction: column; min-height: 100vh; }}
.brand {{ height: 88px; display: flex; gap: 12px; align-items: center; padding: 0 24px; font-weight: 700; color: #fff; }}
.logo {{ width: 28px; height: 28px; border-radius: 7px; border: 2px solid #60a5fa; position: relative; transform: rotate(-30deg); }}
.logo:before,.logo:after {{ content: ""; position: absolute; border: 2px solid #60a5fa; border-radius: 7px; width: 13px; height: 8px; top: 7px; background: var(--nav); }}
.logo:before {{ left: -8px; }} .logo:after {{ right: -8px; }}
.menu {{ padding: 12px 14px; display: grid; gap: 8px; }}
.item {{ height: 44px; width: 100%; border: 0; border-radius: 10px; display: flex; align-items: center; gap: 12px; padding: 0 14px; color: #c8d1df; background: transparent; text-align: left; font-size: 14px; }}
.item.active {{ background: var(--nav-3); color: #7ea6ff; }}
.spacer {{ flex: 1; }}
.nav-section {{ margin: 16px; border: 1px solid #24324a; border-radius: 12px; padding: 16px; display: grid; gap: 10px; background: rgba(255,255,255,0.02); }}
.nav-section-title {{ color: #98a2b3; font-size: 13px; }}
.nav-section-value {{ display: block; font-size: 28px; font-weight: 700; color: #fff; }}
.nav-section-good {{ color: #65d783; }}
.stamp {{ border-top: 1px solid #22314d; padding: 22px 24px; color: #8e9bb0; font-size: 13px; display: grid; gap: 14px; }}
.stamp-card {{ border: 1px solid #24324a; border-radius: 12px; padding: 14px; display: grid; gap: 6px; }}
.stamp-good {{ color: #65d783; }}
main {{ padding: 28px 28px 24px; min-width: 0; background: #fff; }}
.topbar {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
.topbar-copy {{ display: grid; gap: 8px; }}
h1 {{ margin: 0; font-size: 40px; line-height: 1; letter-spacing: 0; }}
.subtitle {{ color: var(--muted); font-size: 16px; }}
.toolbar {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.updated-inline {{ color: var(--muted); font-size: 14px; }}
.refresh {{ border: 1px solid var(--line); background: #fff; border-radius: 10px; padding: 10px 14px; display: flex; align-items: center; gap: 10px; color: #344054; box-shadow: var(--shadow); }}
.refresh.off {{ color: #667085; background: var(--soft-2); }}
.dot {{ width: 10px; height: 10px; border-radius: 99px; background: var(--green); display: inline-block; }}
.refresh.off .dot {{ background: #c7ced8; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 18px; }}
.summary-card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px; box-shadow: var(--shadow); display: grid; gap: 16px; min-height: 104px; }}
.summary-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }}
.summary-label {{ color: var(--muted); font-size: 14px; }}
.summary-value {{ font-size: 38px; font-weight: 700; line-height: 1; }}
.summary-value.good {{ color: var(--green); }}
.summary-icon {{ width: 40px; height: 40px; border-radius: 12px; display: grid; place-items: center; background: var(--soft); color: var(--blue); font-size: 18px; }}
.summary-icon.good {{ background: var(--green-soft); color: var(--green-strong); }}
.summary-icon.warn {{ background: var(--blue-soft); color: var(--blue); }}
.view {{ display: none; }}
.view.active {{ display: block; }}
.stack {{ display: grid; gap: 14px; }}
.instance-panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; box-shadow: var(--shadow); }}
.instance-panel.collapsed .instance-panel-body {{ display: none; }}
.instance-panel-header {{ min-height: 68px; display: flex; align-items: center; gap: 14px; padding: 18px 20px; border-bottom: 1px solid var(--line); }}
.instance-panel.collapsed .instance-panel-header {{ border-bottom: 0; }}
.panel-title-wrap {{ display: grid; gap: 6px; min-width: 0; }}
.panel-title {{ display: flex; align-items: center; gap: 12px; min-width: 0; }}
.panel-title strong {{ font-size: 24px; font-weight: 700; overflow-wrap: anywhere; }}
.panel-subtitle {{ color: var(--muted); font-size: 14px; }}
.panel-meta {{ margin-left: auto; display: flex; align-items: center; gap: 18px; color: #475467; font-size: 14px; flex-wrap: wrap; justify-content: flex-end; }}
.collapse-btn {{ width: 34px; height: 34px; border: 1px solid var(--line); border-radius: 10px; background: #fff; color: #475467; cursor: pointer; }}
.instance-panel.collapsed .collapse-btn {{ transform: rotate(180deg); }}
.instance-panel-body {{ padding: 18px 20px 20px; display: grid; gap: 14px; background: var(--panel); }}
.section-title {{ font-size: 15px; font-weight: 700; color: #344054; }}
.group-table {{ border: 1px solid var(--line); border-radius: 12px; overflow: hidden; background: var(--panel); }}
.group-table-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 16px; background: var(--panel-tint); border-bottom: 1px solid var(--line); }}
.group-table-title {{ display: flex; align-items: center; gap: 10px; font-weight: 700; }}
.group-count {{ padding: 4px 10px; border-radius: 999px; background: var(--gray-soft); color: #475467; font-size: 12px; }}
.group-table-meta {{ display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13px; flex-wrap: wrap; justify-content: flex-end; }}
.config-chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.tiny-chip,.config-chip {{ border-radius: 999px; padding: 5px 10px; background: var(--gray-soft); color: #344054; font-size: 12px; }}
.config-chip {{ background: #eef4ff; color: #344054; }}
.rows {{ width: 100%; }}
.rows-head,.row {{ display: grid; grid-template-columns: minmax(140px, 1.4fr) minmax(110px, .9fr) minmax(100px, .8fr) minmax(100px, .8fr) minmax(160px, 1.1fr) 116px; gap: 14px; align-items: center; padding: 12px 16px; }}
.rows-head {{ background: var(--soft-2); color: #667085; font-size: 12px; text-transform: uppercase; border-bottom: 1px solid var(--line); }}
.row {{ border-bottom: 1px solid #edf1f6; font-size: 14px; }}
.row:last-child {{ border-bottom: 0; }}
.uplink-cell {{ display: flex; align-items: center; gap: 10px; font-weight: 600; }}
.status-pill {{ display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 5px 10px; font-size: 12px; background: var(--gray-soft); color: #475467; }}
.status-pill.good {{ background: var(--green-soft); color: var(--green-strong); }}
.status-pill.warn {{ background: var(--amber-soft); color: #b54708; }}
.status-pill.bad {{ background: #f2f4f7; color: #475467; }}
.status-dot {{ width: 12px; height: 12px; border-radius: 99px; background: #98a2b3; flex: 0 0 auto; }}
.status {{ width: 12px; height: 12px; border-radius: 99px; background: #98a2b3; flex: 0 0 auto; }}
.status-dot.good {{ background: var(--green); }}
.status-dot.warn {{ background: var(--amber); }}
.status-dot.bad {{ background: #98a2b3; }}
.badge {{ margin-left: auto; border-radius: 999px; padding: 5px 12px; background: var(--gray-soft); color: #6b7280; font-size: 13px; white-space: nowrap; }}
.action-btn {{ height: 36px; border-radius: 10px; border: 1px solid var(--line-strong); background: #fff; color: #344054; font-weight: 600; }}
.action-btn.primary {{ background: var(--blue); border-color: var(--blue); color: #fff; }}
.action-btn:disabled {{ opacity: .5; cursor: default; }}
.view {{ display: none; }}
.view.active {{ display: block; }}
.catalog-grid {{ display: grid; grid-template-columns: repeat(2, minmax(320px, 1fr)); gap: 18px; }}
.instance-card,.catalog-card {{ background: #fff; border: 1px solid var(--line); border-radius: 14px; padding: 18px; display: grid; gap: 14px; box-shadow: var(--shadow); }}
.instance-head {{ display: flex; align-items: center; gap: 12px; }}
.instance-name {{ font-size: 19px; font-weight: 700; }}
.instance-sub {{ color: var(--muted); font-size: 14px; }}
.instance-meta,.catalog-meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
.metric {{ border: 1px solid #e8ecf3; border-radius: 12px; padding: 12px; background: #fbfcfe; }}
.metric-label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
.metric-value {{ font-size: 22px; font-weight: 700; }}
.instance-groups,.catalog-list {{ display: grid; gap: 10px; }}
.instance-group,.catalog-row {{ border: 1px solid #e8ecf3; border-radius: 12px; padding: 12px; background: #fff; }}
.catalog-list {{ display: grid; gap: 10px; }}
.catalog-row-top {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }}
.instance-group-top {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }}
.instance-group-name {{ font-weight: 700; }}
.tiny-chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.error {{ border: 1px solid #f6c4be; background: #fff5f3; color: #9f1f14; border-radius: 8px; padding: 14px 16px; }}
@media (max-width: 980px) {{
  .shell {{ grid-template-columns: 1fr; }}
  .nav {{ min-height: auto; }}
  .menu,.nav-section,.stamp {{ display: none; }}
  main {{ padding: 24px 16px; }}
  .summary-grid {{ grid-template-columns: 1fr; }}
  .catalog-grid {{ grid-template-columns: 1fr; }}
  .rows-head {{ display: none; }}
  .row {{ grid-template-columns: 1fr; gap: 8px; }}
  .row > div:last-child {{ padding-top: 4px; }}
  .instance-meta {{ grid-template-columns: 1fr; }}
  .catalog-meta {{ grid-template-columns: 1fr; }}
  .topbar {{ flex-direction: column; }}
  .instance-panel-header {{ flex-wrap: wrap; }}
  .panel-meta {{ margin-left: 0; width: 100%; justify-content: space-between; }}
  .group-table-head {{ flex-direction: column; align-items: flex-start; }}
}}
</style>
</head>
<body>
<div class="shell">
  <aside class="nav">
    <div class="brand"><span class="logo"></span><span>Uplink Monitor</span></div>
    <nav class="menu">
      <button class="item active" data-view="dashboard" type="button">⌂ <span>Дашборд</span></button>
      <button class="item" data-view="instances" type="button">▣ <span>Инстансы</span></button>
      <button class="item" data-view="uplinks" type="button">↗ <span>Аплинки</span></button>
      <button class="item" data-view="groups" type="button">◎ <span>Группы</span></button>
      <div class="item">▤ <span>Логи</span></div>
      <div class="item">⚙ <span>Настройки</span></div>
    </nav>
    <div class="spacer"></div>
    <div class="nav-section">
      <div class="nav-section-title">Всего инстансов</div>
      <span class="nav-section-value" id="instancesTotal">0</span>
      <div class="nav-section-title">Активные аплинки</div>
      <span class="nav-section-value"><span class="nav-section-good" id="activeTotal">0</span> / <span id="uplinksTotal">0</span></span>
    </div>
    <div class="stamp">
      <div>Обновлено: <span id="updatedAt">-</span></div>
      <div class="stamp-card">
        <div class="nav-section-title">Состояние системы</div>
        <div class="stamp-good" id="systemStatus">Нет ошибок</div>
      </div>
    </div>
  </aside>
  <main>
    <div class="topbar">
      <div class="topbar-copy">
        <h1 id="viewTitle">Дашборд</h1>
        <div class="subtitle" id="viewSubtitle">Обзор всех инстансов, групп и аплинков</div>
      </div>
      <div class="toolbar">
        <div class="updated-inline">Last updated: <span id="updatedAtInline">-</span></div>
        <button class="refresh" id="refreshBtn" type="button">↻ <span id="refreshLabel">Автообновление</span> <span class="dot"></span></button>
      </div>
    </div>
    <section class="summary-grid" id="summaryGrid"></section>
    <div id="errors"></div>
    <section class="view active" id="dashboardView">
      <section class="stack" id="groups"></section>
    </section>
    <section class="view" id="instancesView">
      <section class="catalog-grid" id="instancesGrid"></section>
    </section>
    <section class="view" id="uplinksView">
      <section class="catalog-grid" id="uplinksGrid"></section>
    </section>
    <section class="view" id="groupsView">
      <section class="catalog-grid" id="groupsGrid"></section>
    </section>
  </main>
</div>
<script>
const refreshMs = {refresh_ms};
let timer = null;
let autoRefreshEnabled = true;
let currentView = "dashboard";
const state = {{ groups: new Map(), instances: [], uplinks: new Map(), collapsedGroups: new Set(), collapsedInstances: new Set(), errors: [] }};

function groupKey(group, uplink) {{ return group + "\u0000" + uplink; }}
function healthy(entry) {{
  return entry.uplink.tcp_healthy !== false && entry.uplink.udp_healthy !== false;
}}
function active(entry) {{
  const u = entry.uplink;
  return Boolean(u.active_global || u.active_tcp || u.active_udp);
}}
function groupConfigChips(group) {{
  return `
    <span class="config-chip">mode = "${{escapeHtml(group.load_balancing_mode)}}"</span>
    <span class="config-chip">routing_scope = "${{escapeHtml(group.routing_scope)}}"</span>
    <span class="config-chip">auto_failback = ${{group.auto_failback ? "true" : "false"}}</span>`;
}}
function viewMeta(view) {{
  return view === "dashboard"
    ? {{ title: "Дашборд", subtitle: "Обзор всех инстансов, групп и аплинков" }}
    : view === "instances"
    ? {{ title: "Инстансы", subtitle: "Сводка по каждому instance и его группам" }}
    : view === "uplinks"
    ? {{ title: "Аплинки", subtitle: "Состояние аплинков по всем instances" }}
    : {{ title: "Группы", subtitle: "Маршрутизация и состав uplink groups" }};
}}
function computeStats() {{
  const healthyInstances = state.instances.filter(instance => instance.ok).length;
  const totalInstances = state.instances.length;
  let totalGroups = 0;
  let activeUplinks = 0;
  let inactiveUplinks = 0;
  for (const instance of state.instances) {{
    for (const group of instance.groups || []) {{
      totalGroups += 1;
      for (const uplink of group.uplinks || []) {{
        if (uplink.active_global || uplink.active_tcp || uplink.active_udp) {{
          activeUplinks += 1;
        }} else {{
          inactiveUplinks += 1;
        }}
      }}
    }}
  }}
  return {{ totalInstances, healthyInstances, totalGroups, activeUplinks, inactiveUplinks }};
}}
function statusTone(ok, groups) {{
  if (!ok) return "bad";
  const uplinks = groups.flatMap(group => group.uplinks || []);
  if (uplinks.length === 0) return "warn";
  const activeCount = uplinks.filter(u => u.active_global || u.active_tcp || u.active_udp).length;
  const healthyCount = uplinks.filter(u => u.tcp_healthy !== false && u.udp_healthy !== false).length;
  if (healthyCount === uplinks.length && activeCount > 0) return "good";
  if (healthyCount > 0) return "warn";
  return "bad";
}}
function statusLabel(tone) {{
  return tone === "good" ? "Healthy" : tone === "warn" ? "Degraded" : "Offline";
}}
function transportState(value) {{
  return value === false ? "down" : "ok";
}}
function uplinkStatus(entries) {{
  const isActive = entries.some(active);
  const isHealthy = entries.some(healthy);
  if (isActive) return {{ label: "Active", tone: "good" }};
  if (isHealthy) return {{ label: "Ready", tone: "warn" }};
  return {{ label: "Inactive", tone: "bad" }};
}}
function uplinkRole(entry) {{
  const parts = [];
  if (entry.uplink.active_global) parts.push("global");
  if (entry.uplink.active_tcp) parts.push("tcp");
  if (entry.uplink.active_udp) parts.push("udp");
  return parts.length ? parts.join(", ") : "standby";
}}
function summaryCards(stats) {{
  return [
    {{ label: "Total Instances", value: stats.totalInstances, icon: "▣", tone: "" }},
    {{ label: "Healthy Instances", value: stats.healthyInstances, icon: "◌", tone: "good" }},
    {{ label: "Total Uplink Groups", value: stats.totalGroups, icon: "◎", tone: "warn" }},
    {{ label: "Active Uplinks", value: stats.activeUplinks + " / " + (stats.activeUplinks + stats.inactiveUplinks), icon: "↗", tone: "good" }},
  ];
}}
function renderSummary(stats) {{
  const root = document.getElementById("summaryGrid");
  root.innerHTML = summaryCards(stats).map(card => `
    <article class="summary-card">
      <div class="summary-top">
        <div>
          <div class="summary-label">${{card.label}}</div>
          <div class="summary-value ${{card.tone === "good" ? "good" : ""}}">${{card.value}}</div>
        </div>
        <div class="summary-icon ${{card.tone}}">${{card.icon}}</div>
      </div>
    </article>`).join("");
}}
function rebuild(raw) {{
  state.groups = new Map();
  state.instances = [];
  state.uplinks = new Map();
  state.errors = [];
  for (const inst of raw.instances) {{
    if (!inst.ok) {{
      state.errors.push(inst.name + ": " + inst.error);
      state.instances.push({{ name: inst.name, ok: false, error: inst.error, groups: [] }});
      continue;
    }}
    const groups = inst.topology?.instance?.groups || [];
    state.instances.push({{ name: inst.name, ok: true, error: null, groups }});
    for (const group of groups) {{
      if (!state.groups.has(group.name)) state.groups.set(group.name, new Map());
      const byUplink = state.groups.get(group.name);
      for (const uplink of group.uplinks || []) {{
        const key = uplink.name;
        if (!byUplink.has(key)) byUplink.set(key, []);
        const entry = {{ instance: inst.name, group: group.name, uplink, groupObj: group }};
        byUplink.get(key).push(entry);
        if (!state.uplinks.has(key)) state.uplinks.set(key, []);
        state.uplinks.get(key).push(entry);
      }}
    }}
  }}
}}
function renderErrors() {{
  const box = document.getElementById("errors");
  box.innerHTML = state.errors.map(e => `<div class="error">${{escapeHtml(e)}}</div>`).join("");
}}
function renderNav() {{
  document.querySelectorAll("[data-view]").forEach(el => {{
    el.classList.toggle("active", el.dataset.view === currentView);
  }});
  document.getElementById("dashboardView").classList.toggle("active", currentView === "dashboard");
  document.getElementById("instancesView").classList.toggle("active", currentView === "instances");
  document.getElementById("uplinksView").classList.toggle("active", currentView === "uplinks");
  document.getElementById("groupsView").classList.toggle("active", currentView === "groups");
  const meta = viewMeta(currentView);
  document.getElementById("viewTitle").textContent = meta.title;
  document.getElementById("viewSubtitle").textContent = meta.subtitle;
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
    const uplinks = groups.flatMap(group => group.uplinks || []);
    const tone = statusTone(instance.ok, groups);
    const healthyCount = uplinks.filter(u => u.tcp_healthy !== false && u.udp_healthy !== false).length;
    const activeCount = uplinks.filter(u => u.active_global || u.active_tcp || u.active_udp).length;
    panel.innerHTML = `
      <header class="instance-panel-header">
        <div class="status-dot ${{tone}}"></div>
        <div class="panel-title-wrap">
          <div class="panel-title">
            <strong>${{escapeHtml(instance.name)}}</strong>
            <span class="status-pill ${{tone}}">${{statusLabel(tone)}}</span>
          </div>
          <div class="panel-subtitle">${{instance.ok ? `${{groups.length}} groups, ${{uplinks.length}} uplinks` : "Инстанс недоступен"}}</div>
        </div>
        <div class="panel-meta">
          <span>Healthy: <b>${{healthyCount}}</b></span>
          <span>Active: <b>${{activeCount}}</b></span>
          <span>Groups: <b>${{groups.length}}</b></span>
          <button class="collapse-btn" type="button" aria-label="Свернуть инстанс">⌃</button>
        </div>
      </header>`;
    const collapseBtn = panel.querySelector(".collapse-btn");
    collapseBtn.addEventListener("click", () => toggleInstance(instance.name));
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
      const activeInGroup = (group.uplinks || []).filter(u => u.active_global || u.active_tcp || u.active_udp).length;
      groupEl.className = "group-table";
      groupEl.innerHTML = `
        <div class="group-table-head">
          <div class="group-table-title">
            <span>${{escapeHtml(group.name)}}</span>
            <span class="group-count">${{(group.uplinks || []).length}} uplinks</span>
          </div>
          <div class="group-table-meta">
            <span>${{activeInGroup}} active</span>
            <div class="config-chips">${{groupConfigChips(group)}}</div>
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
      const rows = groupEl.querySelector(".rows");
      for (const uplink of group.uplinks || []) {{
        const entry = {{ instance: instance.name, group: group.name, uplink, groupObj: group }};
        const tone = uplink.active_global || uplink.active_tcp || uplink.active_udp ? "good" : (healthy(entry) ? "warn" : "bad");
        const row = document.createElement("div");
        row.className = "row";
        row.innerHTML = `
          <div class="uplink-cell"><span class="status-dot ${{tone}}"></span><span>${{escapeHtml(uplink.name)}}</span></div>
          <div><span class="status-pill ${{tone}}">${{tone === "good" ? "Active" : tone === "warn" ? "Ready" : "Inactive"}}</span></div>
          <div>${{transportState(uplink.tcp_healthy)}}</div>
          <div>${{transportState(uplink.udp_healthy)}}</div>
          <div>${{escapeHtml(uplinkRole(entry))}}</div>
          <div><button class="action-btn ${{tone === "good" ? "" : "primary"}}" type="button" ${{tone === "good" ? "disabled" : ""}}>${{tone === "good" ? "Active" : "Activate"}}</button></div>`;
        const button = row.querySelector("button");
        if (tone !== "good") {{
          button.addEventListener("click", () => activateEntries([entry]));
        }}
        rows.appendChild(row);
      }}
      body.appendChild(groupEl);
    }}
    panel.appendChild(body);
    root.appendChild(panel);
  }}
  document.getElementById("instancesTotal").textContent = stats.totalInstances;
  document.getElementById("uplinksTotal").textContent = stats.activeUplinks + stats.inactiveUplinks;
  document.getElementById("activeTotal").textContent = stats.activeUplinks;
  const now = new Date().toLocaleTimeString();
  document.getElementById("updatedAt").textContent = now;
  document.getElementById("updatedAtInline").textContent = now;
  document.getElementById("systemStatus").textContent = state.errors.length ? "Есть ошибки подключения" : "All systems operational";
  renderInstances();
  renderUplinks();
  renderGroups();
  renderNav();
  renderRefreshButton();
}}
function renderInstances() {{
  const root = document.getElementById("instancesGrid");
  root.innerHTML = "";
  for (const instance of state.instances) {{
    const groups = instance.groups || [];
    const uplinks = groups.flatMap(g => g.uplinks || []);
    const activeCount = uplinks.filter(u => u.active_global || u.active_tcp || u.active_udp).length;
    const healthyCount = uplinks.filter(u => u.tcp_healthy !== false && u.udp_healthy !== false).length;
    const card = document.createElement("article");
    card.className = "instance-card";
    if (!instance.ok) {{
      card.innerHTML = `
        <div class="instance-head">
          <span class="status"></span>
          <div><div class="instance-name">${{escapeHtml(instance.name)}}</div><div class="instance-sub">Недоступен</div></div>
        </div>
        <div class="error">${{escapeHtml(instance.error || "instance недоступен")}}</div>`;
      root.appendChild(card);
      continue;
    }}
    card.innerHTML = `
      <div class="instance-head">
        <span class="status" style="background:${{healthyCount > 0 ? "var(--green)" : "#aeb4bd"}}"></span>
        <div>
          <div class="instance-name">${{escapeHtml(instance.name)}}</div>
          <div class="instance-sub">${{groups.length}} групп, ${{uplinks.length}} аплинков</div>
        </div>
      </div>
      <div class="instance-meta">
        <div class="metric"><div class="metric-label">Группы</div><div class="metric-value">${{groups.length}}</div></div>
        <div class="metric"><div class="metric-label">Активные</div><div class="metric-value">${{activeCount}}</div></div>
        <div class="metric"><div class="metric-label">Доступные</div><div class="metric-value">${{healthyCount}}</div></div>
      </div>`;
    const groupsEl = document.createElement("div");
    groupsEl.className = "instance-groups";
    for (const group of groups) {{
      const uplinkNames = (group.uplinks || []).map(u => `<span class="tiny-chip">${{escapeHtml(u.name)}}</span>`).join("");
      const groupEl = document.createElement("div");
      groupEl.className = "instance-group";
      groupEl.innerHTML = `
        <div class="instance-group-top">
          <span class="instance-group-name">${{escapeHtml(group.name)}}</span>
          <span class="instance-sub">${{(group.uplinks || []).length}} аплинков</span>
        </div>
        <div class="tiny-chips">${{uplinkNames}}</div>`;
      groupsEl.appendChild(groupEl);
    }}
    card.appendChild(groupsEl);
    root.appendChild(card);
  }}
}}
function renderUplinks() {{
  const root = document.getElementById("uplinksGrid");
  root.innerHTML = "";
  for (const [uplinkName, entries] of state.uplinks.entries()) {{
    const healthyCount = entries.filter(healthy).length;
    const activeCount = entries.filter(active).length;
    const instances = [...new Set(entries.map(e => e.instance))];
    const groups = [...new Set(entries.map(e => e.group))];
    const card = document.createElement("article");
    card.className = "catalog-card";
    card.innerHTML = `
      <div class="instance-head">
        <span class="status" style="background:${{healthyCount > 0 ? "var(--green)" : "#aeb4bd"}}"></span>
        <div>
          <div class="instance-name">${{escapeHtml(uplinkName)}}</div>
          <div class="instance-sub">${{instances.length}} инстансов, ${{groups.length}} групп</div>
        </div>
      </div>
      <div class="catalog-meta">
        <div class="metric"><div class="metric-label">Инстансы</div><div class="metric-value">${{instances.length}}</div></div>
        <div class="metric"><div class="metric-label">Активные</div><div class="metric-value">${{activeCount}}</div></div>
        <div class="metric"><div class="metric-label">Доступные</div><div class="metric-value">${{healthyCount}}</div></div>
      </div>`;
    const list = document.createElement("div");
    list.className = "catalog-list";
    for (const entry of entries) {{
      const row = document.createElement("div");
      row.className = "catalog-row";
      row.innerHTML = `
        <div class="catalog-row-top">
          <span class="instance-group-name">${{escapeHtml(entry.instance)}}</span>
          <span class="badge">${{active(entry) ? "Активный" : (healthy(entry) ? "Доступен" : "Неактивный")}}</span>
        </div>
        <div class="tiny-chips">
          <span class="tiny-chip">Группа: ${{escapeHtml(entry.group)}}</span>
          <span class="tiny-chip">TCP: ${{entry.uplink.tcp_healthy === false ? "down" : "ok"}}</span>
          <span class="tiny-chip">UDP: ${{entry.uplink.udp_healthy === false ? "down" : "ok"}}</span>
        </div>`;
      list.appendChild(row);
    }}
    card.appendChild(list);
    root.appendChild(card);
  }}
}}
function renderGroups() {{
  const root = document.getElementById("groupsGrid");
  root.innerHTML = "";
  for (const [groupName, uplinks] of state.groups.entries()) {{
    const entries = [...uplinks.values()].flat();
    const groupSample = entries[0]?.groupObj;
    const instances = [...new Set(entries.map(e => e.instance))];
    const healthyCount = entries.filter(healthy).length;
    const activeCount = entries.filter(active).length;
    const card = document.createElement("article");
    card.className = "catalog-card";
    card.innerHTML = `
      <div class="instance-head">
        <span class="status" style="background:${{healthyCount > 0 ? "var(--green)" : "#aeb4bd"}}"></span>
        <div>
          <div class="instance-name">${{escapeHtml(groupName)}}</div>
          <div class="instance-sub">${{instances.length}} инстансов, ${{uplinks.size}} аплинков</div>
        </div>
      </div>
      <div class="catalog-meta">
        <div class="metric"><div class="metric-label">Инстансы</div><div class="metric-value">${{instances.length}}</div></div>
        <div class="metric"><div class="metric-label">Аплинки</div><div class="metric-value">${{uplinks.size}}</div></div>
        <div class="metric"><div class="metric-label">Активные</div><div class="metric-value">${{activeCount}}</div></div>
      </div>`;
    if (groupSample) {{
      const chips = document.createElement("div");
      chips.className = "config-chips";
      chips.innerHTML = groupConfigChips(groupSample);
      card.appendChild(chips);
    }}
    const list = document.createElement("div");
    list.className = "catalog-list";
    for (const [uplinkName, uplinkEntries] of uplinks.entries()) {{
      const row = document.createElement("div");
      row.className = "catalog-row";
      row.innerHTML = `
        <div class="catalog-row-top">
          <span class="instance-group-name">${{escapeHtml(uplinkName)}}</span>
          <span class="badge">${{uplinkEntries.some(active) ? "Активный" : (uplinkEntries.some(healthy) ? "Доступен" : "Неактивный")}}</span>
        </div>
        <div class="tiny-chips">${{uplinkEntries.map(entry => `<span class="tiny-chip">${{escapeHtml(entry.instance)}}</span>`).join("")}}</div>`;
      list.appendChild(row);
    }}
    card.appendChild(list);
    root.appendChild(card);
  }}
}}
function renderRefreshButton() {{
  const btn = document.getElementById("refreshBtn");
  const label = document.getElementById("refreshLabel");
  btn.classList.toggle("off", !autoRefreshEnabled);
  btn.setAttribute("aria-pressed", String(autoRefreshEnabled));
  label.textContent = autoRefreshEnabled ? "Автообновление" : "Автообновление выкл";
}}
function stopAutoRefresh() {{
  if (timer !== null) {{
    clearInterval(timer);
    timer = null;
  }}
}}
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
function toggleGroup(group) {{
  if (state.collapsedGroups.has(group)) {{
    state.collapsedGroups.delete(group);
  }} else {{
    state.collapsedGroups.add(group);
  }}
  render();
}}
function toggleInstance(instance) {{
  if (state.collapsedInstances.has(instance)) {{
    state.collapsedInstances.delete(instance);
  }} else {{
    state.collapsedInstances.add(instance);
  }}
  render();
}}
function setView(view) {{
  currentView = view;
  renderNav();
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
function entriesForGroup(uplinks) {{
  return [...uplinks.values()].flat();
}}
document.getElementById("refreshBtn").addEventListener("click", toggleAutoRefresh);
document.querySelectorAll("[data-view]").forEach(el => el.addEventListener("click", () => setView(el.dataset.view)));
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
