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
    url.set_path(path);
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
  --nav: #101a2b;
  --nav-2: #16233a;
  --text: #172033;
  --muted: #667085;
  --line: #d9dee7;
  --soft: #f6f8fb;
  --green: #31a852;
  --green-soft: #e8f7ed;
  --blue: #3b82f6;
  --red: #d92d20;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--text); background: #f8fafc; }}
.shell {{ min-height: 100vh; display: grid; grid-template-columns: 244px 1fr; }}
.nav {{ background: var(--nav); color: #d7deeb; display: flex; flex-direction: column; min-height: 100vh; }}
.brand {{ height: 88px; display: flex; gap: 12px; align-items: center; padding: 0 24px; font-weight: 700; color: #fff; }}
.logo {{ width: 28px; height: 28px; border-radius: 7px; border: 2px solid #60a5fa; position: relative; transform: rotate(-30deg); }}
.logo:before,.logo:after {{ content: ""; position: absolute; border: 2px solid #60a5fa; border-radius: 7px; width: 13px; height: 8px; top: 7px; background: var(--nav); }}
.logo:before {{ left: -8px; }} .logo:after {{ right: -8px; }}
.menu {{ padding: 12px 14px; display: grid; gap: 8px; }}
.item {{ height: 44px; width: 100%; border: 0; border-radius: 6px; display: flex; align-items: center; gap: 12px; padding: 0 14px; color: #c8d1df; background: transparent; text-align: left; }}
.item.active {{ background: #22314d; color: #60a5fa; }}
.spacer {{ flex: 1; }}
.stats {{ margin: 16px; border: 1px solid #263650; border-radius: 8px; padding: 16px; display: grid; gap: 10px; }}
.stats b {{ display: block; font-size: 25px; color: #fff; }}
.stats .good {{ color: #65d783; }}
.stamp {{ height: 76px; border-top: 1px solid #22314d; padding: 22px 24px; color: #8e9bb0; font-size: 13px; }}
main {{ padding: 30px 34px 18px; min-width: 0; }}
.topbar {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 26px; }}
h1 {{ margin: 0; font-size: 34px; line-height: 1; letter-spacing: 0; }}
.refresh {{ border: 1px solid var(--line); background: #fff; border-radius: 6px; padding: 10px 14px; display: flex; align-items: center; gap: 10px; color: #344054; box-shadow: 0 1px 2px #1018280d; }}
.refresh.off {{ color: #667085; background: #f8fafc; }}
.dot {{ width: 10px; height: 10px; border-radius: 99px; background: var(--green); display: inline-block; }}
.refresh.off .dot {{ background: #c7ced8; }}
.groups {{ display: grid; gap: 20px; }}
.view {{ display: none; }}
.view.active {{ display: block; }}
.group {{ background: #fff; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }}
.group-head {{ min-height: 64px; display: flex; align-items: center; gap: 16px; padding: 0 28px; border-bottom: 1px solid #e9edf3; }}
.group-title {{ font-size: 17px; display: flex; align-items: center; gap: 10px; }}
.group-title b {{ font-weight: 700; }}
.group-meta {{ margin-left: auto; display: flex; gap: 34px; color: #536079; }}
.cards {{ padding: 16px; display: grid; grid-template-columns: repeat(3, minmax(220px, 1fr)); gap: 14px; }}
.card {{ min-height: 98px; border: 1px solid var(--line); border-radius: 8px; padding: 15px; display: grid; align-content: start; gap: 14px; background: #fff; cursor: pointer; transition: border-color .15s, background .15s, transform .15s; }}
.card.active {{ border-color: #79c893; background: #f8fffa; }}
.card:hover {{ transform: translateY(-1px); }}
.card[aria-disabled="true"] {{ cursor: default; transform: none; opacity: .82; }}
.card-row {{ display: flex; align-items: center; gap: 10px; min-width: 0; }}
.status {{ width: 12px; height: 12px; border-radius: 99px; background: #aeb4bd; flex: 0 0 auto; }}
.active .status {{ background: var(--green); }}
.uplink {{ font-weight: 700; font-size: 17px; overflow-wrap: anywhere; }}
.badge {{ margin-left: auto; border-radius: 999px; padding: 5px 12px; background: #eef0f4; color: #6b7280; font-size: 13px; white-space: nowrap; }}
.active .badge {{ background: var(--green-soft); color: #269444; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 9px; }}
.chip {{ border: 1px solid #dde5dd; background: #eff6f1; border-radius: 7px; padding: 6px 11px; font-size: 13px; color: #1f2937; }}
.instances-grid {{ display: grid; grid-template-columns: repeat(2, minmax(280px, 1fr)); gap: 18px; }}
.instance-card {{ background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 18px; display: grid; gap: 14px; }}
.instance-head {{ display: flex; align-items: center; gap: 12px; }}
.instance-name {{ font-size: 19px; font-weight: 700; }}
.instance-sub {{ color: var(--muted); font-size: 14px; }}
.instance-meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
.metric {{ border: 1px solid #e8ecf3; border-radius: 8px; padding: 12px; background: #fbfcfe; }}
.metric-label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
.metric-value {{ font-size: 22px; font-weight: 700; }}
.instance-groups {{ display: grid; gap: 10px; }}
.instance-group {{ border: 1px solid #e8ecf3; border-radius: 8px; padding: 12px; background: #fff; }}
.instance-group-top {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }}
.instance-group-name {{ font-weight: 700; }}
.tiny-chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.tiny-chip {{ border-radius: 999px; padding: 5px 10px; background: #f2f4f7; color: #344054; font-size: 12px; }}
.error {{ border: 1px solid #f6c4be; background: #fff5f3; color: #9f1f14; border-radius: 8px; padding: 14px 16px; }}
.hint {{ text-align: center; color: #8a94a6; margin-top: 18px; font-size: 14px; }}
@media (max-width: 980px) {{
  .shell {{ grid-template-columns: 1fr; }}
  .nav {{ min-height: auto; }}
  .menu,.stats,.stamp {{ display: none; }}
  main {{ padding: 24px 16px; }}
  .cards {{ grid-template-columns: 1fr; }}
  .instances-grid {{ grid-template-columns: 1fr; }}
  .instance-meta {{ grid-template-columns: 1fr; }}
  .group-head {{ flex-wrap: wrap; padding: 16px; }}
  .group-meta {{ margin-left: 0; width: 100%; justify-content: space-between; gap: 12px; }}
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
      <div class="item">↗ <span>Аплинки</span></div>
      <div class="item">◎ <span>Группы</span></div>
      <div class="item">▤ <span>Логи</span></div>
      <div class="item">⚙ <span>Настройки</span></div>
    </nav>
    <div class="spacer"></div>
    <div class="stats">
      <span>Всего инстансов</span><b id="instancesTotal">0</b>
      <span>Активных аплинков</span><b><span class="good" id="activeTotal">0</span> / <span id="uplinksTotal">0</span></b>
    </div>
    <div class="stamp">Обновлено: <span id="updatedAt">-</span></div>
  </aside>
  <main>
    <div class="topbar">
      <h1 id="viewTitle">Дашборд</h1>
      <button class="refresh" id="refreshBtn" type="button">↻ <span id="refreshLabel">Автообновление</span> <span class="dot"></span></button>
    </div>
    <div id="errors"></div>
    <section class="view active" id="dashboardView">
      <section class="groups" id="groups"></section>
      <div class="hint">Нажмите на неактивный аплинк для его активации через /control/activate</div>
    </section>
    <section class="view" id="instancesView">
      <section class="instances-grid" id="instancesGrid"></section>
    </section>
  </main>
</div>
<script>
const refreshMs = {refresh_ms};
let timer = null;
let autoRefreshEnabled = true;
let currentView = "dashboard";
const state = {{ groups: new Map(), instances: [], errors: [] }};

function groupKey(group, uplink) {{ return group + "\u0000" + uplink; }}
function healthy(entry) {{
  return entry.uplink.tcp_healthy !== false && entry.uplink.udp_healthy !== false;
}}
function active(entry) {{
  const u = entry.uplink;
  return Boolean(u.active_global || u.active_tcp || u.active_udp);
}}
function rebuild(raw) {{
  state.groups = new Map();
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
    for (const group of groups) {{
      if (!state.groups.has(group.name)) state.groups.set(group.name, new Map());
      const byUplink = state.groups.get(group.name);
      for (const uplink of group.uplinks || []) {{
        const key = uplink.name;
        if (!byUplink.has(key)) byUplink.set(key, []);
        byUplink.get(key).push({{ instance: inst.name, group: group.name, uplink }});
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
  document.getElementById("viewTitle").textContent = currentView === "dashboard" ? "Дашборд" : "Инстансы";
}}
function render() {{
  renderErrors();
  const root = document.getElementById("groups");
  root.innerHTML = "";
  let instances = new Set(), uplinksTotal = 0, activeTotal = 0;
  for (const [group, uplinks] of state.groups.entries()) {{
    let instanceCount = 0;
    const groupEl = document.createElement("article");
    groupEl.className = "group";
    const cards = document.createElement("div");
    cards.className = "cards";
    for (const [uplinkName, entries] of uplinks.entries()) {{
      uplinksTotal += entries.length;
      instanceCount += entries.length;
      entries.forEach(e => instances.add(e.instance));
      const isActive = entries.some(active);
      if (isActive) activeTotal += entries.length;
      const isHealthy = entries.some(healthy);
      const card = document.createElement("button");
      card.className = "card" + (isActive ? " active" : "");
      card.type = "button";
      card.setAttribute("aria-disabled", String(isActive));
      card.innerHTML = `
        <div class="card-row">
          <span class="status"></span>
          <span class="uplink">${{escapeHtml(uplinkName)}}</span>
          <span class="badge">${{isActive ? "Активный" : (isHealthy ? "Доступен" : "Неактивный")}}</span>
        </div>
        <div class="chips">${{entries.map(e => `<span class="chip">${{escapeHtml(e.instance)}}</span>`).join("")}}</div>`;
      if (!isActive) {{
        card.addEventListener("click", () => activateEntries(entries));
      }}
      cards.appendChild(card);
    }}
    groupEl.innerHTML = `
      <header class="group-head">
        <div class="group-title"><span style="color: var(--blue)">♙</span><span>Группа: <b>${{escapeHtml(group)}}</b></span></div>
        <div class="group-meta"><span>Инстансов: <b>${{instanceCount}}</b></span><span>Аплинков: <b>${{uplinks.size}}</b></span><span>⌃</span></div>
      </header>`;
    groupEl.appendChild(cards);
    root.appendChild(groupEl);
  }}
  document.getElementById("instancesTotal").textContent = instances.size;
  document.getElementById("uplinksTotal").textContent = uplinksTotal;
  document.getElementById("activeTotal").textContent = activeTotal;
  document.getElementById("updatedAt").textContent = new Date().toLocaleTimeString();
  renderInstances();
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
}
