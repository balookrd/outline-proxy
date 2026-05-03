use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use outline_metrics::record_metrics_http_request;
use outline_uplink::UplinkRegistry;

use crate::config::ControlConfig;
use crate::http::serve::{ServeConfig, serve_with_shutdown};
use super::apply::{ApplyHandle, handle_apply};
use super::handlers::{handle_activate, handle_summary, handle_switch, handle_topology};
use super::uplinks_crud::handle_uplinks;
use super::{ControlResponse, is_authorized, plain_response, unauthorized_response};

pub(crate) struct ControlState {
    pub(crate) token: String,
    pub(crate) uplinks: UplinkRegistry,
    /// Path to the TOML config file. Populated when the binary was launched
    /// with an on-disk config; `None` for pure-CLI / test invocations. CRUD
    /// endpoints return 409 Conflict when this is absent.
    pub(crate) config_path: Option<PathBuf>,
    /// Serialises writes to `config_path` so concurrent CRUD requests cannot
    /// interleave reads and renames of the same file.
    pub(crate) config_write_lock: tokio::sync::Mutex<()>,
    /// Hot-apply handle — rebuilds the live `UplinkRegistry` from the
    /// on-disk config without process restart. `None` for test-only
    /// ControlStates (built inside mod tests without a real config file).
    pub(crate) apply: Option<Arc<ApplyHandle>>,
}

/// Cap concurrent in-flight control requests. The control plane is only
/// used for rare manual switches, so a tight ceiling bounds slowloris
/// impact without ever rate-limiting legitimate use.
const MAX_CONCURRENT_CONTROL_CONNECTIONS: usize = 16;

/// Hard cap on how long a client may take to send its request headers.
/// Slowloris must not be able to pin control-plane sockets — especially
/// because the bearer-token check happens *after* hyper has read the
/// headers, so an unauthenticated peer can otherwise stall us.
const CONTROL_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Window for in-flight control requests to finish on SIGTERM before the
/// listener gives up and returns. Control endpoints are short-lived
/// (config writes, switches), so a couple of seconds is ample.
const CONTROL_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

pub fn spawn_control_server(
    config: ControlConfig,
    uplinks: UplinkRegistry,
    apply: Option<Arc<ApplyHandle>>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let state = Arc::new(ControlState {
        token: config.token,
        uplinks,
        config_path: config.config_path,
        config_write_lock: tokio::sync::Mutex::new(()),
        apply,
    });
    let listen = config.listen;
    tokio::spawn(async move {
        if let Err(error) = run_control_server(listen, state, shutdown).await {
            warn!(error = %format!("{error:#}"), "control server stopped");
        }
    })
}

async fn run_control_server(
    listen: std::net::SocketAddr,
    state: Arc<ControlState>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind control listener {listen}"))?;
    info!(%listen, "control server started");

    serve_with_shutdown(
        listener,
        ServeConfig {
            server_name: "control",
            max_concurrent: MAX_CONCURRENT_CONTROL_CONNECTIONS,
            drain_timeout: CONTROL_DRAIN_TIMEOUT,
        },
        shutdown,
        move |stream, _peer| {
            let state = Arc::clone(&state);
            async move { handle_connection(stream, state).await }
        },
    )
    .await
}

pub(crate) async fn handle_connection(stream: TcpStream, state: Arc<ControlState>) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(CONTROL_HEADER_READ_TIMEOUT)
        .serve_connection(
            io,
            service_fn(move |request: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle_request(request, state).await) }
            }),
        )
        .await
        .context("failed to serve control HTTP connection")?;
    Ok(())
}

async fn handle_request(request: Request<Incoming>, state: Arc<ControlState>) -> ControlResponse {
    let label_path: &'static str = match request.uri().path() {
        "/switch" => "/switch",
        "/control/topology" => "/control/topology",
        "/control/summary" => "/control/summary",
        "/control/activate" => "/control/activate",
        "/control/uplinks" => "/control/uplinks",
        "/control/apply" => "/control/apply",
        _ => "other",
    };

    if !is_authorized(&request, &state.token) {
        record_metrics_http_request(label_path, 401);
        return unauthorized_response();
    }

    match label_path {
        "/switch" => {
            let response = handle_switch(&request, state.uplinks.clone()).await;
            record_metrics_http_request("/switch", response.status().as_u16());
            response
        },
        "/control/topology" => {
            let response = handle_topology(&request, state.uplinks.clone()).await;
            record_metrics_http_request("/control/topology", response.status().as_u16());
            response
        },
        "/control/summary" => {
            let response = handle_summary(&request, state.uplinks.clone()).await;
            record_metrics_http_request("/control/summary", response.status().as_u16());
            response
        },
        "/control/activate" => {
            let response = handle_activate(request, state.uplinks.clone()).await;
            record_metrics_http_request("/control/activate", response.status().as_u16());
            response
        },
        "/control/uplinks" => {
            let response = handle_uplinks(request, Arc::clone(&state)).await;
            record_metrics_http_request("/control/uplinks", response.status().as_u16());
            response
        },
        "/control/apply" => {
            let response = match state.apply.as_ref() {
                Some(handle) => handle_apply(request, Arc::clone(handle)).await,
                None => plain_response(
                    http::StatusCode::CONFLICT,
                    "application/json; charset=utf-8",
                    bytes::Bytes::from_static(
                        br#"{"error":"apply handle not configured; restart required to activate config changes"}"#,
                    ),
                ),
            };
            record_metrics_http_request("/control/apply", response.status().as_u16());
            response
        },
        _ => {
            record_metrics_http_request("other", 404);
            plain_response(
                http::StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                bytes::Bytes::from_static(b"not found\n"),
            )
        },
    }
}
