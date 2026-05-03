//! Built-in dashboard for monitoring and switching configured instances.
//!
//! The browser talks only to this listener. Instance bearer tokens stay in the
//! process config and are used server-side when proxying to each control API.

mod api;
mod backend_client;
mod response;
mod ui;

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{DashboardConfig, DashboardInstanceConfig};
use crate::http::serve::{ServeConfig, serve_with_shutdown};

use self::response::{
    html_response, plain_response, redirect_response, DashboardResponse,
};

#[derive(Clone)]
struct DashboardState {
    refresh_interval_secs: u64,
    request_timeout_secs: u64,
    instances: Vec<DashboardInstanceConfig>,
}

/// Bound concurrent dashboard requests so a single misbehaving browser tab
/// (or a slowloris) cannot exhaust file descriptors. The dashboard fans out
/// to instance backends per request, so 64 is generous for the expected
/// single-operator UI.
const MAX_CONCURRENT_DASHBOARD_CONNECTIONS: usize = 64;

const DASHBOARD_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

pub fn spawn_dashboard_server(
    config: DashboardConfig,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let listen = config.listen;
    let state = DashboardState {
        refresh_interval_secs: config.refresh_interval_secs,
        request_timeout_secs: config.request_timeout_secs,
        instances: config.instances,
    };
    tokio::spawn(async move {
        if let Err(error) = run_dashboard_server(listen, state, shutdown).await {
            warn!(error = %format!("{error:#}"), "dashboard server stopped");
        }
    })
}

async fn run_dashboard_server(
    listen: std::net::SocketAddr,
    state: DashboardState,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind dashboard listener {listen}"))?;
    info!(%listen, instances = state.instances.len(), "dashboard server started");

    serve_with_shutdown(
        listener,
        ServeConfig {
            server_name: "dashboard",
            max_concurrent: MAX_CONCURRENT_DASHBOARD_CONNECTIONS,
            drain_timeout: DASHBOARD_DRAIN_TIMEOUT,
        },
        shutdown,
        move |stream, _peer| {
            let state = state.clone();
            async move { handle_connection(stream, state).await }
        },
    )
    .await
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
        (&Method::GET, "/dashboard") => {
            html_response(ui::dashboard_html(state.refresh_interval_secs))
        },
        (&Method::GET, "/dashboard/uplinks") => html_response(ui::uplinks_html()),
        (&Method::GET, "/dashboard/outline-logo.png") => plain_response(
            StatusCode::OK,
            "image/png",
            Bytes::from_static(include_bytes!("outline-logo.png")),
        ),
        (&Method::GET, "/dashboard/api/instances") => api::handle_instances(state).await,
        (&Method::GET, "/dashboard/api/topology") => api::handle_topology(request, state).await,
        (&Method::POST, "/dashboard/api/activate") => api::handle_activate(request, state).await,
        (&Method::GET, "/dashboard/api/uplinks")
        | (&Method::POST, "/dashboard/api/uplinks")
        | (&Method::PATCH, "/dashboard/api/uplinks")
        | (&Method::DELETE, "/dashboard/api/uplinks") => {
            api::handle_uplinks_proxy(request, state).await
        },
        (&Method::POST, "/dashboard/api/apply") => api::handle_apply_proxy(request, state).await,
        _ => plain_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found\n"),
        ),
    }
}
