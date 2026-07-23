//! Separate browser dashboard for managing users on configured control instances.
//!
//! The browser talks only to this listener. Per-instance bearer tokens stay in
//! the process config and are injected server-side when proxying to `/control`.

mod auth;
mod control_pool;
mod handlers;
mod proxy;
mod tls;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, patch, post},
};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::{DashboardConfig, DashboardInstanceConfig};

use super::shutdown::ShutdownSignal;
use control_pool::ControlPool;

/// Idle control-API connections parked per instance. Two covers the browser's
/// parallel fetches on a dashboard refresh without holding sockets open for a
/// dashboard nobody is watching.
const CONTROL_POOL_MAX_IDLE_PER_TARGET: usize = 2;
/// How long a parked connection stays reusable. Kept short: upstreams and any
/// middlebox in between drop idle keep-alive sockets silently, and a stale one
/// costs a failed request before we redial.
const CONTROL_POOL_IDLE_TTL_SECS: u64 = 30;

#[derive(Clone)]
pub(super) struct DashboardState {
    pub(super) request_timeout_secs: u64,
    pub(super) refresh_interval_secs: u64,
    pub(super) instances: Arc<[DashboardInstanceConfig]>,
    pub(super) tls_connector: TlsConnector,
    /// Optional shared secret guarding the whole listener. `None` keeps the
    /// historical unauthenticated behaviour for loopback deployments.
    pub(super) token: Option<Arc<str>>,
    /// Keep-alive connections to the control APIs, reused across requests.
    /// Dashboard-internal: nothing outside this module drives the proxy path.
    pub(in crate::server::dashboard) control_pool: Arc<ControlPool>,
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
        authenticated = config.token.is_some(),
        "dashboard server started"
    );
    auth::warn_if_unauthenticated_exposure(config.listen, config.token.is_some());

    let state = DashboardState {
        request_timeout_secs: config.request_timeout_secs,
        refresh_interval_secs: config.refresh_interval_secs,
        instances: Arc::from(config.instances),
        tls_connector: tls::connector(),
        token: config.token.map(Arc::from),
        control_pool: Arc::new(ControlPool::new(
            CONTROL_POOL_MAX_IDLE_PER_TARGET,
            Duration::from_secs(CONTROL_POOL_IDLE_TTL_SECS),
        )),
    };

    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("dashboard server exited unexpectedly")
}

fn build_router(state: DashboardState) -> Router {
    let router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(handlers::dashboard_page))
        .route("/dashboard/assets/outline-logo.png", get(handlers::dashboard_logo))
        .route("/dashboard/api/instances", get(handlers::list_instances))
        .route("/dashboard/api/users", get(handlers::list_users).post(handlers::create_user))
        .route(
            "/dashboard/api/users/{id}",
            patch(handlers::update_user).delete(handlers::delete_user),
        )
        .route("/dashboard/api/users/{id}/access-urls", get(handlers::get_user_access_urls))
        .route("/dashboard/api/users/{id}/block", post(handlers::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(handlers::unblock_user))
        .fallback(handlers::not_found);

    let router = if state.token.is_some() {
        router.layer(middleware::from_fn_with_state(state.clone(), auth::require_dashboard_auth))
    } else {
        router
    };
    router.with_state(state)
}
