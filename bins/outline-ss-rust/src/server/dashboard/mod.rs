//! Separate browser dashboard for managing users on configured control instances.
//!
//! The browser talks only to this listener. Per-instance bearer tokens stay in
//! the process config and are injected server-side when proxying to `/control`.

mod auth;
mod control_pool;
mod guard;
mod handlers;
mod proxy;
mod tls;

#[cfg(test)]
mod tests;

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

use crate::config::{DashboardConfig, DashboardInstanceConfig, TuningProfile};

use super::bootstrap::serve_plain_listener;
use super::shutdown::ShutdownSignal;
use control_pool::ControlPool;
use guard::OriginPolicy;

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
    /// Host/Origin/Content-Type checks applied to every request before routing,
    /// independently of `token`. See [`guard`]. Dashboard-internal, like
    /// `control_pool`: nothing outside this module constructs the policy.
    pub(in crate::server::dashboard) origin_policy: OriginPolicy,
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

async fn run(config: DashboardConfig, shutdown: ShutdownSignal) -> Result<()> {
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
        origin_policy: OriginPolicy::new(config.listen, &config.allowed_hosts),
        instances: Arc::from(config.instances),
        tls_connector: tls::connector(),
        token: config.token.map(Arc::from),
        control_pool: Arc::new(ControlPool::new(
            CONTROL_POOL_MAX_IDLE_PER_TARGET,
            Duration::from_secs(CONTROL_POOL_IDLE_TTL_SECS),
        )),
    };

    serve_dashboard_router(listener, build_router(state), shutdown).await
}

/// Serve the dashboard router under the shared plain-HTTP accept loop, giving
/// the dashboard listener the same pre-auth slowloris bounds as the data-plane
/// listeners (connection cap + first-byte / header-read timeout) instead of the
/// unbounded `axum::serve` it used to run on. The origin guard and optional
/// token are application-layer gates that only run *after* headers are read, so
/// they do not bound an unauthenticated peer that connects and dribbles. Split
/// out from `run` so a regression test can drive it with an arbitrary
/// listener/router.
async fn serve_dashboard_router(
    listener: TcpListener,
    router: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    serve_plain_listener(listener, router, TuningProfile::default(), "dashboard", shutdown).await
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
        .route("/dashboard/api/users/{id}/block", post(handlers::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(handlers::unblock_user))
        .fallback(handlers::not_found);

    // The origin guard runs on every request, whether or not a token is set;
    // the credential gate, when present, is layered *after* it so it sits
    // outermost and answers first — an unauthorised caller gets a plain 401
    // rather than a 403 describing what this listener expects.
    let router =
        router.layer(middleware::from_fn_with_state(state.clone(), guard::enforce_origin_policy));
    let router = if state.token.is_some() {
        router.layer(middleware::from_fn_with_state(state.clone(), auth::require_dashboard_auth))
    } else {
        router
    };
    router.with_state(state)
}
