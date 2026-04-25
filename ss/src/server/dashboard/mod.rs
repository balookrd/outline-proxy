//! Separate browser dashboard for managing users on configured control instances.
//!
//! The browser talks only to this listener. Per-instance bearer tokens stay in
//! the process config and are injected server-side when proxying to `/control`.

mod handlers;
mod proxy;
mod tls;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    response::Redirect,
    routing::{get, patch, post},
};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::{DashboardConfig, DashboardInstanceConfig};

use super::shutdown::ShutdownSignal;

#[derive(Clone)]
pub(super) struct DashboardState {
    pub(super) request_timeout_secs: u64,
    pub(super) refresh_interval_secs: u64,
    pub(super) instances: Arc<[DashboardInstanceConfig]>,
    pub(super) tls_connector: TlsConnector,
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
        tls_connector: tls::connector(),
    };

    let router = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(handlers::dashboard_page))
        .route(
            "/dashboard/assets/outline-logo.png",
            get(handlers::dashboard_logo),
        )
        .route("/dashboard/api/instances", get(handlers::list_instances))
        .route(
            "/dashboard/api/users",
            get(handlers::list_users).post(handlers::create_user),
        )
        .route(
            "/dashboard/api/users/{id}",
            patch(handlers::update_user).delete(handlers::delete_user),
        )
        .route(
            "/dashboard/api/users/{id}/access-urls",
            get(handlers::get_user_access_urls),
        )
        .route("/dashboard/api/users/{id}/block", post(handlers::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(handlers::unblock_user))
        .fallback(handlers::not_found)
        .with_state(state);

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("dashboard server exited unexpectedly")
}
