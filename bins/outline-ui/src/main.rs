//! Aggregating web UI for the outline fleet. Serves both dashboards and nothing
//! else: no uplinks, no listeners, no traffic. Every route reaches the
//! configured instances' control APIs with their bearer tokens injected
//! server-side, so both gates below run before routing rather than inside
//! handlers — a route added later cannot sit outside a check by not asking.

mod assets;
mod auth;
mod backend;
mod config;
mod origin;
mod ss;
mod ws;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::get;
use axum::{Router, middleware};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use crate::backend::Backend;
use crate::config::UiConfig;

#[derive(Parser, Debug)]
#[command(name = "outline-ui", about = "Web UI for the outline fleet")]
struct Args {
    /// Path to the UI configuration file.
    #[arg(long, env = "OUTLINE_UI_CONFIG", default_value = "/etc/outline-ui/config.toml")]
    config: PathBuf,
}

fn build_app(config: &UiConfig) -> Router {
    let backend = Arc::new(Backend::new(config.request_timeout_secs));
    let refresh_ms = config.refresh_interval_secs.saturating_mul(1000);

    let ws_state = ws::WsState {
        backend: Arc::clone(&backend),
        instances: Arc::from(config.ws.clone()),
        refresh_ms,
    };
    let ss_state = ss::SsState {
        backend,
        instances: Arc::from(config.ss.clone()),
        refresh_ms,
    };

    let router =
        Router::new()
            .route(
                "/ui-assets/{*path}",
                get(|axum::extract::Path(p): axum::extract::Path<String>| async move {
                    assets::asset(&p)
                }),
            )
            .route("/", get(|| async { assets::spa_index() }))
            .nest("/ws", ws::router(ws_state))
            .nest("/ss", ss::router(ss_state))
            // Client-side routes deep-linked at the top level (and any other
            // unmatched path) still get the SPA shell, which then routes itself.
            .fallback(|| async { assets::spa_index() });

    // Origin inner, credentials outermost: an unauthorised caller gets a plain
    // 401 rather than a 403 describing what this listener expects.
    let policy = origin::OriginPolicy::new(config.listen, &config.allowed_hosts);
    let router = router.layer(middleware::from_fn_with_state(policy, origin::enforce_origin));
    let auth_state = auth::AuthState { token: Arc::from(config.token.as_str()) };
    router.layer(middleware::from_fn_with_state(auth_state, auth::require_auth))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = UiConfig::load(&args.config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    // Every field is logged deliberately: this is the whole of what the service
    // was told to do, and an operator debugging a 403 or a stalled page wants to
    // see the timeouts and allowed hosts it actually loaded.
    info!(
        listen = %config.listen,
        ws_instances = config.ws.len(),
        ss_instances = config.ss.len(),
        request_timeout_secs = config.request_timeout_secs,
        refresh_interval_secs = config.refresh_interval_secs,
        allowed_hosts = config.allowed_hosts.len(),
        "outline-ui started"
    );

    axum::serve(listener, build_app(&config))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("server stopped")
}

#[cfg(test)]
#[path = "tests/routing.rs"]
mod tests;
