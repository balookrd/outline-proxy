//! Control server: axum listener guarded by a bearer token.
//!
//! Bound on a separate socket from the data plane and metrics listeners so
//! that exposing read-only observability does not imply authority to mutate
//! runtime state.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::{ControlConfig, TuningProfile};

use super::super::bootstrap::serve_plain_listener;
use super::super::shutdown::ShutdownSignal;
use super::handlers::{
    ControlState, block_user, create_user, delete_user, get_user, list_users, unblock_user,
    update_user,
};
use super::manager::UserManager;

pub(in crate::server) fn spawn_control_server(
    config: ControlConfig,
    manager: Arc<UserManager>,
    shutdown: ShutdownSignal,
) {
    tokio::spawn(async move {
        if let Err(error) = run(config, manager, shutdown).await {
            warn!(error = %format!("{error:#}"), "control server stopped");
        }
    });
}

async fn run(
    config: ControlConfig,
    manager: Arc<UserManager>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind control listener {}", config.listen))?;
    info!(listen = %config.listen, "control server started");

    let state = ControlState { manager, token: Arc::from(config.token) };

    let router = Router::new()
        .route("/control/users", get(list_users).post(create_user))
        .route("/control/users/{id}", get(get_user).patch(update_user).delete(delete_user))
        .route("/control/users/{id}/block", post(block_user))
        .route("/control/users/{id}/unblock", post(unblock_user))
        .fallback(any(not_found))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer_token))
        .with_state(state);

    serve_control_router(listener, router, shutdown).await
}

/// Serve the control API router under the shared plain-HTTP accept loop, giving
/// the control listener the same pre-auth slowloris bounds as the data-plane
/// listeners (connection cap + first-byte / header-read timeout) instead of the
/// unbounded `axum::serve` it used to run on. The bearer-token middleware is an
/// application-layer gate that only runs *after* headers are read, so it does
/// not bound an unauthenticated peer that connects and dribbles. Split out from
/// `run` so a regression test can drive it with an arbitrary listener/router.
async fn serve_control_router(
    listener: TcpListener,
    router: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    serve_plain_listener(listener, router, TuningProfile::default(), "control", shutdown).await
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

async fn require_bearer_token(
    State(state): State<ControlState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match request.headers().get(AUTHORIZATION) {
        Some(header) if bearer_token_matches(header, &state.token) => next.run(request).await,
        _ => {
            let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
            response
                .headers_mut()
                .insert("WWW-Authenticate", HeaderValue::from_static("Bearer"));
            response
        },
    }
}

fn bearer_token_matches(header: &HeaderValue, expected: &str) -> bool {
    let Ok(value) = header.to_str() else { return false };
    let Some(presented) = value.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;
