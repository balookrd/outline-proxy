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

use crate::config::ControlConfig;

use super::super::shutdown::ShutdownSignal;
use super::handlers::{
    ControlState, block_user, create_user, delete_user, get_user, get_user_access_urls, list_users,
    unblock_user, update_user,
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
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind control listener {}", config.listen))?;
    info!(listen = %config.listen, "control server started");

    let state = ControlState { manager, token: Arc::from(config.token) };

    let router = Router::new()
        .route("/control/users", get(list_users).post(create_user))
        .route("/control/users/{id}", get(get_user).patch(update_user).delete(delete_user))
        .route("/control/users/{id}/access-urls", get(get_user_access_urls))
        .route("/control/users/{id}/block", post(block_user))
        .route("/control/users/{id}/unblock", post(unblock_user))
        .fallback(any(not_found))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer_token))
        .with_state(state);

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("control server exited unexpectedly")
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
mod tests {
    use super::*;

    #[test]
    fn bearer_token_parsing() {
        let ok = HeaderValue::from_static("Bearer secret");
        assert!(bearer_token_matches(&ok, "secret"));
        let wrong = HeaderValue::from_static("Bearer bad");
        assert!(!bearer_token_matches(&wrong, "secret"));
        let basic = HeaderValue::from_static("Basic secret");
        assert!(!bearer_token_matches(&basic, "secret"));
    }
}
