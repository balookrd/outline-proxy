//! HTTP handlers for the control plane.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::{CipherKind, UserEntry};

use super::manager::{UserManager, UserView};

#[derive(Clone)]
pub(super) struct ControlState {
    pub manager: Arc<UserManager>,
    pub token: Arc<str>,
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ListResponse {
    pub users: Vec<UserView>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateRequest {
    pub id: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub vless_id: Option<String>,
    #[serde(default)]
    pub method: Option<CipherKind>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub ws_path_tcp: Option<String>,
    #[serde(default)]
    pub ws_path_udp: Option<String>,
    #[serde(default)]
    pub vless_ws_path: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl From<CreateRequest> for UserEntry {
    fn from(req: CreateRequest) -> Self {
        Self {
            id: req.id,
            password: req.password,
            fwmark: req.fwmark,
            method: req.method,
            ws_path_tcp: req.ws_path_tcp,
            ws_path_udp: req.ws_path_udp,
            vless_id: req.vless_id,
            vless_ws_path: req.vless_ws_path,
            enabled: req.enabled,
        }
    }
}

fn ok_json<T: Serialize>(payload: T) -> axum::response::Response {
    (StatusCode::OK, Json(payload)).into_response()
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> axum::response::Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

pub(super) async fn list_users(
    State(state): State<ControlState>,
) -> axum::response::Response {
    ok_json(ListResponse { users: state.manager.list() })
}

pub(super) async fn get_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.manager.get(&id) {
        Some(view) => ok_json(view),
        None => error_response(StatusCode::NOT_FOUND, format!("user {id:?} not found")),
    }
}

pub(super) async fn create_user(
    State(state): State<ControlState>,
    Json(req): Json<CreateRequest>,
) -> axum::response::Response {
    match state.manager.create(req.into()) {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "control create_user rejected");
            error_response(StatusCode::BAD_REQUEST, format!("{error:#}"))
        },
    }
}

pub(super) async fn delete_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.manager.delete(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "control delete_user failed");
            let status = if error.to_string().contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            error_response(status, format!("{error:#}"))
        },
    }
}

pub(super) async fn block_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    set_enabled(state, id, false).await
}

pub(super) async fn unblock_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    set_enabled(state, id, true).await
}

async fn set_enabled(
    state: ControlState,
    id: String,
    enabled: bool,
) -> axum::response::Response {
    match state.manager.set_enabled(&id, enabled) {
        Ok(view) => ok_json(view),
        Err(error) => {
            let msg = format!("{error:#}");
            warn!(%id, enabled, error = %msg, "control set_enabled failed");
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            error_response(status, msg)
        },
    }
}
