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

use super::manager::{AccessUrlError, FieldPatch, UserManager, UserPatch, UserView};

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
    pub ws_path_vless: Option<String>,
    #[serde(default)]
    pub xhttp_path_vless: Option<String>,
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
            ws_path_vless: req.ws_path_vless,
            xhttp_path_vless: req.xhttp_path_vless,
            enabled: req.enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateRequest {
    #[serde(default)]
    pub password: FieldPatch<String>,
    #[serde(default)]
    pub vless_id: FieldPatch<String>,
    #[serde(default)]
    pub method: FieldPatch<CipherKind>,
    #[serde(default)]
    pub fwmark: FieldPatch<u32>,
    #[serde(default)]
    pub ws_path_tcp: FieldPatch<String>,
    #[serde(default)]
    pub ws_path_udp: FieldPatch<String>,
    #[serde(default)]
    pub ws_path_vless: FieldPatch<String>,
    #[serde(default)]
    pub xhttp_path_vless: FieldPatch<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl From<UpdateRequest> for UserPatch {
    fn from(req: UpdateRequest) -> Self {
        Self {
            password: req.password,
            vless_id: req.vless_id,
            method: req.method,
            fwmark: req.fwmark,
            ws_path_tcp: req.ws_path_tcp,
            ws_path_udp: req.ws_path_udp,
            ws_path_vless: req.ws_path_vless,
            xhttp_path_vless: req.xhttp_path_vless,
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

pub(super) async fn list_users(State(state): State<ControlState>) -> axum::response::Response {
    ok_json(ListResponse { users: state.manager.list().await })
}

pub(super) async fn get_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.manager.get(&id).await {
        Some(view) => ok_json(view),
        None => error_response(StatusCode::NOT_FOUND, format!("user {id:?} not found")),
    }
}

pub(super) async fn get_user_access_urls(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.manager.access_urls(&id).await {
        Ok(view) => ok_json(view),
        Err(error) => {
            let status = match &error {
                AccessUrlError::NotFound(_) => StatusCode::NOT_FOUND,
                AccessUrlError::Build(_) => StatusCode::BAD_REQUEST,
            };
            let msg = match &error {
                AccessUrlError::NotFound(_) => error.to_string(),
                AccessUrlError::Build(err) => format!("{err:#}"),
            };
            warn!(%id, error = %msg, "control access URL generation failed");
            error_response(status, msg)
        },
    }
}

pub(super) async fn create_user(
    State(state): State<ControlState>,
    Json(req): Json<CreateRequest>,
) -> axum::response::Response {
    match state.manager.create(req.into()).await {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "control create_user rejected");
            error_response(StatusCode::BAD_REQUEST, format!("{error:#}"))
        },
    }
}

pub(super) async fn update_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRequest>,
) -> axum::response::Response {
    match state.manager.update(&id, req.into()).await {
        Ok(view) => ok_json(view),
        Err(error) => {
            let msg = format!("{error:#}");
            warn!(%id, error = %msg, "control update_user rejected");
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            error_response(status, msg)
        },
    }
}

pub(super) async fn delete_user(
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.manager.delete(&id).await {
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

async fn set_enabled(state: ControlState, id: String, enabled: bool) -> axum::response::Response {
    match state.manager.set_enabled(&id, enabled).await {
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
