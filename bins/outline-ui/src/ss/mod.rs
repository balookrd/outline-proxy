//! Server dashboard: user CRUD across instances.

mod api;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, patch, post};

use crate::backend::Backend;
use crate::config::InstanceConfig;

const DASHBOARD_TEMPLATE: &str = include_str!("dashboard.html");

/// Mount point of this tree; see the note on `ws::BASE`.
pub const BASE: &str = "/ss";

#[derive(Clone)]
pub struct SsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: SsState) -> Router {
    Router::new()
        .route("/", get(|| async { axum::response::Redirect::temporary("/ss/dashboard") }))
        .route("/dashboard", get(api::dashboard_page))
        .route("/dashboard/assets/outline-logo.png", get(|| async { crate::assets::logo() }))
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/users", get(api::list_users).post(api::create_user))
        .route("/dashboard/api/users/{id}", patch(api::update_user).delete(api::delete_user))
        .route("/dashboard/api/users/{id}/block", post(api::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(api::unblock_user))
        .fallback(|| async { crate::assets::not_found() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
