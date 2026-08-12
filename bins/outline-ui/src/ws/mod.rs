//! Client dashboard: uplinks, topology, carrier loss.

mod api;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::backend::Backend;
use crate::config::InstanceConfig;

const DASHBOARD_TEMPLATE: &str = include_str!("dashboard.html");
const UPLINKS_TEMPLATE: &str = include_str!("uplinks.html");

/// Mount point of this tree. Handlers embed it in the HTML they serve, so it
/// must match the `nest` prefix in `main.rs` — a mismatch makes every fetch from
/// the page 404 while the page itself loads fine.
pub const BASE: &str = "/ws";

#[derive(Clone)]
pub struct WsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: WsState) -> Router {
    Router::new()
        .route("/", get(|| async { axum::response::Redirect::temporary("/ws/dashboard") }))
        .route("/dashboard", get(api::dashboard_page))
        .route("/dashboard/uplinks", get(api::uplinks_page))
        .route("/dashboard/outline-logo.png", get(|| async { crate::assets::logo() }))
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/topology", get(api::topology))
        .route("/dashboard/api/activate", post(api::activate))
        .route("/dashboard/api/set_enabled", post(api::set_enabled))
        .route("/dashboard/api/reselect", post(api::reselect))
        .route(
            "/dashboard/api/uplinks",
            get(api::uplinks_proxy)
                .post(api::uplinks_proxy)
                .patch(api::uplinks_proxy)
                .delete(api::uplinks_proxy),
        )
        .route("/dashboard/api/apply", post(api::apply_proxy))
        .fallback(|| async { crate::assets::not_found() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
