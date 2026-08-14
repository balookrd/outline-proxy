//! Client dashboard: uplinks, topology, carrier loss.

mod api;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::backend::Backend;
use crate::config::InstanceConfig;

#[derive(Clone)]
pub struct WsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: WsState) -> Router {
    Router::new()
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
        .route(
            "/dashboard/api/routes",
            get(api::routes_proxy)
                .post(api::routes_proxy)
                .patch(api::routes_proxy)
                .delete(api::routes_proxy),
        )
        .route("/dashboard/api/uplinks/reorder", post(api::uplinks_reorder_proxy))
        .route("/dashboard/api/routes/reorder", post(api::routes_reorder_proxy))
        .fallback(|| async { crate::assets::spa_index() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
