//! Server dashboard: user CRUD and cluster orchestration across instances.

mod api;
mod cluster;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, patch, post};

use crate::backend::Backend;
use crate::config::{ClusterConfig, InstanceConfig};

#[derive(Clone)]
pub struct SsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub clusters: Arc<[ClusterConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: SsState) -> Router {
    Router::new()
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/clusters", get(cluster::list_clusters))
        .route("/dashboard/api/clusters/{cluster}/defaults", get(cluster::defaults))
        .route(
            "/dashboard/api/clusters/{cluster}/config",
            get(cluster::get_config).patch(cluster::patch_config),
        )
        .route(
            "/dashboard/api/clusters/{cluster}/users",
            get(cluster::list_users).post(cluster::create_user),
        )
        .route(
            "/dashboard/api/clusters/{cluster}/users/{id}",
            patch(cluster::update_user).delete(cluster::delete_user),
        )
        .route("/dashboard/api/clusters/{cluster}/users/{id}/block", post(cluster::block_user))
        .route(
            "/dashboard/api/clusters/{cluster}/users/{id}/unblock",
            post(cluster::unblock_user),
        )
        .route(
            "/dashboard/api/clusters/{cluster}/users/{id}/access-keys",
            get(cluster::get_user_access_keys),
        )
        .route(
            "/dashboard/api/clusters/{cluster}/access-keys/regenerate",
            post(cluster::regenerate_access_keys),
        )
        .route("/dashboard/api/defaults", get(api::defaults))
        .route("/dashboard/api/config", get(api::get_config).patch(api::patch_config))
        .route("/dashboard/api/users", get(api::list_users).post(api::create_user))
        .route("/dashboard/api/users/{id}", patch(api::update_user).delete(api::delete_user))
        .route("/dashboard/api/users/{id}/block", post(api::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(api::unblock_user))
        .route("/dashboard/api/users/{id}/access-keys", get(api::get_user_access_keys))
        .route("/dashboard/api/access-keys/regenerate", post(api::regenerate_access_keys))
        .fallback(|| async { crate::assets::spa_index() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
