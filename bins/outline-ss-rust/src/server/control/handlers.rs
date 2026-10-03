//! HTTP handlers for the control plane.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::{CipherKind, Config, OneOrManyCidr, UserEntry};

use super::manager::{FieldPatch, UserManager, UserPatch, UserView};
use super::persist::{ServerConfigPatch, persist_config_patch};

#[derive(Clone)]
pub(super) struct ControlState {
    pub manager: Arc<UserManager>,
    pub config: Arc<Config>,
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
#[serde(deny_unknown_fields)]
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
    pub enabled: Option<bool>,
    #[serde(default)]
    pub aliases: Option<BTreeMap<String, OneOrManyCidr>>,
}

impl From<CreateRequest> for UserEntry {
    fn from(req: CreateRequest) -> Self {
        // Users are pure credentials — no per-user paths; routing is driven by
        // `Config.endpoints`.
        Self {
            id: req.id,
            password: req.password,
            fwmark: req.fwmark,
            method: req.method,
            vless_id: req.vless_id,
            enabled: req.enabled,
            aliases: req.aliases,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub enabled: Option<bool>,
    #[serde(default)]
    pub aliases: FieldPatch<BTreeMap<String, OneOrManyCidr>>,
}

impl From<UpdateRequest> for UserPatch {
    fn from(req: UpdateRequest) -> Self {
        Self {
            password: req.password,
            vless_id: req.vless_id,
            method: req.method,
            fwmark: req.fwmark,
            enabled: req.enabled,
            aliases: req.aliases,
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

/// Read-only snapshot of the server-wide default cipher. The dashboard needs
/// it to show a user's *effective* configuration: a user that carries no
/// method of its own runs on `default_method`, and the clone form cannot
/// generate a password without knowing which cipher that is.
pub(super) async fn get_defaults(State(state): State<ControlState>) -> axum::response::Response {
    ok_json(state.manager.defaults())
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

#[derive(Debug, Serialize)]
pub(super) struct ServerConfigResponse {
    pub config_path: Option<String>,
    pub cluster: Option<ClusterConfigView>,
    pub server: Option<ServerListenerConfigView>,
    pub session_resumption: Option<SessionResumptionConfigView>,
    pub outbound: Option<OutboundConfigView>,
    pub tuning_profile: Option<String>,
    pub endpoints: Vec<EndpointConfigView>,
}

#[derive(Debug, Serialize)]
pub(super) struct ClusterConfigView {
    pub enabled: bool,
    pub shard_id: Option<u8>,
    pub cluster_psk: Option<String>,
    pub has_cluster_psk: bool,
    pub mesh_listen: Option<String>,
    pub mesh_relay_budget_ms: Option<u64>,
    pub peers: Vec<ClusterPeerView>,
}

#[derive(Debug, Serialize)]
pub(super) struct ClusterPeerView {
    pub shard: u8,
    pub addr: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ServerListenerConfigView {
    pub listen: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub h3_listen: Option<String>,
    pub h3_cert_path: Option<String>,
    pub h3_key_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SessionResumptionConfigView {
    pub enabled: bool,
    pub orphan_ttl_tcp_secs: Option<u64>,
    pub orphan_ttl_udp_secs: Option<u64>,
    pub orphan_per_user_cap: Option<usize>,
    pub orphan_global_cap: Option<usize>,
    pub downlink_buffer_bytes: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(super) struct OutboundConfigView {
    pub prefer_ipv4: Option<bool>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_interface: Option<String>,
    pub ipv6_sticky: Option<bool>,
    pub ipv6_sticky_ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct EndpointConfigView {
    pub path: String,
    pub protocol: String,
    pub transport: String,
    pub padded: bool,
}

pub(super) async fn get_config(State(state): State<ControlState>) -> axum::response::Response {
    let config_path = state.manager.config_path().map(|p| p.display().to_string());

    // Attempt to read current on-disk FileConfig if config_path exists
    let disk_file: Option<crate::config::FileConfig> =
        if let Some(path) = state.manager.config_path() {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| toml::from_str(&text).ok())
        } else {
            None
        };

    let cluster = if let Some(df) = disk_file.as_ref().and_then(|f| f.cluster.as_ref()) {
        Some(ClusterConfigView {
            enabled: df.enabled.unwrap_or(false),
            shard_id: df.shard_id,
            has_cluster_psk: df.cluster_psk.as_ref().is_some_and(|k| !k.is_empty()),
            cluster_psk: df.cluster_psk.as_ref().map(|_| "********".to_string()),
            mesh_listen: df.mesh_listen.clone(),
            mesh_relay_budget_ms: df.mesh_relay_budget_ms,
            peers: df
                .peers
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|p| ClusterPeerView { shard: p.shard, addr: p.addr })
                .collect(),
        })
    } else if let Some(c) = state.config.cluster.as_ref() {
        Some(ClusterConfigView {
            enabled: true,
            shard_id: Some(c.shard.get()),
            has_cluster_psk: true,
            cluster_psk: Some("********".to_string()),
            mesh_listen: Some(c.mesh_listen.to_string()),
            mesh_relay_budget_ms: Some(c.mesh_relay_budget.as_millis() as u64),
            peers: c
                .peers
                .iter()
                .map(|(s, a)| ClusterPeerView { shard: (*s).get(), addr: a.to_string() })
                .collect(),
        })
    } else {
        Some(ClusterConfigView {
            enabled: false,
            shard_id: None,
            has_cluster_psk: false,
            cluster_psk: None,
            mesh_listen: None,
            mesh_relay_budget_ms: None,
            peers: Vec::new(),
        })
    };

    let server = if let Some(df) = disk_file.as_ref().and_then(|f| f.server.as_ref()) {
        Some(ServerListenerConfigView {
            listen: df.listen.map(|a| a.to_string()),
            cert_path: df.cert_path.as_ref().map(|p| p.display().to_string()),
            key_path: df.key_path.as_ref().map(|p| p.display().to_string()),
            h3_listen: df.h3.as_ref().and_then(|h| h.listen).map(|a| a.to_string()),
            h3_cert_path: df
                .h3
                .as_ref()
                .and_then(|h| h.cert_path.as_ref())
                .map(|p| p.display().to_string()),
            h3_key_path: df
                .h3
                .as_ref()
                .and_then(|h| h.key_path.as_ref())
                .map(|p| p.display().to_string()),
        })
    } else {
        Some(ServerListenerConfigView {
            listen: state.config.listen.map(|a| a.to_string()),
            cert_path: state.config.tls_cert_path.as_ref().map(|p| p.display().to_string()),
            key_path: state.config.tls_key_path.as_ref().map(|p| p.display().to_string()),
            h3_listen: state.config.h3_listen.map(|a| a.to_string()),
            h3_cert_path: state.config.h3_cert_path.as_ref().map(|p| p.display().to_string()),
            h3_key_path: state.config.h3_key_path.as_ref().map(|p| p.display().to_string()),
        })
    };

    let session_resumption =
        if let Some(df) = disk_file.as_ref().and_then(|f| f.session_resumption.as_ref()) {
            Some(SessionResumptionConfigView {
                enabled: df.enabled.unwrap_or(false),
                orphan_ttl_tcp_secs: df.orphan_ttl_tcp_secs,
                orphan_ttl_udp_secs: df.orphan_ttl_udp_secs,
                orphan_per_user_cap: df.orphan_per_user_cap,
                orphan_global_cap: df.orphan_global_cap,
                downlink_buffer_bytes: df.downlink_buffer_bytes,
            })
        } else {
            Some(SessionResumptionConfigView {
                enabled: state.config.session_resumption.enabled,
                orphan_ttl_tcp_secs: Some(state.config.session_resumption.orphan_ttl_tcp_secs),
                orphan_ttl_udp_secs: Some(state.config.session_resumption.orphan_ttl_udp_secs),
                orphan_per_user_cap: Some(state.config.session_resumption.orphan_per_user_cap),
                orphan_global_cap: Some(state.config.session_resumption.orphan_global_cap),
                downlink_buffer_bytes: Some(state.config.session_resumption.downlink_buffer_bytes),
            })
        };

    let outbound = if let Some(df) = disk_file.as_ref().and_then(|f| f.outbound.as_ref()) {
        Some(OutboundConfigView {
            prefer_ipv4: df.prefer_ipv4,
            ipv6_prefix: df.ipv6_prefix.clone(),
            ipv6_interface: df.ipv6_interface.clone(),
            ipv6_sticky: df.ipv6_sticky,
            ipv6_sticky_ttl_secs: df.ipv6_sticky_ttl_secs,
        })
    } else {
        Some(OutboundConfigView {
            prefer_ipv4: Some(state.config.prefer_ipv4_upstream),
            ipv6_prefix: state.config.outbound_ipv6_prefix.as_ref().map(|p| p.to_string()),
            ipv6_interface: state.config.outbound_ipv6_interface.clone(),
            ipv6_sticky: Some(state.config.outbound_ipv6_sticky),
            ipv6_sticky_ttl_secs: Some(state.config.outbound_ipv6_sticky_ttl_secs),
        })
    };

    let tuning_profile = disk_file
        .as_ref()
        .and_then(|f| f.tuning_profile)
        .map(|p| format!("{p:?}").to_lowercase());

    let endpoints = state
        .manager
        .endpoints()
        .iter()
        .map(|e| EndpointConfigView {
            path: e.path.clone(),
            protocol: if e.kind.is_vless() {
                "vless".to_string()
            } else {
                "shadowsocks".to_string()
            },
            transport: match e.kind {
                crate::config::EndpointKind::WsSs
                | crate::config::EndpointKind::WsSsTcp
                | crate::config::EndpointKind::WsSsUdp
                | crate::config::EndpointKind::WsVless => "websocket".to_string(),
                crate::config::EndpointKind::XhttpSs
                | crate::config::EndpointKind::XhttpSsTcp
                | crate::config::EndpointKind::XhttpSsUdp
                | crate::config::EndpointKind::XhttpVless => "xhttp".to_string(),
            },
            padded: e.padded,
        })
        .collect();

    ok_json(ServerConfigResponse {
        config_path,
        cluster,
        server,
        session_resumption,
        outbound,
        tuning_profile,
        endpoints,
    })
}

pub(super) async fn patch_config(
    State(state): State<ControlState>,
    Json(req): Json<ServerConfigPatch>,
) -> axum::response::Response {
    // 1. Validation
    if let Some(cluster) = &req.cluster {
        if let Some(shard) = cluster.shard_id
            && shard >= 16
        {
            return error_response(StatusCode::BAD_REQUEST, "cluster shard_id must be in 0..15");
        }
        if let Some(peers) = &cluster.peers {
            let mut seen = HashSet::new();
            for p in peers {
                if p.shard >= 16 {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("peer shard {} must be in 0..15", p.shard),
                    );
                }
                if !seen.insert(p.shard) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("duplicate shard {} in cluster peers", p.shard),
                    );
                }
                if p.addr.trim().is_empty() {
                    return error_response(StatusCode::BAD_REQUEST, "peer addr cannot be empty");
                }
            }
        }
        if let Some(psk) = &cluster.cluster_psk {
            let trimmed = psk.trim();
            if !trimmed.is_empty()
                && trimmed != "********"
                && let Err(e) = base64::engine::general_purpose::STANDARD.decode(trimmed)
            {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid base64 cluster_psk: {e}"),
                );
            }
        }
        if let Some(listen) = &cluster.mesh_listen
            && listen.trim().is_empty()
        {
            return error_response(StatusCode::BAD_REQUEST, "mesh_listen cannot be empty");
        }
    }

    if let Some(server) = &req.server {
        if let Some(listen) = &server.listen
            && !listen.trim().is_empty()
            && listen.trim().parse::<SocketAddr>().is_err()
        {
            return error_response(StatusCode::BAD_REQUEST, "invalid server.listen socket address");
        }
        if let Some(h3_listen) = &server.h3_listen
            && !h3_listen.trim().is_empty()
            && h3_listen.trim().parse::<SocketAddr>().is_err()
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid server.h3.listen socket address",
            );
        }
    }

    let Some(path) = state.manager.config_path() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "server is running without a config file; cannot persist changes",
        );
    };

    let path = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || persist_config_patch(&path, &req)).await;

    match res {
        Ok(Ok(())) => ok_json(serde_json::json!({
            "ok": true,
            "message": "Configuration saved to config.toml",
            "requires_restart": true
        })),
        Ok(Err(err)) => {
            warn!(error = %format!("{err:#}"), "failed to persist server config patch");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}"))
        },
        Err(err) => {
            warn!(error = %format!("{err:#}"), "persist task panicked");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "persist task panicked")
        },
    }
}

#[cfg(test)]
#[path = "tests/handlers.rs"]
mod tests;
