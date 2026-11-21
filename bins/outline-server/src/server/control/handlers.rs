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

use crate::config::{
    CipherKind, Config, EndpointKind, H3Alpn, OneOrManyCidr, TuningOverrides, UserEntry,
};

use super::access_keys::{AccessKeysRunnerConfig, validate_node_host};
use super::manager::{FieldPatch, UserManager, UserPatch, UserView};
use super::persist::{PersistConfigError, ServerConfigPatch, TlsCertDto, persist_config_patch};

#[derive(Clone)]
pub(super) struct ControlState {
    pub manager: Arc<UserManager>,
    pub config: Arc<Config>,
    pub token: Arc<str>,
    pub access_keys: Option<AccessKeysRunnerConfig>,
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

pub(super) fn error_response(
    status: StatusCode,
    msg: impl Into<String>,
) -> axum::response::Response {
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
    pub restart_pending: bool,
    pub cluster: Option<ClusterConfigView>,
    pub server: Option<ServerListenerConfigView>,
    pub shadowsocks: Option<ShadowsocksConfigView>,
    pub http_root: Option<HttpRootConfigView>,
    pub access_keys: Option<AccessKeysConfigView>,
    pub session_resumption: Option<SessionResumptionConfigView>,
    pub outbound: Option<OutboundConfigView>,
    pub padding: Option<PaddingConfigView>,
    pub http_fallback: Option<HttpFallbackConfigView>,
    pub sni_fallback: Option<SniFallbackConfigView>,
    pub tuning_profile: Option<String>,
    pub tuning: Option<TuningOverrides>,
    pub metrics: Option<MetricsConfigView>,
    pub control: Option<ControlReadOnlyView>,
    pub endpoints: Vec<EndpointConfigView>,
}

#[derive(Debug, Serialize)]
pub(super) struct ClusterConfigView {
    pub enabled: bool,
    pub shard_id: Option<u8>,
    pub cluster_psk: Option<String>,
    pub has_cluster_psk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk_fingerprint: Option<String>,
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
    pub max_connections_per_ip: Option<usize>,
    pub certs: Vec<TlsCertDto>,
    pub h3_listen: Option<String>,
    pub h3_cert_path: Option<String>,
    pub h3_key_path: Option<String>,
    pub h3_certs: Option<Vec<TlsCertDto>>,
    pub h3_alpn: Option<Vec<String>>,
    pub h3_initial_mtu: Option<u16>,
    pub h3_mtu_first_probe: Option<u16>,
    pub h3_udp_datagrams: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(super) struct ShadowsocksConfigView {
    pub method: Option<CipherKind>,
}

#[derive(Debug, Serialize)]
pub(super) struct HttpRootConfigView {
    pub auth: Option<bool>,
    pub realm: Option<String>,
}

#[derive(Serialize)]
pub(super) struct AccessKeysConfigView {
    pub public_host: Option<String>,
    pub public_scheme: Option<String>,
    pub url_base: Option<String>,
    pub file_extension: Option<String>,
    pub write_dir: Option<String>,
    pub nodes: Option<Vec<String>>,
}

impl std::fmt::Debug for AccessKeysConfigView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKeysConfigView")
            .field("public_host", &self.public_host)
            .field("public_scheme", &self.public_scheme)
            .field("url_base", &self.url_base)
            .field("file_extension", &self.file_extension)
            .field("write_dir", &self.write_dir.as_ref().map(|_| "<redacted>"))
            .field("nodes", &self.nodes)
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub(super) struct MetricsConfigView {
    pub listen: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ControlReadOnlyView {
    pub listen: Option<String>,
    pub access_keys_enabled: bool,
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
    pub ipv6_prefix_interface: Option<String>,
    pub ipv6_refresh_secs: Option<u64>,
    pub ipv6_sticky: Option<bool>,
    pub ipv6_sticky_ttl_secs: Option<u64>,
    pub block_private_ips: Option<bool>,
    pub allowed_subnets: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(super) struct PaddingConfigView {
    pub min_bytes: Option<u16>,
    pub max_bytes: Option<u16>,
    pub cover: Option<bool>,
    pub cover_jitter_min_ms: Option<u64>,
    pub cover_jitter_max_ms: Option<u64>,
    pub throttle_detect_enabled: Option<bool>,
    pub throttle_ratio_percent: Option<u32>,
    pub throttle_window_secs: Option<u64>,
    pub throttle_sustain_windows: Option<u32>,
    pub throttle_min_bytes_per_sec: Option<u64>,
    pub throttle_signal_cooldown_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct HttpFallbackConfigView {
    pub backend: Option<String>,
    pub request_timeout_secs: Option<u64>,
    pub add_x_forwarded_for: Option<bool>,
    pub add_x_forwarded_proto: Option<bool>,
    pub add_x_forwarded_host: Option<bool>,
    pub proxy_protocol: Option<String>,
    pub backend_proto: Option<String>,
    pub apply_to_h1: Option<bool>,
    pub apply_to_h3: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(super) struct SniFallbackConfigView {
    pub match_sni: Vec<String>,
    pub allow_no_sni: bool,
    pub max_client_hello_bytes: Option<usize>,
    pub backends: Vec<SniBackendConfigView>,
}

#[derive(Debug, Serialize)]
pub(super) struct SniBackendConfigView {
    pub backend: String,
    pub proxy_protocol: Option<String>,
    pub match_sni: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct EndpointConfigView {
    pub path: String,
    pub kind: EndpointKind,
    pub protocol: String,
    pub transport: String,
    pub padded: bool,
}

fn psk_fingerprint_from_b64(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .unwrap_or_else(|_| trimmed.as_bytes().to_vec());
    if decoded.is_empty() {
        return None;
    }
    Some(super::blake3_fingerprint(b"outline-cluster-psk-fp\0", &[&decoded]))
}

fn cert_section_to_dto(entry: &crate::config::TlsCertSection) -> TlsCertDto {
    TlsCertDto {
        cert_path: entry.cert_path.display().to_string(),
        key_path: entry.key_path.display().to_string(),
        sni: (!entry.sni.as_ref().is_none_or(Vec::is_empty))
            .then(|| entry.sni.clone())
            .flatten(),
    }
}

fn cert_entry_to_dto(entry: &crate::config::TlsCertEntry) -> TlsCertDto {
    TlsCertDto {
        cert_path: entry.cert_path.display().to_string(),
        key_path: entry.key_path.display().to_string(),
        sni: (!entry.sni.is_empty()).then(|| entry.sni.clone()),
    }
}

fn endpoint_to_view(path: String, kind: EndpointKind, padded: bool) -> EndpointConfigView {
    EndpointConfigView {
        path,
        kind,
        protocol: if kind.is_vless() {
            "vless".to_string()
        } else {
            "shadowsocks".to_string()
        },
        transport: match kind {
            EndpointKind::WsSs
            | EndpointKind::WsSsTcp
            | EndpointKind::WsSsUdp
            | EndpointKind::WsVless => "websocket".to_string(),
            EndpointKind::XhttpSs
            | EndpointKind::XhttpSsTcp
            | EndpointKind::XhttpSsUdp
            | EndpointKind::XhttpVless => "xhttp".to_string(),
        },
        padded,
    }
}

pub(super) async fn get_config(State(state): State<ControlState>) -> axum::response::Response {
    let config_path = state.manager.config_path().map(|p| p.display().to_string());

    // Read current on-disk FileConfig and resolve runtime Config for `restart_pending`.
    let (disk_file, disk_resolved): (Option<crate::config::FileConfig>, Option<Config>) =
        if let Some(path) = state.manager.config_path() {
            let path = path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    return (None, None);
                };
                let file: Option<crate::config::FileConfig> = toml::from_str(&text).ok();
                let resolved = crate::config::parse_and_validate(&text).ok();
                (file, resolved)
            })
            .await
            .unwrap_or((None, None))
        } else {
            (None, None)
        };

    let restart_pending = disk_resolved
        .as_ref()
        .is_some_and(|cfg| state.config.runtime_settings_differ(cfg));

    let cluster = if let Some(df) = disk_file.as_ref().and_then(|f| f.cluster.as_ref()) {
        Some(ClusterConfigView {
            enabled: df.enabled.unwrap_or(false),
            shard_id: df.shard_id,
            has_cluster_psk: df.cluster_psk.as_ref().is_some_and(|k| !k.is_empty()),
            cluster_psk: df.cluster_psk.as_ref().map(|_| "********".to_string()),
            psk_fingerprint: df.cluster_psk.as_deref().and_then(psk_fingerprint_from_b64),
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
            psk_fingerprint: Some(super::blake3_fingerprint(
                b"outline-cluster-psk-fp\0",
                &[c.psk.as_bytes()],
            )),
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
            psk_fingerprint: None,
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
            max_connections_per_ip: df.max_connections_per_ip,
            certs: df
                .certs
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(cert_section_to_dto)
                .collect(),
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
            h3_certs: df
                .h3
                .as_ref()
                .and_then(|h| h.certs.as_ref())
                .map(|list| list.iter().map(cert_section_to_dto).collect()),
            h3_alpn: df.h3.as_ref().and_then(|h| h.alpn.clone()),
            h3_initial_mtu: df.h3.as_ref().and_then(|h| h.initial_mtu),
            h3_mtu_first_probe: df.h3.as_ref().and_then(|h| h.mtu_first_probe),
            h3_udp_datagrams: df.h3.as_ref().and_then(|h| h.udp_datagrams),
        })
    } else {
        Some(ServerListenerConfigView {
            listen: state.config.listen.map(|a| a.to_string()),
            cert_path: state.config.tls_cert_path.as_ref().map(|p| p.display().to_string()),
            key_path: state.config.tls_key_path.as_ref().map(|p| p.display().to_string()),
            max_connections_per_ip: state.config.max_connections_per_ip,
            certs: state.config.tls_certs.iter().map(cert_entry_to_dto).collect(),
            h3_listen: state.config.h3_listen.map(|a| a.to_string()),
            h3_cert_path: state.config.h3_cert_path.as_ref().map(|p| p.display().to_string()),
            h3_key_path: state.config.h3_key_path.as_ref().map(|p| p.display().to_string()),
            h3_certs: Some(state.config.h3_certs.iter().map(cert_entry_to_dto).collect()),
            h3_alpn: Some(
                state
                    .config
                    .h3_alpn
                    .iter()
                    .map(|a| match a {
                        H3Alpn::H3 => "h3".to_string(),
                    })
                    .collect(),
            ),
            h3_initial_mtu: state.config.h3_initial_mtu,
            h3_mtu_first_probe: state.config.h3_mtu_first_probe,
            h3_udp_datagrams: Some(state.config.h3_udp_datagrams),
        })
    };

    let shadowsocks = if let Some(f) = disk_file.as_ref() {
        Some(ShadowsocksConfigView {
            method: f.shadowsocks.as_ref().and_then(|s| s.method),
        })
    } else {
        Some(ShadowsocksConfigView { method: Some(state.config.method) })
    };

    let http_root = if let Some(f) = disk_file.as_ref() {
        Some(HttpRootConfigView {
            auth: f.http_root.as_ref().and_then(|h| h.auth),
            realm: f.http_root.as_ref().and_then(|h| h.realm.clone()),
        })
    } else {
        Some(HttpRootConfigView {
            auth: Some(state.config.http_root_auth),
            realm: Some(state.config.http_root_realm.clone()),
        })
    };

    let access_keys =
        disk_file
            .as_ref()
            .and_then(|f| f.access_keys.as_ref())
            .map(|ak| AccessKeysConfigView {
                public_host: ak.public_host.clone(),
                public_scheme: ak.public_scheme.clone(),
                url_base: ak.url_base.clone(),
                file_extension: ak.file_extension.clone(),
                write_dir: ak.write_dir.as_ref().map(|p| p.display().to_string()),
                nodes: ak.nodes.clone(),
            });

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
            ipv6_prefix_interface: df.ipv6_prefix_interface.clone(),
            ipv6_refresh_secs: df.ipv6_refresh_secs,
            ipv6_sticky: df.ipv6_sticky,
            ipv6_sticky_ttl_secs: df.ipv6_sticky_ttl_secs,
            block_private_ips: df.block_private_ips,
            allowed_subnets: df.allowed_subnets.clone(),
        })
    } else {
        Some(OutboundConfigView {
            prefer_ipv4: Some(state.config.prefer_ipv4_upstream),
            ipv6_prefix: state.config.outbound_ipv6_prefix.as_ref().map(|p| p.to_string()),
            ipv6_interface: state.config.outbound_ipv6_interface.clone(),
            ipv6_prefix_interface: state.config.outbound_ipv6_prefix_interface.clone(),
            ipv6_refresh_secs: Some(state.config.outbound_ipv6_refresh_secs),
            ipv6_sticky: Some(state.config.outbound_ipv6_sticky),
            ipv6_sticky_ttl_secs: Some(state.config.outbound_ipv6_sticky_ttl_secs),
            block_private_ips: Some(state.config.outbound_block_private_ips),
            allowed_subnets: Some(state.config.outbound_allowed_subnets.clone()),
        })
    };

    let padding = if let Some(df) = disk_file.as_ref().and_then(|f| f.padding.as_ref()) {
        Some(PaddingConfigView {
            min_bytes: df.min_bytes,
            max_bytes: df.max_bytes,
            cover: df.cover,
            cover_jitter_min_ms: df.cover_jitter_min_ms,
            cover_jitter_max_ms: df.cover_jitter_max_ms,
            throttle_detect_enabled: df.throttle_detect_enabled,
            throttle_ratio_percent: df.throttle_ratio_percent,
            throttle_window_secs: df.throttle_window_secs,
            throttle_sustain_windows: df.throttle_sustain_windows,
            throttle_min_bytes_per_sec: df.throttle_min_bytes_per_sec,
            throttle_signal_cooldown_secs: df.throttle_signal_cooldown_secs,
        })
    } else {
        Some(PaddingConfigView {
            min_bytes: Some(state.config.padding.min_bytes),
            max_bytes: Some(state.config.padding.max_bytes),
            cover: Some(state.config.padding.cover),
            cover_jitter_min_ms: Some(state.config.padding.cover_jitter_min_ms),
            cover_jitter_max_ms: Some(state.config.padding.cover_jitter_max_ms),
            throttle_detect_enabled: Some(state.config.padding.throttle_detect_enabled),
            throttle_ratio_percent: Some(state.config.padding.throttle_ratio_percent),
            throttle_window_secs: Some(state.config.padding.throttle_window_secs),
            throttle_sustain_windows: Some(state.config.padding.throttle_sustain_windows),
            throttle_min_bytes_per_sec: Some(state.config.padding.throttle_min_bytes_per_sec),
            throttle_signal_cooldown_secs: Some(state.config.padding.throttle_signal_cooldown_secs),
        })
    };

    let http_fallback = if let Some(df) = disk_file.as_ref().and_then(|f| f.http_fallback.as_ref())
    {
        Some(HttpFallbackConfigView {
            backend: df.backend.clone(),
            request_timeout_secs: df.request_timeout_secs,
            add_x_forwarded_for: df.add_x_forwarded_for,
            add_x_forwarded_proto: df.add_x_forwarded_proto,
            add_x_forwarded_host: df.add_x_forwarded_host,
            proxy_protocol: df.proxy_protocol.clone(),
            backend_proto: df.backend_proto.clone(),
            apply_to_h1: df.apply_to_h1,
            apply_to_h3: df.apply_to_h3,
        })
    } else {
        state.config.http_fallback.as_ref().map(|hf| HttpFallbackConfigView {
            backend: Some(hf.backend_authority.clone()),
            request_timeout_secs: Some(hf.request_timeout_secs),
            add_x_forwarded_for: Some(hf.add_x_forwarded_for),
            add_x_forwarded_proto: Some(hf.add_x_forwarded_proto),
            add_x_forwarded_host: Some(hf.add_x_forwarded_host),
            proxy_protocol: hf.proxy_protocol.as_ref().map(|p| match p {
                crate::config::ProxyProtocolVersion::V1 => "v1".to_string(),
                crate::config::ProxyProtocolVersion::V2 => "v2".to_string(),
            }),
            backend_proto: Some(match hf.backend_proto {
                crate::config::BackendProto::H1 => "h1".to_string(),
                crate::config::BackendProto::H2 => "h2".to_string(),
            }),
            apply_to_h1: Some(hf.apply_to_h1),
            apply_to_h3: Some(hf.apply_to_h3),
        })
    };

    let sni_fallback = if let Some(df) = disk_file.as_ref().and_then(|f| f.sni_fallback.as_ref()) {
        let backends = if let Some(bes) = &df.backends {
            bes.iter()
                .map(|b| SniBackendConfigView {
                    backend: b.backend.clone(),
                    proxy_protocol: b.proxy_protocol.clone(),
                    match_sni: b.match_sni.clone().unwrap_or_default(),
                })
                .collect()
        } else if let Some(b) = &df.backend {
            vec![SniBackendConfigView {
                backend: b.clone(),
                proxy_protocol: df.proxy_protocol.clone(),
                match_sni: Vec::new(),
            }]
        } else {
            Vec::new()
        };

        Some(SniFallbackConfigView {
            match_sni: df.match_sni.clone().unwrap_or_default(),
            allow_no_sni: df.allow_no_sni.unwrap_or(false),
            max_client_hello_bytes: df.max_client_hello_bytes,
            backends,
        })
    } else {
        state.config.sni_fallback.as_ref().map(|sf| {
            let match_sni = sf
                .match_sni
                .iter()
                .map(|m| match m {
                    crate::config::SniMatcher::Exact(s) => s.clone(),
                    crate::config::SniMatcher::Wildcard { suffix } => format!("*{suffix}"),
                })
                .collect();

            let backends = sf
                .backends
                .iter()
                .map(|b| {
                    let match_sni = b
                        .match_sni
                        .iter()
                        .map(|m| match m {
                            crate::config::SniMatcher::Exact(s) => s.clone(),
                            crate::config::SniMatcher::Wildcard { suffix } => format!("*{suffix}"),
                        })
                        .collect();

                    SniBackendConfigView {
                        backend: b.authority.clone(),
                        proxy_protocol: b.proxy_protocol.map(|p| match p {
                            crate::config::ProxyProtocolVersion::V1 => "v1".to_string(),
                            crate::config::ProxyProtocolVersion::V2 => "v2".to_string(),
                        }),
                        match_sni,
                    }
                })
                .collect();

            SniFallbackConfigView {
                match_sni,
                allow_no_sni: sf.allow_no_sni,
                max_client_hello_bytes: Some(sf.max_client_hello_bytes),
                backends,
            }
        })
    };

    let tuning_profile = disk_file
        .as_ref()
        .and_then(|f| f.tuning_profile)
        .map(|p| format!("{p:?}").to_lowercase())
        .or_else(|| Some("large".to_string()));

    let tuning = disk_file.as_ref().and_then(|f| f.tuning);

    let metrics = if let Some(df) = disk_file.as_ref().and_then(|f| f.metrics.as_ref()) {
        Some(MetricsConfigView {
            listen: df.listen.map(|a| a.to_string()),
            path: df.path.clone().or_else(|| Some(state.config.metrics_path.clone())),
        })
    } else {
        Some(MetricsConfigView {
            listen: state.config.metrics_listen.map(|a| a.to_string()),
            path: Some(state.config.metrics_path.clone()),
        })
    };

    let control = Some(ControlReadOnlyView {
        listen: state.config.control.as_ref().map(|c| c.listen.to_string()),
        access_keys_enabled: state.access_keys.is_some(),
    });

    let endpoints = if let Some(eps) = disk_file.as_ref().and_then(|f| f.endpoints.as_ref()) {
        eps.iter()
            .map(|e| endpoint_to_view(e.path.clone(), e.kind, e.padded))
            .collect()
    } else {
        state
            .manager
            .endpoints()
            .iter()
            .map(|e| endpoint_to_view(e.path.clone(), e.kind, e.padded))
            .collect()
    };

    ok_json(ServerConfigResponse {
        config_path,
        restart_pending,
        cluster,
        server,
        shadowsocks,
        http_root,
        access_keys,
        session_resumption,
        outbound,
        padding,
        http_fallback,
        sni_fallback,
        tuning_profile,
        tuning,
        metrics,
        control,
        endpoints,
    })
}

fn validate_cert_list(certs: &[TlsCertDto], label: &str) -> Result<(), String> {
    for (i, cert) in certs.iter().enumerate() {
        if cert.cert_path.trim().is_empty() {
            return Err(format!("{label}[{i}].cert_path cannot be empty"));
        }
        if cert.key_path.trim().is_empty() {
            return Err(format!("{label}[{i}].key_path cannot be empty"));
        }
        if let Some(snis) = &cert.sni {
            for s in snis {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(format!("{label}[{i}].sni entries must not be empty"));
                }
                if trimmed.contains('*') {
                    return Err(format!("{label}[{i}].sni entry {s:?} must not contain '*'"));
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn patch_config(
    State(state): State<ControlState>,
    Json(req): Json<ServerConfigPatch>,
) -> axum::response::Response {
    // 1. Validation
    if let FieldPatch::Set(Some(profile)) = &req.tuning_profile {
        let trimmed = profile.trim().to_ascii_lowercase();
        if !trimmed.is_empty() && !matches!(trimmed.as_str(), "small" | "medium" | "large") {
            return error_response(
                StatusCode::BAD_REQUEST,
                "tuning_profile must be one of: small, medium, large",
            );
        }
    }

    if let FieldPatch::Set(Some(pad)) = &req.padding {
        if let (FieldPatch::Set(Some(min)), FieldPatch::Set(Some(max))) =
            (&pad.min_bytes, &pad.max_bytes)
            && *min > *max
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "padding min_bytes cannot exceed max_bytes",
            );
        }
        if let (FieldPatch::Set(Some(min_jitter)), FieldPatch::Set(Some(max_jitter))) =
            (&pad.cover_jitter_min_ms, &pad.cover_jitter_max_ms)
            && *min_jitter > *max_jitter
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "padding cover_jitter_min_ms cannot exceed cover_jitter_max_ms",
            );
        }
    }

    if let FieldPatch::Set(Some(hf)) = &req.http_fallback {
        if let FieldPatch::Set(Some(proto)) = &hf.proxy_protocol {
            let p = proto.trim().to_ascii_lowercase();
            if !p.is_empty() && !matches!(p.as_str(), "v1" | "v2") {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "http_fallback proxy_protocol must be 'v1' or 'v2'",
                );
            }
        }
        if let FieldPatch::Set(Some(proto)) = &hf.backend_proto {
            let p = proto.trim().to_ascii_lowercase();
            if !p.is_empty() && !matches!(p.as_str(), "h1" | "h2") {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "http_fallback backend_proto must be 'h1' or 'h2'",
                );
            }
        }
    }

    if let FieldPatch::Set(Some(sf)) = &req.sni_fallback {
        if let FieldPatch::Set(Some(match_sni)) = &sf.match_sni {
            for entry in match_sni {
                if entry.trim().is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "sni_fallback match_sni entries must not be empty",
                    );
                }
                let trimmed = entry.trim().to_ascii_lowercase();
                if trimmed.contains('*')
                    && (!trimmed.starts_with("*.")
                        || trimmed.len() <= 2
                        || trimmed[2..].contains('*'))
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("malformed sni_fallback wildcard in match_sni: {entry:?}"),
                    );
                }
            }
        }
        if let FieldPatch::Set(Some(bytes)) = sf.max_client_hello_bytes
            && bytes < 256
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "sni_fallback max_client_hello_bytes must be >= 256",
            );
        }
        if let FieldPatch::Set(Some(backends)) = &sf.backends {
            let last_idx = if backends.is_empty() { 0 } else { backends.len() - 1 };
            for (i, b) in backends.iter().enumerate() {
                if b.backend.trim().is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("sni_fallback.backends[{i}].backend must not be empty"),
                    );
                }
                if let Some(pp) = &b.proxy_protocol {
                    let p = pp.trim().to_ascii_lowercase();
                    if !p.is_empty() && !matches!(p.as_str(), "v1" | "v2") {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "sni_fallback.backends[{i}].proxy_protocol must be 'v1' or 'v2'"
                            ),
                        );
                    }
                }
                if let Some(match_sni) = &b.match_sni {
                    for entry in match_sni {
                        if entry.trim().is_empty() {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "sni_fallback.backends[{i}].match_sni entries must not be empty"
                                ),
                            );
                        }
                    }
                    if match_sni.is_empty() && i != last_idx {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!(
                                "sni_fallback.backends[{i}] is a catch-all but not the last entry"
                            ),
                        );
                    }
                } else if i != last_idx {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("sni_fallback.backends[{i}] is a catch-all but not the last entry"),
                    );
                }
            }
        }
    }

    if let FieldPatch::Set(Some(cluster)) = &req.cluster {
        if let FieldPatch::Set(Some(shard)) = cluster.shard_id
            && shard >= 16
        {
            return error_response(StatusCode::BAD_REQUEST, "cluster shard_id must be in 0..15");
        }
        if let FieldPatch::Set(Some(peers)) = &cluster.peers {
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
        if let FieldPatch::Set(Some(psk)) = &cluster.cluster_psk {
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
        if let FieldPatch::Set(Some(listen)) = &cluster.mesh_listen
            && listen.trim().is_empty()
        {
            return error_response(StatusCode::BAD_REQUEST, "mesh_listen cannot be empty");
        }
    }

    if let FieldPatch::Set(Some(server)) = &req.server {
        if let FieldPatch::Set(Some(listen)) = &server.listen
            && !listen.trim().is_empty()
            && listen.trim().parse::<SocketAddr>().is_err()
        {
            return error_response(StatusCode::BAD_REQUEST, "invalid server.listen socket address");
        }
        if let FieldPatch::Set(Some(h3_listen)) = &server.h3_listen
            && !h3_listen.trim().is_empty()
            && h3_listen.trim().parse::<SocketAddr>().is_err()
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid server.h3.listen socket address",
            );
        }
        if let FieldPatch::Set(Some(certs)) = &server.certs
            && let Err(msg) = validate_cert_list(certs, "server.certs")
        {
            return error_response(StatusCode::BAD_REQUEST, msg);
        }
        if let FieldPatch::Set(Some(h3_certs)) = &server.h3_certs
            && let Err(msg) = validate_cert_list(h3_certs, "server.h3.certs")
        {
            return error_response(StatusCode::BAD_REQUEST, msg);
        }
        if let FieldPatch::Set(Some(alpn)) = &server.h3_alpn {
            if alpn.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "server.h3.alpn must list at least one protocol",
                );
            }
            let mut seen = HashSet::new();
            for entry in alpn {
                let trimmed = entry.trim();
                if trimmed != "h3" {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "unsupported server.h3.alpn entry {entry:?}; only 'h3' is supported"
                        ),
                    );
                }
                if !seen.insert(trimmed.to_owned()) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("duplicate server.h3.alpn entry {entry:?}"),
                    );
                }
            }
        }
        if let FieldPatch::Set(Some(mtu)) = server.h3_initial_mtu
            && !(1200..=1452).contains(&mtu)
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "server.h3.initial_mtu must be between 1200 and 1452 bytes",
            );
        }
        if let FieldPatch::Set(Some(probe)) = server.h3_mtu_first_probe
            && !(1200..=1452).contains(&probe)
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "server.h3.mtu_first_probe must be between 1200 and 1452 bytes",
            );
        }
    }

    if let FieldPatch::Set(Some(ak)) = &req.access_keys {
        if let FieldPatch::Set(Some(scheme)) = &ak.public_scheme {
            let trimmed = scheme.trim();
            if !trimmed.is_empty() && !matches!(trimmed, "ws" | "wss") {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "access_keys.public_scheme must be 'ws' or 'wss'",
                );
            }
        }
        if let FieldPatch::Set(Some(nodes)) = &ak.nodes {
            for node in nodes {
                if let Err(msg) = validate_node_host(node) {
                    return error_response(StatusCode::BAD_REQUEST, msg);
                }
            }
        }
    }

    if let FieldPatch::Set(Some(endpoints)) = &req.endpoints {
        let all_with_kind = endpoints.iter().all(|ep| ep.kind.is_some());
        let all_without_kind = endpoints.iter().all(|ep| ep.kind.is_none());
        if !endpoints.is_empty() && !all_with_kind && !all_without_kind {
            return error_response(
                StatusCode::BAD_REQUEST,
                "endpoints entries must either all include kind or all omit kind",
            );
        }
        let mut seen_paths = HashSet::new();
        for (i, ep) in endpoints.iter().enumerate() {
            let trimmed = ep.path.trim();
            if trimmed.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("endpoints[{i}].path cannot be empty"),
                );
            }
            if all_with_kind {
                if !trimmed.starts_with('/') {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("endpoints[{i}].path {trimmed:?} must start with '/'"),
                    );
                }
                if !seen_paths.insert(trimmed.to_owned()) {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("duplicate endpoint path {trimmed:?}"),
                    );
                }
            }
        }
    }

    let Some(path) = state.manager.config_path() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "server is running without a config file; cannot persist changes",
        );
    };

    let touches_runtime = req.touches_runtime_settings();
    let path = path.to_path_buf();
    let running_cfg = state.config.clone();
    let _file_guard = state.manager.config_file_lock().lock().await;
    let res = tokio::task::spawn_blocking(move || {
        let changed = persist_config_patch(&path, &req)?;
        let requires_restart = if !touches_runtime || !changed {
            false
        } else {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| crate::config::parse_and_validate(&text).ok())
                .is_some_and(|disk_cfg| running_cfg.runtime_settings_differ(&disk_cfg))
        };
        Ok::<bool, PersistConfigError>(requires_restart)
    })
    .await;

    match res {
        Ok(Ok(requires_restart)) => ok_json(serde_json::json!({
            "ok": true,
            "message": "Configuration saved to config.toml",
            "requires_restart": requires_restart
        })),
        Ok(Err(PersistConfigError::Validation(err))) => {
            let msg = format!("{err:#}");
            warn!(error = %msg, "server config patch failed validation");
            error_response(StatusCode::BAD_REQUEST, msg)
        },
        Ok(Err(PersistConfigError::Io(err))) => {
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
