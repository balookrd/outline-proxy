//! Runtime user manager: canonical list + atomic snapshot publishing.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    config::{
        CipherKind, Config, H3Alpn, UserEntry, access_key::build_access_key_artifacts_for_user,
    },
    crypto::UserKey,
    metrics::Transport,
    protocol::vless::VlessUser,
};

use super::super::{
    setup::{
        UserRoute, VlessUserRoute, build_transport_route_map, build_vless_transport_route_map,
    },
    state::{
        AuthUsersSnapshot, RouteRegistry, RoutesSnapshot, TransportRoute, UserKeySlice,
        VlessTransportRoute,
    },
};

use super::persist::persist_users;

/// Owns the authoritative user list and publishes derived state via
/// `ArcSwap`. Every mutation takes the single mutex, rebuilds the full route
/// maps + auth slice, then publishes them atomically and re-serializes the
/// config file. Readers on the data plane do a cheap `ArcSwap::load` and
/// observe either the pre- or post-mutation state — never a mix.
pub(in crate::server) struct UserManager {
    inner: Mutex<Inner>,
    routes: RoutesSnapshot,
    auth_users: AuthUsersSnapshot,
    default_method: CipherKind,
    default_ws_path_tcp: String,
    default_ws_path_udp: String,
    default_ws_path_vless: Option<String>,
    default_xhttp_path_vless: Option<String>,
    default_xhttp_path_ss: Option<String>,
    default_xhttp_path_ss_udp: Option<String>,
    access_key_config: crate::config::AccessKeyConfig,
    access_key_base_config: Config,
    // Paths that exist in the startup Axum/H3 routers. Mutations that
    // introduce a path outside this set are rejected — the routers cannot
    // dispatch requests to unknown paths until the next restart.
    allowed_tcp_paths: BTreeSet<String>,
    allowed_udp_paths: BTreeSet<String>,
    allowed_vless_paths: BTreeSet<String>,
    allowed_xhttp_paths: BTreeSet<String>,
    allowed_xhttp_ss_paths: BTreeSet<String>,
    allowed_xhttp_ss_udp_paths: BTreeSet<String>,
    /// Whether raw VLESS-over-QUIC is enabled (`"vless"` in `[server.h3].alpn`).
    /// When true a `vless_id` user needs no ws/xhttp path — the raw-QUIC ALPN is
    /// itself a transport. Mirrors the startup check in `config::validation` so
    /// the control API accepts exactly the users a fresh start would.
    has_raw_quic_vless: bool,
    config_path: Option<PathBuf>,
}

struct Inner {
    users: Vec<UserEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct UserView {
    pub id: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<CipherKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path_tcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path_udp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path_vless: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_vless: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_ss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_ss_udp: Option<String>,
    pub has_password: bool,
    pub has_vless_id: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct AccessUrlsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ss_config_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ss_access_key_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vless_url: Option<String>,
}

#[derive(Debug, Error)]
pub(in crate::server) enum AccessUrlError {
    #[error("user {0:?} not found")]
    NotFound(String),
    #[error(transparent)]
    Build(anyhow::Error),
}

impl From<&UserEntry> for UserView {
    fn from(entry: &UserEntry) -> Self {
        Self {
            id: entry.id.clone(),
            enabled: entry.is_enabled(),
            method: entry.method,
            fwmark: entry.fwmark,
            ws_path_tcp: entry.ws_path_tcp.clone(),
            ws_path_udp: entry.ws_path_udp.clone(),
            ws_path_vless: entry.ws_path_vless.clone(),
            xhttp_path_vless: entry.xhttp_path_vless.clone(),
            xhttp_path_ss: entry.xhttp_path_ss.clone(),
            xhttp_path_ss_udp: entry.xhttp_path_ss_udp.clone(),
            has_password: entry.password.is_some(),
            has_vless_id: entry.vless_id.is_some(),
        }
    }
}

/// Startup-registered route paths the control plane may attach new users
/// to. The live axum/h3 routers cannot grow new paths until the next
/// process restart, so a hot-reload mutation that names an unregistered
/// path is rejected. Bundled into one argument to keep `UserManager::new`
/// within the project's argument-count budget (cf. `H3ServeCtx`).
pub(in crate::server) struct AllowedRoutePaths {
    pub(in crate::server) tcp: BTreeSet<String>,
    pub(in crate::server) udp: BTreeSet<String>,
    pub(in crate::server) vless: BTreeSet<String>,
    pub(in crate::server) xhttp_vless: BTreeSet<String>,
    pub(in crate::server) xhttp_ss: BTreeSet<String>,
    pub(in crate::server) xhttp_ss_udp: BTreeSet<String>,
}

impl UserManager {
    pub(in crate::server) fn new(
        config: &Config,
        routes: RoutesSnapshot,
        auth_users: AuthUsersSnapshot,
        allowed: AllowedRoutePaths,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner { users: config.users.clone() }),
            routes,
            auth_users,
            default_method: config.method,
            default_ws_path_tcp: config.ws_path_tcp.clone(),
            default_ws_path_udp: config.ws_path_udp.clone(),
            default_ws_path_vless: config.ws_path_vless.clone(),
            default_xhttp_path_vless: config.xhttp_path_vless.clone(),
            default_xhttp_path_ss: config.xhttp_path_ss.clone(),
            default_xhttp_path_ss_udp: config.xhttp_path_ss_udp.clone(),
            access_key_config: config.access_key.clone(),
            access_key_base_config: config.clone(),
            allowed_tcp_paths: allowed.tcp,
            allowed_udp_paths: allowed.udp,
            allowed_vless_paths: allowed.vless,
            allowed_xhttp_paths: allowed.xhttp_vless,
            allowed_xhttp_ss_paths: allowed.xhttp_ss,
            allowed_xhttp_ss_udp_paths: allowed.xhttp_ss_udp,
            has_raw_quic_vless: config.h3_alpn.contains(&H3Alpn::Vless),
            config_path: config.config_path.clone(),
        }
    }

    pub(super) async fn list(&self) -> Vec<UserView> {
        self.inner.lock().await.users.iter().map(UserView::from).collect()
    }

    pub(super) async fn get(&self, id: &str) -> Option<UserView> {
        self.inner
            .lock()
            .await
            .users
            .iter()
            .find(|u| u.id == id)
            .map(UserView::from)
    }

    pub(super) async fn access_urls(&self, id: &str) -> Result<AccessUrlsView, AccessUrlError> {
        let user = self
            .inner
            .lock()
            .await
            .users
            .iter()
            .find(|u| u.id == id)
            .cloned()
            .ok_or_else(|| AccessUrlError::NotFound(id.to_string()))?;

        let artifacts = build_access_key_artifacts_for_user(
            &self.access_key_base_config,
            &self.access_key_config,
            &user,
        )
        .map_err(AccessUrlError::Build)?;
        let mut view = AccessUrlsView {
            ss_config_url: None,
            ss_access_key_url: None,
            vless_url: None,
        };

        for artifact in artifacts {
            if artifact.yaml.starts_with("vless://") {
                // `build_access_key_artifacts_for_user` may return
                // multiple VLESS URIs per user (WS, plus XHTTP
                // packet-up + stream-one). The view keeps a single
                // representative; first wins so the carrier order
                // (WS → XHTTP packet-up → XHTTP stream-one) decides
                // which one surfaces here.
                if view.vless_url.is_none() {
                    view.vless_url = artifact.access_key_url;
                }
            } else {
                view.ss_config_url = artifact.config_url;
                view.ss_access_key_url = artifact.access_key_url;
            }
        }

        Ok(view)
    }

    pub(super) async fn create(&self, entry: UserEntry) -> Result<UserView> {
        self.validate_new(&entry)?;
        let mut guard = self.inner.lock().await;
        if guard.users.iter().any(|u| u.id == entry.id) {
            bail!("user id {:?} already exists", entry.id);
        }
        guard.users.push(entry);
        self.publish_and_persist(&guard.users).await?;
        Ok(UserView::from(guard.users.last().expect("just pushed")))
    }

    pub(super) async fn update(&self, id: &str, patch: UserPatch) -> Result<UserView> {
        let mut guard = self.inner.lock().await;
        let index = guard
            .users
            .iter()
            .position(|u| u.id == id)
            .ok_or_else(|| anyhow!("user {id:?} not found"))?;

        let mut updated = guard.users[index].clone();
        patch.apply_to(&mut updated);
        self.validate_new(&updated)?;
        guard.users[index] = updated;
        self.publish_and_persist(&guard.users).await?;
        Ok(UserView::from(&guard.users[index]))
    }

    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let before = guard.users.len();
        guard.users.retain(|u| u.id != id);
        if guard.users.len() == before {
            bail!("user {id:?} not found");
        }
        self.publish_and_persist(&guard.users).await
    }

    pub(super) async fn set_enabled(&self, id: &str, enabled: bool) -> Result<UserView> {
        let mut guard = self.inner.lock().await;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or_else(|| anyhow!("user {id:?} not found"))?;
        user.enabled = Some(enabled);
        let view = UserView::from(&*user);
        self.publish_and_persist(&guard.users).await?;
        Ok(view)
    }

    fn validate_new(&self, entry: &UserEntry) -> Result<()> {
        if entry.id.is_empty() {
            bail!("id must not be empty");
        }
        if entry.password.is_none() && entry.vless_id.is_none() {
            bail!("user must have either password or vless_id");
        }
        if let Some(path) = entry.ws_path_tcp.as_deref() {
            if !path.starts_with('/') {
                bail!("ws_path_tcp must start with '/'");
            }
            if !self.allowed_tcp_paths.contains(path) {
                bail!(
                    "ws_path_tcp {path:?} was not registered at startup; restart the \
                     server after adding it to [[users]] in the config file"
                );
            }
        } else {
            let default = self.default_ws_path_tcp.as_str();
            if !self.allowed_tcp_paths.contains(default) {
                bail!(
                    "default ws_path_tcp {default:?} is not registered; this user needs \
                     an explicit ws_path_tcp that matches an existing startup path"
                );
            }
        }
        if let Some(path) = entry.ws_path_udp.as_deref() {
            if !path.starts_with('/') {
                bail!("ws_path_udp must start with '/'");
            }
            if !self.allowed_udp_paths.contains(path) {
                bail!(
                    "ws_path_udp {path:?} was not registered at startup; restart the \
                     server after adding it to [[users]] in the config file"
                );
            }
        } else {
            let default = self.default_ws_path_udp.as_str();
            if !self.allowed_udp_paths.contains(default) {
                bail!(
                    "default ws_path_udp {default:?} is not registered; this user needs \
                     an explicit ws_path_udp that matches an existing startup path"
                );
            }
        }
        if entry.vless_id.is_some() {
            let ws_path = entry
                .ws_path_vless
                .as_deref()
                .or(self.default_ws_path_vless.as_deref());
            let xhttp_path = entry
                .xhttp_path_vless
                .as_deref()
                .or(self.default_xhttp_path_vless.as_deref());
            if ws_path.is_none() && xhttp_path.is_none() && !self.has_raw_quic_vless {
                bail!(
                    "vless_id requires at least one transport: ws_path_vless, \
                     xhttp_path_vless, or raw VLESS-over-QUIC (\"vless\" in [server.h3].alpn)"
                );
            }
            if let Some(path) = ws_path {
                if !path.starts_with('/') {
                    bail!("ws_path_vless must start with '/'");
                }
                if !self.allowed_vless_paths.contains(path) {
                    bail!(
                        "ws_path_vless {path:?} was not registered at startup; restart the \
                         server after adding it to the config file"
                    );
                }
            }
            if let Some(path) = xhttp_path {
                if !path.starts_with('/') {
                    bail!("xhttp_path_vless must start with '/'");
                }
                // Symmetric to the ws_path_vless check above —
                // pre-registered route set is the dispatch contract;
                // the live router cannot grow new routes until the
                // next process restart.
                if !self.allowed_xhttp_paths.contains(path) {
                    bail!(
                        "xhttp_path_vless {path:?} was not registered at startup; restart \
                         the server after adding it to the config file"
                    );
                }
            }
        }
        // SS-over-XHTTP: identity is a password, so gate on `password`
        // and the SS-XHTTP known-path set (symmetric to the vless block).
        if entry.password.is_some()
            && let Some(path) = entry
                .xhttp_path_ss
                .as_deref()
                .or(self.default_xhttp_path_ss.as_deref())
        {
            if !path.starts_with('/') {
                bail!("xhttp_path_ss must start with '/'");
            }
            if !self.allowed_xhttp_ss_paths.contains(path) {
                bail!(
                    "xhttp_path_ss {path:?} was not registered at startup; restart \
                     the server after adding it to the config file"
                );
            }
        }
        // SS-UDP-over-XHTTP: same password gate on the separate UDP path.
        if entry.password.is_some()
            && let Some(path) = entry
                .xhttp_path_ss_udp
                .as_deref()
                .or(self.default_xhttp_path_ss_udp.as_deref())
        {
            if !path.starts_with('/') {
                bail!("xhttp_path_ss_udp must start with '/'");
            }
            if !self.allowed_xhttp_ss_udp_paths.contains(path) {
                bail!(
                    "xhttp_path_ss_udp {path:?} was not registered at startup; restart \
                     the server after adding it to the config file"
                );
            }
        }
        Ok(())
    }

    async fn publish_and_persist(&self, users: &[UserEntry]) -> Result<()> {
        let (routes, auth_keys) = self.rebuild_snapshots(users)?;
        self.routes.store(Arc::new(routes));
        self.auth_users.store(Arc::new(UserKeySlice(auth_keys)));

        if let Some(path) = &self.config_path {
            let path = path.clone();
            let users = users.to_vec();
            tokio::task::spawn_blocking(move || {
                persist_users(&path, &users)
                    .with_context(|| format!("failed to persist users to {}", path.display()))
            })
            .await
            .context("persist task panicked")??;
        }
        Ok(())
    }

    fn rebuild_snapshots(&self, users: &[UserEntry]) -> Result<(RouteRegistry, Arc<[UserKey]>)> {
        let enabled: Vec<&UserEntry> = users.iter().filter(|u| u.is_enabled()).collect();

        let mut seen_ids = HashSet::new();
        for user in &enabled {
            if !seen_ids.insert(&user.id) {
                bail!("duplicate user id: {}", user.id);
            }
        }

        let mut user_routes: Vec<UserRoute> = Vec::new();
        let mut ss_xhttp_routes: Vec<crate::server::setup::SsXhttpUserRoute> = Vec::new();
        let mut ss_xhttp_udp_routes: Vec<crate::server::setup::SsXhttpUserRoute> = Vec::new();
        for user in &enabled {
            let Some(password) = &user.password else { continue };
            let method = user.effective_method(self.default_method);
            let ws_path_tcp: Arc<str> =
                Arc::from(user.effective_ws_path_tcp(&self.default_ws_path_tcp));
            let ws_path_udp: Arc<str> =
                Arc::from(user.effective_ws_path_udp(&self.default_ws_path_udp));
            let user_key = UserKey::new(user.id.clone(), password, user.fwmark, method)
                .with_context(|| format!("failed to derive key for user {}", user.id))?;
            if let Some(path) = user.effective_xhttp_path_ss(self.default_xhttp_path_ss.as_deref())
            {
                ss_xhttp_routes.push(crate::server::setup::SsXhttpUserRoute {
                    user: user_key.clone(),
                    xhttp_path: Arc::from(path),
                });
            }
            if let Some(path) =
                user.effective_xhttp_path_ss_udp(self.default_xhttp_path_ss_udp.as_deref())
            {
                ss_xhttp_udp_routes.push(crate::server::setup::SsXhttpUserRoute {
                    user: user_key.clone(),
                    xhttp_path: Arc::from(path),
                });
            }
            user_routes.push(UserRoute { user: user_key, ws_path_tcp, ws_path_udp });
        }

        let mut vless_routes: Vec<VlessUserRoute> = Vec::new();
        let mut xhttp_routes: Vec<crate::server::setup::VlessXhttpUserRoute> = Vec::new();
        for user in &enabled {
            let Some(vless_id) = &user.vless_id else { continue };
            let ws_path = user.effective_ws_path_vless(self.default_ws_path_vless.as_deref());
            let xhttp_path =
                user.effective_xhttp_path_vless(self.default_xhttp_path_vless.as_deref());
            if ws_path.is_none() && xhttp_path.is_none() {
                bail!("vless user {} requires at least ws_path_vless or xhttp_path_vless", user.id);
            }
            let vless_user =
                VlessUser::new(vless_id.clone(), Arc::from(user.id.as_str()), user.fwmark)
                    .with_context(|| format!("failed to parse vless_id for user {}", user.id))?;
            if let Some(path) = ws_path {
                vless_routes.push(VlessUserRoute {
                    user: vless_user.clone(),
                    ws_path: Arc::from(path),
                });
            }
            if let Some(path) = xhttp_path {
                xhttp_routes.push(crate::server::setup::VlessXhttpUserRoute {
                    user: vless_user,
                    xhttp_path: Arc::from(path),
                });
            }
        }

        let tcp_map: BTreeMap<String, Arc<TransportRoute>> =
            build_transport_route_map(&user_routes, Transport::Tcp);
        let udp_map: BTreeMap<String, Arc<TransportRoute>> =
            build_transport_route_map(&user_routes, Transport::Udp);
        let vless_map: BTreeMap<String, Arc<VlessTransportRoute>> =
            build_vless_transport_route_map(&vless_routes);
        let xhttp_map: BTreeMap<String, Arc<VlessTransportRoute>> =
            crate::server::setup::build_xhttp_vless_route_map(&xhttp_routes);
        let xhttp_ss_map: BTreeMap<String, Arc<TransportRoute>> =
            crate::server::setup::build_xhttp_ss_route_map(&ss_xhttp_routes);
        let xhttp_ss_udp_map: BTreeMap<String, Arc<TransportRoute>> =
            crate::server::setup::build_xhttp_ss_route_map(&ss_xhttp_udp_routes);

        let auth_keys: Arc<[UserKey]> = Arc::from(
            user_routes
                .iter()
                .map(|r| r.user.clone())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );

        Ok((
            RouteRegistry {
                tcp: Arc::new(tcp_map),
                udp: Arc::new(udp_map),
                vless: Arc::new(vless_map),
                xhttp_vless: Arc::new(xhttp_map),
                xhttp_ss: Arc::new(xhttp_ss_map),
                xhttp_ss_udp: Arc::new(xhttp_ss_udp_map),
            },
            auth_keys,
        ))
    }
}

pub(super) struct UserPatch {
    pub password: FieldPatch<String>,
    pub vless_id: FieldPatch<String>,
    pub method: FieldPatch<CipherKind>,
    pub fwmark: FieldPatch<u32>,
    pub ws_path_tcp: FieldPatch<String>,
    pub ws_path_udp: FieldPatch<String>,
    pub ws_path_vless: FieldPatch<String>,
    pub xhttp_path_vless: FieldPatch<String>,
    pub xhttp_path_ss: FieldPatch<String>,
    pub xhttp_path_ss_udp: FieldPatch<String>,
    pub enabled: Option<bool>,
}

impl UserPatch {
    fn apply_to(self, entry: &mut UserEntry) {
        if let FieldPatch::Set(password) = self.password {
            entry.password = password;
        }
        if let FieldPatch::Set(vless_id) = self.vless_id {
            entry.vless_id = vless_id;
        }
        if let FieldPatch::Set(method) = self.method {
            entry.method = method;
        }
        if let FieldPatch::Set(fwmark) = self.fwmark {
            entry.fwmark = fwmark;
        }
        if let FieldPatch::Set(ws_path_tcp) = self.ws_path_tcp {
            entry.ws_path_tcp = ws_path_tcp;
        }
        if let FieldPatch::Set(ws_path_udp) = self.ws_path_udp {
            entry.ws_path_udp = ws_path_udp;
        }
        if let FieldPatch::Set(ws_path_vless) = self.ws_path_vless {
            entry.ws_path_vless = ws_path_vless;
        }
        if let FieldPatch::Set(xhttp_path_vless) = self.xhttp_path_vless {
            entry.xhttp_path_vless = xhttp_path_vless;
        }
        if let FieldPatch::Set(xhttp_path_ss) = self.xhttp_path_ss {
            entry.xhttp_path_ss = xhttp_path_ss;
        }
        if let FieldPatch::Set(xhttp_path_ss_udp) = self.xhttp_path_ss_udp {
            entry.xhttp_path_ss_udp = xhttp_path_ss_udp;
        }
        if let Some(enabled) = self.enabled {
            entry.enabled = Some(enabled);
        }
    }
}

#[derive(Debug, Default)]
pub(super) enum FieldPatch<T> {
    #[default]
    Missing,
    Set(Option<T>),
}

impl<'de, T> Deserialize<'de> for FieldPatch<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Self::Set)
    }
}

#[cfg(test)]
#[path = "tests/manager.rs"]
mod tests;
