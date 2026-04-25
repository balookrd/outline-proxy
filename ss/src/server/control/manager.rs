//! Runtime user manager: canonical list + atomic snapshot publishing.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    config::{CipherKind, Config, UserEntry, access_key::build_access_key_artifacts_for_user},
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
/// [`ArcSwap`]. Every mutation takes the single mutex, rebuilds the full route
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
    default_vless_ws_path: Option<String>,
    access_key_config: crate::config::AccessKeyConfig,
    access_key_base_config: Config,
    // Paths that exist in the startup Axum/H3 routers. Mutations that
    // introduce a path outside this set are rejected — the routers cannot
    // dispatch requests to unknown paths until the next restart.
    allowed_tcp_paths: BTreeSet<String>,
    allowed_udp_paths: BTreeSet<String>,
    allowed_vless_paths: BTreeSet<String>,
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
    pub vless_ws_path: Option<String>,
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
            vless_ws_path: entry.vless_ws_path.clone(),
            has_password: entry.password.is_some(),
            has_vless_id: entry.vless_id.is_some(),
        }
    }
}

impl UserManager {
    pub(in crate::server) fn new(
        config: &Config,
        routes: RoutesSnapshot,
        auth_users: AuthUsersSnapshot,
        allowed_tcp_paths: BTreeSet<String>,
        allowed_udp_paths: BTreeSet<String>,
        allowed_vless_paths: BTreeSet<String>,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner { users: config.users.clone() }),
            routes,
            auth_users,
            default_method: config.method,
            default_ws_path_tcp: config.ws_path_tcp.clone(),
            default_ws_path_udp: config.ws_path_udp.clone(),
            default_vless_ws_path: config.vless_ws_path.clone(),
            access_key_config: config.access_key.clone(),
            access_key_base_config: config.clone(),
            allowed_tcp_paths,
            allowed_udp_paths,
            allowed_vless_paths,
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
                view.vless_url = artifact.access_key_url;
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
            let path = entry
                .vless_ws_path
                .as_deref()
                .or(self.default_vless_ws_path.as_deref())
                .ok_or_else(|| anyhow!("vless_id requires vless_ws_path"))?;
            if !path.starts_with('/') {
                bail!("vless_ws_path must start with '/'");
            }
            if !self.allowed_vless_paths.contains(path) {
                bail!(
                    "vless_ws_path {path:?} was not registered at startup; restart the \
                     server after adding it to the config file"
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
        for user in &enabled {
            let Some(password) = &user.password else { continue };
            let method = user.effective_method(self.default_method);
            let ws_path_tcp: Arc<str> =
                Arc::from(user.effective_ws_path_tcp(&self.default_ws_path_tcp));
            let ws_path_udp: Arc<str> =
                Arc::from(user.effective_ws_path_udp(&self.default_ws_path_udp));
            let user_key = UserKey::new(user.id.clone(), password, user.fwmark, method)
                .with_context(|| format!("failed to derive key for user {}", user.id))?;
            user_routes.push(UserRoute { user: user_key, ws_path_tcp, ws_path_udp });
        }

        let mut vless_routes: Vec<VlessUserRoute> = Vec::new();
        for user in &enabled {
            let Some(vless_id) = &user.vless_id else { continue };
            let path = user
                .effective_vless_ws_path(self.default_vless_ws_path.as_deref())
                .ok_or_else(|| anyhow!("vless user {} missing vless_ws_path", user.id))?;
            let vless_user = VlessUser::new(vless_id.clone(), user.fwmark)
                .with_context(|| format!("failed to parse vless_id for user {}", user.id))?;
            vless_routes.push(VlessUserRoute {
                user: vless_user,
                ws_path: Arc::from(path),
            });
        }

        let tcp_map: BTreeMap<String, Arc<TransportRoute>> =
            build_transport_route_map(&user_routes, Transport::Tcp);
        let udp_map: BTreeMap<String, Arc<TransportRoute>> =
            build_transport_route_map(&user_routes, Transport::Udp);
        let vless_map: BTreeMap<String, Arc<VlessTransportRoute>> =
            build_vless_transport_route_map(&vless_routes);

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
            },
            auth_keys,
        ))
    }
}

pub(super) struct UserPatch {
    pub password: Option<Option<String>>,
    pub vless_id: Option<Option<String>>,
    pub method: Option<Option<CipherKind>>,
    pub fwmark: Option<Option<u32>>,
    pub ws_path_tcp: Option<Option<String>>,
    pub ws_path_udp: Option<Option<String>>,
    pub vless_ws_path: Option<Option<String>>,
    pub enabled: Option<bool>,
}

impl UserPatch {
    fn apply_to(self, entry: &mut UserEntry) {
        if let Some(password) = self.password {
            entry.password = password;
        }
        if let Some(vless_id) = self.vless_id {
            entry.vless_id = vless_id;
        }
        if let Some(method) = self.method {
            entry.method = method;
        }
        if let Some(fwmark) = self.fwmark {
            entry.fwmark = fwmark;
        }
        if let Some(ws_path_tcp) = self.ws_path_tcp {
            entry.ws_path_tcp = ws_path_tcp;
        }
        if let Some(ws_path_udp) = self.ws_path_udp {
            entry.ws_path_udp = ws_path_udp;
        }
        if let Some(vless_ws_path) = self.vless_ws_path {
            entry.vless_ws_path = vless_ws_path;
        }
        if let Some(enabled) = self.enabled {
            entry.enabled = Some(enabled);
        }
    }
}

#[allow(dead_code)]
fn _arc_swap_is_used(snapshot: &RoutesSnapshot) {
    let _ = ArcSwap::load(snapshot);
}
