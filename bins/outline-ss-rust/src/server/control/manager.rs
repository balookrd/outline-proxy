//! Runtime user manager: canonical list + atomic snapshot publishing.

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    config::{CipherKind, Config, EndpointConfig, OneOrManyCidr, UserEntry},
    crypto::UserKey,
};

use super::super::{
    endpoint_routes::{build_route_registry, build_ss_user_pool, build_vless_user_pool},
    state::{AuthUsersSnapshot, RouteRegistry, RoutesSnapshot, UserKeySlice},
};

use super::persist::{UserMutation, persist_user_mutation};

/// Owns the authoritative user list and publishes derived state via
/// `ArcSwap`. Every mutation takes the single mutex, rebuilds the full route
/// maps + auth slice, writes the one changed user to the config file, and only
/// then publishes the snapshots atomically. Readers on the data plane do a
/// cheap `ArcSwap::load` and observe either the pre- or post-mutation state —
/// never a mix. The config file is *patched*, never re-authored from this list:
/// see [`super::persist`] for why that distinction is the difference between
/// adding a user and deleting everyone else.
pub(in crate::server) struct UserManager {
    inner: Mutex<Inner>,
    routes: RoutesSnapshot,
    auth_users: AuthUsersSnapshot,
    default_method: CipherKind,
    /// Startup endpoint list. Routes are rebuilt against this same list on
    /// every mutation, so a user shows up on every endpoint of its kind —
    /// there are no per-user paths to gate on. Endpoints are startup-only:
    /// the live axum/h3 routers cannot grow new paths until the next restart.
    endpoints: Arc<[EndpointConfig]>,
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
    /// Source-IP → alias map. Exposed in full (not a `has_*` flag) — it is
    /// accounting/routing policy, not a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<BTreeMap<String, OneOrManyCidr>>,
    pub has_password: bool,
    pub has_vless_id: bool,
}

impl From<&UserEntry> for UserView {
    fn from(entry: &UserEntry) -> Self {
        Self {
            id: entry.id.clone(),
            enabled: entry.is_enabled(),
            method: entry.method,
            fwmark: entry.fwmark,
            aliases: entry.aliases.clone(),
            has_password: entry.password.is_some(),
            has_vless_id: entry.vless_id.is_some(),
        }
    }
}

/// The server-wide fallback a user inherits when it carries none of its own.
/// Exposed read-only over `GET /control/defaults` so the dashboard can show a
/// user's *effective* cipher: cloning a user that runs on the default method
/// otherwise yields a blank form, and the UI cannot generate a password
/// without knowing the cipher. Carries no secrets — method only. Paths are no
/// longer a per-user concern: users work on every endpoint of their kind.
#[derive(Debug, Serialize)]
pub(super) struct ServerDefaults {
    pub method: CipherKind,
}

impl UserManager {
    pub(in crate::server) fn new(
        config: &Config,
        routes: RoutesSnapshot,
        auth_users: AuthUsersSnapshot,
    ) -> Self {
        if config.config_path.is_none() {
            // Users came from `--user`/env, not a file, so there is nothing to
            // patch. Say so once at startup rather than letting every mutation
            // report a success that a restart silently undoes.
            warn!(
                "control plane has no config file to write to; user changes apply to the \
                 running process only and are lost on restart"
            );
        }
        Self {
            inner: Mutex::new(Inner { users: config.users.clone() }),
            routes,
            auth_users,
            default_method: config.method,
            endpoints: Arc::from(config.endpoints.clone().into_boxed_slice()),
            config_path: config.config_path.clone(),
        }
    }

    /// Snapshot of the server-wide defaults. Not `async` and takes no lock:
    /// `default_method` is set once in `new` and never mutates, unlike the user
    /// list behind `Inner`.
    pub(super) fn defaults(&self) -> ServerDefaults {
        ServerDefaults { method: self.default_method }
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

    pub(super) async fn create(&self, entry: UserEntry) -> Result<UserView> {
        self.validate_new(&entry)?;
        let mut guard = self.inner.lock().await;
        if guard.users.iter().any(|u| u.id == entry.id) {
            bail!("user id {:?} already exists", entry.id);
        }
        let mut candidate = guard.users.clone();
        candidate.push(entry);
        let created = candidate.last().expect("just pushed").clone();
        self.commit(&candidate, UserMutation::Upsert(Box::new(created)))
            .await?;
        guard.users = candidate;
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
        let mut candidate = guard.users.clone();
        candidate[index] = updated.clone();
        self.commit(&candidate, UserMutation::Upsert(Box::new(updated)))
            .await?;
        guard.users = candidate;
        Ok(UserView::from(&guard.users[index]))
    }

    pub(super) async fn delete(&self, id: &str) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let mut candidate = guard.users.clone();
        candidate.retain(|u| u.id != id);
        if candidate.len() == guard.users.len() {
            bail!("user {id:?} not found");
        }
        self.commit(&candidate, UserMutation::Remove(id.to_owned())).await?;
        guard.users = candidate;
        Ok(())
    }

    pub(super) async fn set_enabled(&self, id: &str, enabled: bool) -> Result<UserView> {
        let mut guard = self.inner.lock().await;
        let index = guard
            .users
            .iter()
            .position(|u| u.id == id)
            .ok_or_else(|| anyhow!("user {id:?} not found"))?;
        let mut candidate = guard.users.clone();
        candidate[index].enabled = Some(enabled);
        let updated = candidate[index].clone();
        self.commit(&candidate, UserMutation::Upsert(Box::new(updated)))
            .await?;
        guard.users = candidate;
        Ok(UserView::from(&guard.users[index]))
    }

    fn validate_new(&self, entry: &UserEntry) -> Result<()> {
        if entry.id.is_empty() {
            bail!("id must not be empty");
        }
        if entry.password.is_none() && entry.vless_id.is_none() {
            bail!("user must have either password or vless_id");
        }
        // Users are pure credentials: there are no per-user paths to validate
        // against the startup route set. A credential is reachable on every
        // endpoint of its kind; whether any such endpoint exists is a
        // startup-time concern (see `services::build`), not a per-user one.
        // Per-user alias CIDRs must parse (global uniqueness is enforced in
        // `rebuild_snapshots`, which sees the full user set).
        entry
            .build_ip_aliases()
            .map_err(|e| anyhow!("invalid ip aliases: {e}"))?;
        Ok(())
    }

    /// Validate `users` as a whole, write the single change that produced it to
    /// the config file, then publish the derived snapshots.
    ///
    /// The order is the contract: the API reports success or failure as the
    /// source of truth, so a mutation that could not be saved must not be live
    /// on the data plane. `mutation` names ONE user — the file keeps every
    /// entry this change did not touch, even one the runtime does not hold.
    async fn commit(&self, users: &[UserEntry], mutation: UserMutation) -> Result<()> {
        let (routes, auth_keys) = self.rebuild_snapshots(users)?;

        if let Some(path) = &self.config_path {
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                persist_user_mutation(&path, &mutation)
                    .with_context(|| format!("failed to persist user to {}", path.display()))
            })
            .await
            .context("persist task panicked")??;
        }

        self.routes.store(Arc::new(routes));
        self.auth_users.store(Arc::new(UserKeySlice(auth_keys)));
        Ok(())
    }

    fn rebuild_snapshots(&self, users: &[UserEntry]) -> Result<(RouteRegistry, Arc<[UserKey]>)> {
        // The same set the old per-user-path builders fed on: enabled users,
        // unique by id. A disabled user contributes to neither pool and so is
        // not routed — do not silently start routing it here.
        let enabled: Vec<UserEntry> = users.iter().filter(|u| u.is_enabled()).cloned().collect();

        let mut seen_ids = HashSet::new();
        for user in &enabled {
            if !seen_ids.insert(&user.id) {
                bail!("duplicate user id: {}", user.id);
            }
        }
        // Per-source-IP aliases: CIDRs parse and alias names are globally
        // unique vs ids — mirrors the startup `Config::validate` check so a
        // control-plane mutation cannot install config the server would reject
        // on restart. Runs on the full enabled set (enabled users are the ones
        // whose aliases become live labels).
        crate::config::validate_ip_aliases(enabled.iter())?;

        // Fan the credential pools across the startup endpoints through the
        // SAME shared helper the startup path uses (`services::build`), so a
        // runtime mutation and a fresh start can never disagree on how routes
        // are shaped. With per-user paths gone, a credential shows up on every
        // endpoint of its kind.
        let ss_users = build_ss_user_pool(&enabled, self.default_method)?;
        let vless_users = build_vless_user_pool(&enabled)?;
        let registry = build_route_registry(&self.endpoints, &ss_users, &vless_users);
        let auth_keys: Arc<[UserKey]> = Arc::from(ss_users.into_boxed_slice());
        Ok((registry, auth_keys))
    }
}

pub(super) struct UserPatch {
    pub password: FieldPatch<String>,
    pub vless_id: FieldPatch<String>,
    pub method: FieldPatch<CipherKind>,
    pub fwmark: FieldPatch<u32>,
    pub aliases: FieldPatch<BTreeMap<String, OneOrManyCidr>>,
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
        if let FieldPatch::Set(aliases) = self.aliases {
            entry.aliases = aliases;
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

// Reused by `control::server::tests` so the defaults route test drives a real
// `UserManager` instead of duplicating a second builder.
#[cfg(test)]
pub(in crate::server::control) use tests::test_manager;
