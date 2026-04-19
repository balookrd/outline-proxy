//! Persistent uplink state — survives process restarts.
//!
//! Only the active-uplink selection is persisted (by uplink name, so it
//! remains valid even if the uplink list order changes in config).
//! Metrics such as EWMA and penalty are deliberately not persisted: they
//! represent short-lived observations and the probe loop will re-establish
//! accurate values within one probe cycle.
//!
//! The file is written asynchronously with a 200 ms debounce; a crash
//! between a switch and the flush means at most one missed write, which
//! is acceptable — the next probe cycle will correct the selection.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

/// The subset of runtime state worth persisting across restarts.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistedState {
    #[serde(default)]
    pub groups: HashMap<String, GroupActiveState>,
}

/// Per-group active uplink names.  Stored by name so that index shifts in
/// config (adding/removing uplinks) do not silently reroute traffic.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct GroupActiveState {
    /// Active uplink for `routing_scope = global`.
    pub global_active: Option<String>,
    /// Active TCP uplink for `routing_scope = per_uplink`.
    pub tcp_active: Option<String>,
    /// Active UDP uplink for `routing_scope = per_uplink`.
    pub udp_active: Option<String>,
}

/// Thread-safe store that persists [`PersistedState`] to a TOML file.
///
/// Callers update the in-memory state via [`StateStore::update_active`] and
/// the store schedules a debounced background flush automatically.
pub struct StateStore {
    path: PathBuf,
    state: Mutex<PersistedState>,
    dirty: Notify,
}

impl StateStore {
    /// Load state from `path` (silently starting fresh on any error) and
    /// return a reference-counted handle ready for use.
    pub async fn load_or_default(path: PathBuf) -> Arc<Self> {
        let state = Self::try_load(&path).await.unwrap_or_default();
        Arc::new(Self { path, state: Mutex::new(state), dirty: Notify::new() })
    }

    async fn try_load(path: &PathBuf) -> Option<PersistedState> {
        let raw = tokio::fs::read_to_string(path).await.ok()?;
        match toml::from_str(&raw) {
            Ok(state) => Some(state),
            Err(e) => {
                warn!(path = ?path, error = %e, "failed to parse uplink state file, starting fresh");
                None
            },
        }
    }

    /// Return the persisted active state for `group`, or a blank default if
    /// there is no entry for that group yet.
    pub async fn group_state(&self, group: &str) -> GroupActiveState {
        self.state.lock().await.groups.get(group).cloned().unwrap_or_default()
    }

    /// Update one or more active-uplink fields for `group` and schedule a
    /// flush.  Pass `Some(Some(name))` to set a field, `Some(None)` to clear
    /// it, and `None` to leave it unchanged.
    pub async fn update_active(
        &self,
        group: &str,
        global: Option<Option<String>>,
        tcp: Option<Option<String>>,
        udp: Option<Option<String>>,
    ) {
        let mut state = self.state.lock().await;
        let g = state.groups.entry(group.to_string()).or_default();
        let mut changed = false;
        if let Some(v) = global
            && g.global_active != v
        {
            g.global_active = v;
            changed = true;
        }
        if let Some(v) = tcp
            && g.tcp_active != v
        {
            g.tcp_active = v;
            changed = true;
        }
        if let Some(v) = udp
            && g.udp_active != v
        {
            g.udp_active = v;
            changed = true;
        }
        if changed {
            self.dirty.notify_one();
        }
    }

    /// Spawn a background task that flushes the state to disk whenever it is
    /// marked dirty, with a 200 ms debounce to coalesce bursts of updates.
    pub fn spawn_writer(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                self.dirty.notified().await;
                // Drain any burst of updates within 200 ms.
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(200)) => break,
                        _ = self.dirty.notified() => {},
                    }
                }
                let snapshot = self.state.lock().await.clone();
                match toml::to_string_pretty(&snapshot) {
                    Ok(text) => {
                        if let Err(e) = write_atomic(&self.path, text.as_bytes()).await {
                            warn!(path = ?self.path, error = %format!("{e:#}"), "failed to persist uplink state");
                        } else {
                            debug!(path = ?self.path, "uplink state persisted");
                        }
                    },
                    Err(e) => warn!(error = %e, "failed to serialize uplink state"),
                }
            }
        });
    }
}

/// Write `bytes` to `path` atomically: create a sibling `.tmp` file with
/// mode 0o600 (Unix), write the payload, fsync it, then rename over the
/// destination. A crash between any of those steps leaves either the old
/// file or the tmp file — never a truncated destination.
async fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("state path {} has no parent directory", path.display())
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!("state path {} has no file name", path.display())
    })?;

    let mut tmp_name = OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp_path: PathBuf = parent.join(&tmp_name);

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&tmp_path)
        .await
        .with_context(|| format!("open tmp {}", tmp_path.display()))?;

    use tokio::io::AsyncWriteExt;
    file.write_all(bytes)
        .await
        .with_context(|| format!("write tmp {}", tmp_path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("fsync tmp {}", tmp_path.display()))?;
    drop(file);

    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!("rename {} -> {}", tmp_path.display(), path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_atomic_creates_file_with_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        write_atomic(&path, b"hello").await.unwrap();
        let got = tokio::fs::read(&path).await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn write_atomic_leaves_no_tmp_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        write_atomic(&path, b"x").await.unwrap();
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        let mut names = Vec::new();
        while let Some(e) = entries.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["state.toml"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_atomic_sets_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        write_atomic(&path, b"x").await.unwrap();
        let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn write_atomic_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        tokio::fs::write(&path, b"old").await.unwrap();
        write_atomic(&path, b"new").await.unwrap();
        let got = tokio::fs::read(&path).await.unwrap();
        assert_eq!(got, b"new");
    }

    // ── StateStore tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn state_store_in_memory_update_reflected_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let store = StateStore::load_or_default(path).await;
        store.update_active("g1", Some(Some("u1".into())), None, None).await;
        let gs = store.group_state("g1").await;
        assert_eq!(gs.global_active, Some("u1".to_string()));
        assert_eq!(gs.tcp_active, None);
        assert_eq!(gs.udp_active, None);
    }

    #[tokio::test]
    async fn state_store_none_field_leaves_existing_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let store = StateStore::load_or_default(path).await;
        store.update_active("g", Some(Some("a".into())), Some(Some("b".into())), None).await;
        // Pass None for global — must not touch the existing value.
        store.update_active("g", None, Some(Some("c".into())), None).await;
        let gs = store.group_state("g").await;
        assert_eq!(gs.global_active, Some("a".to_string()));
        assert_eq!(gs.tcp_active, Some("c".to_string()));
    }

    #[tokio::test]
    async fn state_store_clear_field_with_some_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let store = StateStore::load_or_default(path).await;
        store.update_active("g", Some(Some("x".into())), None, None).await;
        // Some(None) must clear the field.
        store.update_active("g", Some(None), None, None).await;
        assert_eq!(store.group_state("g").await.global_active, None);
    }

    #[tokio::test]
    async fn state_store_missing_group_returns_blank_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let store = StateStore::load_or_default(path).await;
        let gs = store.group_state("no_such_group").await;
        assert_eq!(gs.global_active, None);
        assert_eq!(gs.tcp_active, None);
        assert_eq!(gs.udp_active, None);
    }

    #[tokio::test]
    async fn state_store_persists_to_disk_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        {
            let store = StateStore::load_or_default(path.clone()).await;
            store
                .update_active(
                    "grp",
                    Some(Some("uplink1".into())),
                    None,
                    Some(Some("uplink2".into())),
                )
                .await;
            store.clone().spawn_writer();
            // Wait for the 200 ms debounce + slack.
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        let reloaded = StateStore::load_or_default(path).await;
        let gs = reloaded.group_state("grp").await;
        assert_eq!(gs.global_active, Some("uplink1".to_string()));
        assert_eq!(gs.udp_active, Some("uplink2".to_string()));
    }

    #[tokio::test]
    async fn state_store_corrupt_file_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        tokio::fs::write(&path, b"this is not valid toml!!!@@@").await.unwrap();
        let store = StateStore::load_or_default(path).await;
        let gs = store.group_state("any").await;
        assert_eq!(gs.global_active, None);
    }

    #[tokio::test]
    async fn state_store_empty_file_starts_fresh() {
        // First-run scenario: the state file exists (e.g. pre-created by
        // systemd-tmpfiles or an install script) but is empty. Must parse
        // as an empty PersistedState without warnings, not fail or crash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        tokio::fs::write(&path, b"").await.unwrap();
        let store = StateStore::load_or_default(path).await;
        let gs = store.group_state("any").await;
        assert_eq!(gs.global_active, None);
        assert_eq!(gs.tcp_active, None);
        assert_eq!(gs.udp_active, None);
    }

    #[tokio::test]
    async fn state_store_missing_file_starts_fresh() {
        // No state file at all (clean install). Must not error; subsequent
        // update + flush should create the file atomically.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-existed.toml");
        assert!(!path.exists());
        let store = StateStore::load_or_default(path.clone()).await;
        let gs = store.group_state("any").await;
        assert_eq!(gs.global_active, None);
    }
}
