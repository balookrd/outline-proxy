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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

/// The subset of runtime state worth persisting across restarts.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistedState {
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

/// Thread-safe store that persists [`PersistedState`] to a JSON file.
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
        if let Some(v) = global {
            g.global_active = v;
        }
        if let Some(v) = tcp {
            g.tcp_active = v;
        }
        if let Some(v) = udp {
            g.udp_active = v;
        }
        self.dirty.notify_one();
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
                        if let Err(e) = tokio::fs::write(&self.path, text.as_bytes()).await {
                            warn!(path = ?self.path, error = %e, "failed to persist uplink state");
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
