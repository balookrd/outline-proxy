//! Hot-reload of listener TLS certificates when the cert/key files on
//! disk change.
//!
//! A lightweight background task polls the configured cert/key files and,
//! on a detected change, asks the caller to rebuild and install a fresh
//! TLS config. Both listeners reuse the same loop:
//!
//! - TCP swaps an `ArcSwap<TlsAcceptor>` that the accept loop reads once
//!   per connection.
//! - HTTP/3 calls `quinn::Endpoint::set_server_config`, which applies to
//!   new QUIC connections.
//!
//! In both cases only *new* connections pick up the new certificate;
//! already-established connections keep the cert they negotiated.
//!
//! Polling (rather than an inotify/kqueue watch) is intentional: it adds
//! no dependency and is robust to the atomic rename / symlink swap that
//! ACME clients (certbot, lego, acme.sh) perform on renewal, where a
//! watch pinned to the original inode would silently stop firing.

use std::{
    hash::Hasher,
    path::{Path, PathBuf},
};

use anyhow::Result;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::config::Config;

use super::super::shutdown::ShutdownSignal;

/// Cert + key files backing the TCP listener: the default pair plus every
/// `[[server.certs]]` entry.
pub(in crate::server) fn tcp_cert_paths(config: &Config) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    push_pair(&mut paths, config.tls_cert_path.as_deref(), config.tls_key_path.as_deref());
    for entry in &config.tls_certs {
        paths.push(entry.cert_path.clone());
        paths.push(entry.key_path.clone());
    }
    paths
}

/// Cert + key files backing the HTTP/3 listener: the default pair plus
/// every `[[server.h3.certs]]` entry. These are already resolved with the
/// TCP-listener inheritance applied at config-load time, so they name the
/// files actually in use.
pub(in crate::server) fn h3_cert_paths(config: &Config) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    push_pair(&mut paths, config.h3_cert_path.as_deref(), config.h3_key_path.as_deref());
    for entry in &config.h3_certs {
        paths.push(entry.cert_path.clone());
        paths.push(entry.key_path.clone());
    }
    paths
}

fn push_pair(paths: &mut Vec<PathBuf>, cert: Option<&Path>, key: Option<&Path>) {
    if let Some(cert) = cert {
        paths.push(cert.to_path_buf());
    }
    if let Some(key) = key {
        paths.push(key.to_path_buf());
    }
}

/// Spawns a background task that watches `paths` and calls `reload` when
/// their on-disk contents change. `reload` re-reads the files and installs
/// the new TLS config; on error the previously loaded config is kept and
/// the failure is logged. The task exits on the shutdown signal. A no-op
/// when `paths` is empty (the listener has no cert files to watch).
pub(in crate::server) fn spawn_cert_reloader<F>(
    listener: &'static str,
    paths: Vec<PathBuf>,
    poll_interval: Duration,
    mut shutdown: ShutdownSignal,
    mut reload: F,
) where
    F: FnMut() -> Result<()> + Send + 'static,
{
    if paths.is_empty() {
        return;
    }
    tokio::spawn(async move {
        // Baseline = whatever is on disk now; the listener already loaded
        // these files at startup, so we only react to subsequent changes.
        let mut tracker = ReloadTracker::new(fingerprint(&paths));
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // consume the immediate tick; baseline already captured
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    debug!(listener, "certificate reloader stopping on shutdown signal");
                    break;
                }
                _ = interval.tick() => {
                    let current = fingerprint(&paths);
                    if !tracker.should_attempt(current) {
                        continue;
                    }
                    match reload() {
                        Ok(()) => {
                            tracker.mark_applied(current);
                            info!(listener, "reloaded TLS certificates after on-disk change");
                        },
                        Err(error) => {
                            // Keep serving with the previously loaded certs.
                            // `should_attempt` already recorded this state, so
                            // we neither retry nor re-log it until the files
                            // change again — e.g. once a half-written rotation
                            // (cert updated, key not yet) finishes.
                            warn!(
                                listener,
                                ?error,
                                "failed to reload TLS certificates; keeping the previous ones"
                            );
                        },
                    }
                }
            }
        }
    });
}

/// Content fingerprint of the watched files. Hashes each path together
/// with its bytes, so any content edit, addition, or removal changes the
/// result. A transient read error (the brief window of an atomic rename)
/// hashes to a distinct value, which simply triggers a reload attempt that
/// fails and is retried on the next change.
fn fingerprint(paths: &[PathBuf]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for path in paths {
        hasher.write(path.as_os_str().as_encoded_bytes());
        match std::fs::read(path) {
            Ok(bytes) => {
                hasher.write_u8(0);
                hasher.write_usize(bytes.len());
                hasher.write(&bytes);
            },
            Err(_) => hasher.write_u8(1),
        }
    }
    hasher.finish()
}

/// Tracks which on-disk fingerprint is live (`applied`) and which one we
/// last tried (`last_attempted`). Together they make the reloader attempt
/// each distinct file state exactly once: it never reloads a state already
/// live, and never spams on a persistently broken pair, while still
/// retrying automatically as soon as the files change again.
struct ReloadTracker {
    applied: u64,
    last_attempted: u64,
}

impl ReloadTracker {
    fn new(initial: u64) -> Self {
        Self {
            applied: initial,
            last_attempted: initial,
        }
    }

    /// `true` when `current` differs from both the live config and the
    /// state we last tried — i.e. a genuinely new on-disk state worth a
    /// reload attempt. Records it as attempted.
    fn should_attempt(&mut self, current: u64) -> bool {
        if current == self.applied || current == self.last_attempted {
            return false;
        }
        self.last_attempted = current;
        true
    }

    fn mark_applied(&mut self, current: u64) {
        self.applied = current;
    }
}

#[cfg(test)]
#[path = "tests/cert_reload.rs"]
mod tests;
