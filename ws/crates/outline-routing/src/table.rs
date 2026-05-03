//! Runtime routing table: CIDR-matching rules with first-match-wins semantics
//! and an explicit default.
//!
//! Built from [`RoutingTableConfig`]. Each rule's CIDR set lives behind its
//! own [`Arc<RwLock<CidrSet>>`] so per-file hot-reload (see [`spawn_route_watchers`])
//! swaps a single rule without locking the whole table.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

use crate::config::{RouteRule, RouteTarget, RoutingTableConfig};
use socks5_proto::TargetAddr;

use super::cidr::{CidrSet, read_prefixes_from_file};

/// Compiled rule: CIDR set (shared, hot-reloadable) + target / fallback.
#[derive(Debug)]
pub struct CompiledRule {
    pub cidrs: Arc<RwLock<CidrSet>>,
    /// Inline prefixes from config — merged with file contents on each
    /// reload so removing the file doesn't drop the inline entries.
    pub inline_prefixes: Arc<[String]>,
    pub files: Arc<[PathBuf]>,
    pub file_poll: Duration,
    pub target: RouteTarget,
    pub fallback: Option<RouteTarget>,
    /// When true, the rule matches addresses NOT in the CIDR set.
    /// Domains still never match (they fall through to the default).
    pub invert: bool,
}

#[derive(Debug)]
pub struct RoutingTable {
    pub rules: Vec<CompiledRule>,
    pub default_target: RouteTarget,
    pub default_fallback: Option<RouteTarget>,
    /// Bumped by [`spawn_route_watchers`] after every successful rule
    /// reload. Downstream consumers (e.g. the UDP per-association route
    /// cache) compare this against the version snapshot taken when the
    /// entry was inserted: a mismatch invalidates the cached decision.
    pub version: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub primary: RouteTarget,
    pub fallback: Option<RouteTarget>,
}

impl RoutingTable {
    /// Compile the table, reading every rule's `file` (if set) and merging
    /// with its inline prefixes.
    pub async fn compile(config: &RoutingTableConfig) -> Result<Self> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for (index, rule) in config.rules.iter().enumerate() {
            let cidrs = build_cidr_set(rule)
                .await
                .with_context(|| format!("failed to build route {} CIDR set", index + 1))?;
            // An inverted rule with an empty CIDR set would match every IP
            // and silently swallow all traffic — almost certainly a misconfig
            // (missing `prefixes` or an empty/unreadable `file`). Refuse it.
            if rule.invert && cidrs.is_empty() {
                bail!(
                    "route {} has `invert = true` but no prefixes; \
                     an inverted empty set would match every address",
                    index + 1
                );
            }
            rules.push(CompiledRule {
                cidrs: Arc::new(RwLock::new(cidrs)),
                inline_prefixes: rule.inline_prefixes.as_slice().into(),
                files: rule.files.as_slice().into(),
                file_poll: rule.file_poll,
                target: rule.target.clone(),
                fallback: rule.fallback.clone(),
                invert: rule.invert,
            });
        }
        Ok(Self {
            rules,
            default_target: config.default_target.clone(),
            default_fallback: config.default_fallback.clone(),
            version: AtomicU64::new(0),
        })
    }

    /// Current routing-table version. Callers cache this alongside a
    /// per-target decision and re-resolve on mismatch.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// First-match-wins resolve. Domains never match a CIDR rule and always
    /// fall through to the default (including inverted rules — inverting an
    /// empty match on a domain would incorrectly match everything).
    pub async fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        self.resolve_versioned(target).await.0
    }

    /// Resolve and return the version snapshot captured *before* the first
    /// CIDR read. Callers that cache the decision should tag it with this
    /// version (not the version at the time of insertion): if the watcher
    /// bumps the version during resolution the caller will see a stale
    /// snapshot on the next lookup and re-resolve, rather than tagging a
    /// potentially-stale decision with the post-bump version.
    pub async fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64) {
        // Snapshot BEFORE any CIDR read so a concurrent reload invalidates
        // the decision we are about to compute instead of silently shadowing
        // it with the post-bump version.
        let version = self.version.load(Ordering::Acquire);
        let is_domain = matches!(target, TargetAddr::Domain(_, _));
        for rule in &self.rules {
            if is_domain {
                // Domains skip all CIDR rules (inverted or not).
                continue;
            }
            let in_set = rule.cidrs.read().await.contains(target);
            let matched = if rule.invert { !in_set } else { in_set };
            if matched {
                return (
                    RouteDecision {
                        primary: rule.target.clone(),
                        fallback: rule.fallback.clone(),
                    },
                    version,
                );
            }
        }
        (
            RouteDecision {
                primary: self.default_target.clone(),
                fallback: self.default_fallback.clone(),
            },
            version,
        )
    }
}

async fn build_cidr_set(rule: &RouteRule) -> Result<CidrSet> {
    let mut prefixes = rule.inline_prefixes.clone();
    for file in &rule.files {
        let from_file = read_prefixes_from_file(file)
            .await
            .with_context(|| format!("failed to read route prefix file {}", file.display()))?;
        prefixes.extend(from_file);
    }
    CidrSet::parse(&prefixes)
}

/// Guard returned by [`spawn_route_watchers`]. Dropping it signals every
/// spawned watcher task to exit on its next poll cycle (or immediately if
/// it is currently sleeping). Without this guard the tasks would live for
/// the full process lifetime and keep `Arc<RoutingTable>` alive, which
/// would leak tasks/tables on any future routing hot-reload.
#[must_use = "dropping the guard cancels the route watcher tasks"]
pub struct RouteWatchersGuard {
    shutdown: watch::Sender<bool>,
}

impl Drop for RouteWatchersGuard {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// Spawn a file watcher for every rule that has at least one `files` entry.
/// On mtime change in any of the rule's files the whole CIDR set is rebuilt
/// (inline + all files) and swapped atomically, then
/// [`RoutingTable::version`] is bumped so per-association caches that hold
/// stale resolutions re-resolve on the next hit.
///
/// Returns a [`RouteWatchersGuard`] that cancels all spawned tasks on drop.
/// The caller must keep the guard alive for as long as the watchers should
/// run; dropping it before process exit (e.g. on a routing hot-reload) lets
/// the old `Arc<RoutingTable>` and its `Arc<RwLock<CidrSet>>` references be
/// released.
pub fn spawn_route_watchers(table: Arc<RoutingTable>) -> RouteWatchersGuard {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for (index, rule) in table.rules.iter().enumerate() {
        if rule.files.is_empty() {
            continue;
        }
        let files = rule.files.clone();
        let cidrs = Arc::clone(&rule.cidrs);
        let inline = rule.inline_prefixes.clone();
        let poll = rule.file_poll;
        let invert = rule.invert;
        let table_for_version = Arc::clone(&table);
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            // Seed from each file's current mtime so the first poll cycle
            // does not reload files that haven't changed since compile() read
            // them. A missing file is represented as `None` and still triggers
            // a reload once it reappears with a readable mtime.
            let mut last_mtimes: Vec<Option<SystemTime>> = Vec::with_capacity(files.len());
            for f in files.iter() {
                last_mtimes.push(
                    tokio::fs::metadata(f)
                        .await
                        .ok()
                        .and_then(|m| m.modified().ok()),
                );
            }
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(poll) => {},
                    res = shutdown.changed() => {
                        // Either an explicit shutdown signal (Ok with `true`)
                        // or the sender was dropped (Err). Both mean exit.
                        if res.is_err() || *shutdown.borrow() {
                            break;
                        }
                        continue;
                    }
                }
                let mut changed = false;
                for (i, f) in files.iter().enumerate() {
                    let mtime = tokio::fs::metadata(f)
                        .await
                        .ok()
                        .and_then(|m| m.modified().ok());
                    if mtime != last_mtimes[i] {
                        last_mtimes[i] = mtime;
                        changed = true;
                    }
                }
                if !changed {
                    continue;
                }
                match reload_rule_cidrs(&files, &inline).await {
                    Ok(new_set) => {
                        // Safety net: an inverted rule with an empty set
                        // would match everything. Refuse the swap and keep
                        // the previous (valid) set.
                        if invert && new_set.is_empty() {
                            warn!(
                                rule_index = index,
                                paths = ?files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                                "refusing to reload inverted route with empty CIDR set — \
                                 would match every address; keeping previous"
                            );
                            continue;
                        }
                        let count_v4 = new_set.v4_range_count();
                        let count_v6 = new_set.v6_range_count();
                        *cidrs.write().await = new_set;
                        let new_version =
                            table_for_version.version.fetch_add(1, Ordering::AcqRel) + 1;
                        info!(
                            rule_index = index,
                            paths = ?files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                            v4_ranges = count_v4,
                            v6_ranges = count_v6,
                            table_version = new_version,
                            "route CIDR set reloaded"
                        );
                    },
                    Err(err) => {
                        warn!(
                            rule_index = index,
                            paths = ?files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                            error = %format!("{err:#}"),
                            "failed to reload route CIDR set, keeping previous"
                        );
                    },
                }
            }
        });
    }
    RouteWatchersGuard { shutdown: shutdown_tx }
}

async fn reload_rule_cidrs(files: &[PathBuf], inline: &[String]) -> Result<CidrSet> {
    let mut all: Vec<String> = inline.to_vec();
    for file in files {
        let from_file = read_prefixes_from_file(file)
            .await
            .with_context(|| format!("failed to read route prefix file {}", file.display()))?;
        all.extend(from_file);
    }
    CidrSet::parse(&all)
}

#[cfg(test)]
#[path = "tests/table.rs"]
mod tests;
