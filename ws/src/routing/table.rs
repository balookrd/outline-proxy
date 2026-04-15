//! Runtime routing table: CIDR-matching rules with first-match-wins semantics
//! and an explicit default.
//!
//! Built from [`RoutingTableConfig`]. Each rule's CIDR set lives behind its
//! own [`Arc<RwLock<CidrSet>>`] so per-file hot-reload (see [`spawn_route_watchers`])
//! swaps a single rule without locking the whole table.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{RouteRule, RouteTarget, RoutingTableConfig};
use crate::types::TargetAddr;

use super::cidr::{CidrSet, read_prefixes_from_file};

/// Compiled rule: CIDR set (shared, hot-reloadable) + target / fallback.
pub struct CompiledRule {
    pub cidrs: Arc<RwLock<CidrSet>>,
    /// Inline prefixes from config — merged with file contents on each
    /// reload so removing the file doesn't drop the inline entries.
    pub inline_prefixes: Vec<String>,
    pub file: Option<PathBuf>,
    pub file_poll: Duration,
    pub target: RouteTarget,
    pub fallback: Option<RouteTarget>,
}

pub struct RoutingTable {
    pub rules: Vec<CompiledRule>,
    pub default_target: RouteTarget,
    pub default_fallback: Option<RouteTarget>,
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
            rules.push(CompiledRule {
                cidrs: Arc::new(RwLock::new(cidrs)),
                inline_prefixes: rule.inline_prefixes.clone(),
                file: rule.file.clone(),
                file_poll: rule.file_poll,
                target: rule.target.clone(),
                fallback: rule.fallback.clone(),
            });
        }
        Ok(Self {
            rules,
            default_target: config.default_target.clone(),
            default_fallback: config.default_fallback.clone(),
        })
    }

    /// First-match-wins resolve. Domains never match a CIDR rule and always
    /// fall through to the default.
    pub async fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        for rule in &self.rules {
            if rule.cidrs.read().await.contains(target) {
                return RouteDecision {
                    primary: rule.target.clone(),
                    fallback: rule.fallback.clone(),
                };
            }
        }
        RouteDecision {
            primary: self.default_target.clone(),
            fallback: self.default_fallback.clone(),
        }
    }
}

async fn build_cidr_set(rule: &RouteRule) -> Result<CidrSet> {
    let mut prefixes = rule.inline_prefixes.clone();
    if let Some(file) = &rule.file {
        let from_file = read_prefixes_from_file(file)
            .await
            .with_context(|| format!("failed to read route prefix file {}", file.display()))?;
        prefixes.extend(from_file);
    }
    CidrSet::parse(&prefixes)
}

/// Spawn a file watcher for every rule that has `file` set. On mtime change
/// the rule's CIDR set is rebuilt (inline + file) and swapped atomically.
pub fn spawn_route_watchers(table: Arc<RoutingTable>) {
    for (index, rule) in table.rules.iter().enumerate() {
        let Some(file) = rule.file.clone() else {
            continue;
        };
        let cidrs = Arc::clone(&rule.cidrs);
        let inline = rule.inline_prefixes.clone();
        let poll = rule.file_poll;
        tokio::spawn(async move {
            let mut last_mtime: Option<SystemTime> = None;
            loop {
                tokio::time::sleep(poll).await;
                let mtime = tokio::fs::metadata(&file).await.ok().and_then(|m| m.modified().ok());
                if mtime == last_mtime {
                    continue;
                }
                last_mtime = mtime;
                match reload_rule_cidrs(&file, &inline).await {
                    Ok(new_set) => {
                        let count_v4 = new_set.v4_range_count();
                        let count_v6 = new_set.v6_range_count();
                        *cidrs.write().await = new_set;
                        info!(
                            rule_index = index,
                            path = %file.display(),
                            v4_ranges = count_v4,
                            v6_ranges = count_v6,
                            "route CIDR set reloaded"
                        );
                    },
                    Err(err) => {
                        warn!(
                            rule_index = index,
                            path = %file.display(),
                            error = %format!("{err:#}"),
                            "failed to reload route CIDR set, keeping previous"
                        );
                    },
                }
            }
        });
    }
}

async fn reload_rule_cidrs(file: &std::path::Path, inline: &[String]) -> Result<CidrSet> {
    let from_file = read_prefixes_from_file(file).await?;
    let mut all = Vec::with_capacity(inline.len() + from_file.len());
    all.extend_from_slice(inline);
    all.extend(from_file);
    CidrSet::parse(&all)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> TargetAddr {
        TargetAddr::IpV4(Ipv4Addr::new(a, b, c, d), 80)
    }

    fn v6(s: &str) -> TargetAddr {
        TargetAddr::IpV6(s.parse::<Ipv6Addr>().unwrap(), 80)
    }

    fn rule(prefixes: &[&str], target: RouteTarget, fallback: Option<RouteTarget>) -> RouteRule {
        RouteRule {
            inline_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
            file: None,
            file_poll: Duration::from_secs(60),
            target,
            fallback,
        }
    }

    #[tokio::test]
    async fn resolve_first_match_wins() {
        let cfg = RoutingTableConfig {
            rules: vec![
                rule(&["10.0.0.0/8"], RouteTarget::Direct, None),
                rule(&["1.0.0.0/8"], RouteTarget::Group("main".into()), None),
            ],
            default_target: RouteTarget::Group("main".into()),
            default_fallback: None,
        };
        let table = RoutingTable::compile(&cfg).await.unwrap();

        let d = table.resolve(&v4(10, 1, 2, 3)).await;
        assert_eq!(d.primary, RouteTarget::Direct);

        let d = table.resolve(&v4(1, 1, 1, 1)).await;
        assert_eq!(d.primary, RouteTarget::Group("main".into()));

        // Unmatched → default
        let d = table.resolve(&v4(8, 8, 8, 8)).await;
        assert_eq!(d.primary, RouteTarget::Group("main".into()));
    }

    #[tokio::test]
    async fn resolve_carries_fallback() {
        let cfg = RoutingTableConfig {
            rules: vec![rule(
                &["1.0.0.0/8"],
                RouteTarget::Group("main".into()),
                Some(RouteTarget::Group("backup".into())),
            )],
            default_target: RouteTarget::Direct,
            default_fallback: Some(RouteTarget::Drop),
        };
        let table = RoutingTable::compile(&cfg).await.unwrap();

        let d = table.resolve(&v4(1, 2, 3, 4)).await;
        assert_eq!(d.primary, RouteTarget::Group("main".into()));
        assert_eq!(d.fallback, Some(RouteTarget::Group("backup".into())));

        let d = table.resolve(&v4(9, 9, 9, 9)).await;
        assert_eq!(d.primary, RouteTarget::Direct);
        assert_eq!(d.fallback, Some(RouteTarget::Drop));
    }

    #[tokio::test]
    async fn resolve_v6_and_domain_fallthrough() {
        let cfg = RoutingTableConfig {
            rules: vec![rule(&["fc00::/7"], RouteTarget::Direct, None)],
            default_target: RouteTarget::Group("main".into()),
            default_fallback: None,
        };
        let table = RoutingTable::compile(&cfg).await.unwrap();

        assert_eq!(table.resolve(&v6("fc00::1")).await.primary, RouteTarget::Direct);
        assert_eq!(
            table.resolve(&v6("2001:db8::1")).await.primary,
            RouteTarget::Group("main".into())
        );
        // Domains never match a CIDR rule.
        let dom = TargetAddr::Domain("example.com".into(), 80);
        assert_eq!(table.resolve(&dom).await.primary, RouteTarget::Group("main".into()));
    }

    #[tokio::test]
    async fn resolve_empty_rules_uses_default() {
        let cfg = RoutingTableConfig {
            rules: vec![],
            default_target: RouteTarget::Direct,
            default_fallback: None,
        };
        let table = RoutingTable::compile(&cfg).await.unwrap();
        assert_eq!(table.resolve(&v4(1, 2, 3, 4)).await.primary, RouteTarget::Direct);
    }
}
