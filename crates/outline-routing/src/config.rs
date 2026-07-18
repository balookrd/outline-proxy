//! Declarative routing configuration shared between the main binary (which
//! parses it from TOML) and the routing engine (which compiles it into a
//! [`crate::RoutingTable`]).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Action a matched route should take for the traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    /// Forward the connection outside any uplink (equivalent to the old
    /// `via = "direct"` behaviour).
    Direct,
    /// Silently drop the connection (TCP → SOCKS5 reply `REP=0x02`, UDP → drop).
    Drop,
    /// Route through the named group.
    Group(Arc<str>),
}

/// One policy routing rule.
///
/// Prefixes come from `inline_prefixes` and/or one or more `files`; domain
/// suffixes come from `inline_domains` and/or `domain_files`. When any file
/// list is non-empty, a background watcher polls `file_poll` for mtime
/// changes on every listed file and swaps the compiled sets in place
/// whenever any file changes.
///
/// An IP target is matched against the CIDR set (honouring `invert`); a
/// domain target is matched against the domain suffixes. A rule may carry
/// both kinds. `invert` only applies to the CIDR side and is rejected at
/// compile time when the rule also has domains — "not in this domain list"
/// has no sound meaning across the two address kinds.
#[derive(Debug, Clone)]
pub struct RouteRule {
    pub inline_prefixes: Vec<String>,
    pub files: Vec<PathBuf>,
    /// Domain suffixes matched against domain targets (SOCKS5h hostnames).
    /// `"*"` is a catch-all. See [`crate::DomainSet`].
    pub inline_domains: Vec<String>,
    /// Files with one domain suffix per line, merged with `inline_domains`.
    pub domain_files: Vec<PathBuf>,
    pub file_poll: Duration,
    pub target: RouteTarget,
    pub fallback: Option<RouteTarget>,
    /// When true, the rule matches addresses NOT in the CIDR set.
    pub invert: bool,
}

/// Full routing table — ordered rules + explicit default.
#[derive(Debug, Clone)]
pub struct RoutingTableConfig {
    pub rules: Vec<RouteRule>,
    pub default_target: RouteTarget,
    pub default_fallback: Option<RouteTarget>,
}
