//! Declarative routing configuration shared between the main binary (which
//! parses it from TOML) and the routing engine (which compiles it into a
//! [`crate::RoutingTable`]).

use std::path::PathBuf;
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
    Group(String),
}

/// One policy routing rule.
///
/// Prefixes come from `inline_prefixes` and/or one or more `files`. When
/// `files` is non-empty, a background watcher polls `file_poll` for mtime
/// changes on every listed file and swaps the compiled CIDR set in place
/// whenever any file changes.
#[derive(Debug, Clone)]
pub struct RouteRule {
    pub inline_prefixes: Vec<String>,
    pub files: Vec<PathBuf>,
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
