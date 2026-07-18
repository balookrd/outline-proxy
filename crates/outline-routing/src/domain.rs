//! Domain suffix set for policy routing rules.
//!
//! CIDR rules cannot see a domain target (a SOCKS5h client hands the proxy a
//! hostname precisely so it is *not* resolved locally), so without this every
//! domain target falls through to the routing default. A [`DomainSet`] lets a
//! rule match domain targets by suffix instead.
//!
//! Matching is label-wise (`example.com` matches `example.com` and
//! `a.b.example.com`, never `notexample.com`), case-insensitive, and ignores a
//! trailing dot. The wildcard pattern `"*"` matches every domain — useful as a
//! catch-all rule so domain targets get an explicit route instead of the
//! default.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Set of domain suffixes with O(labels) lookup.
#[derive(Debug, Clone, Default)]
pub struct DomainSet {
    /// Normalized suffixes (lowercase, no leading/trailing dots).
    suffixes: HashSet<String>,
    /// True when a `"*"` pattern was present: match every domain.
    match_all: bool,
}

impl DomainSet {
    /// Build a set from patterns: domain suffixes (`example.com`,
    /// `.example.com` and `*.example.com` are equivalent) or the `"*"`
    /// catch-all. Empty/whitespace patterns are rejected.
    pub fn parse(patterns: &[String]) -> Result<Self> {
        let mut suffixes = HashSet::with_capacity(patterns.len());
        let mut match_all = false;
        for raw in patterns {
            let pattern = raw.trim();
            if pattern == "*" {
                match_all = true;
                continue;
            }
            let normalized = normalize(pattern);
            if normalized.is_empty() {
                bail!(
                    "invalid domain pattern {raw:?} (want a suffix like \"example.com\" or \"*\")"
                );
            }
            suffixes.insert(normalized);
        }
        Ok(Self { suffixes, match_all })
    }

    /// True if `host` (a domain name; IPs never reach this) matches the
    /// catch-all or any stored suffix on a label boundary.
    pub fn contains_domain(&self, host: &str) -> bool {
        if self.match_all {
            return true;
        }
        if self.suffixes.is_empty() {
            return false;
        }
        let host = normalize(host);
        // Walk the suffixes of `host` label by label: for a.b.example.com try
        // a.b.example.com, b.example.com, example.com, com.
        let mut suffix = host.as_str();
        loop {
            if self.suffixes.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => return false,
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.match_all && self.suffixes.is_empty()
    }

    /// Number of stored suffixes (the catch-all not included).
    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    pub fn matches_all(&self) -> bool {
        self.match_all
    }
}

/// Lowercase and strip the decorations a suffix or host may carry: leading
/// `*.`/`.` on patterns, one trailing `.` on FQDNs.
fn normalize(s: &str) -> String {
    let s = s.strip_prefix("*.").unwrap_or(s);
    let s = s.strip_prefix('.').unwrap_or(s);
    let s = s.strip_suffix('.').unwrap_or(s);
    s.to_ascii_lowercase()
}

/// Read domain patterns from a file: one per line, `#` comments and blank
/// lines ignored — the same shape as the CIDR prefix files.
pub async fn read_domains_from_file(path: &Path) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read domain file {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
#[path = "tests/domain.rs"]
mod tests;
