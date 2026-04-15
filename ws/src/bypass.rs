use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::routing::{CidrSet, read_prefixes_from_file};
use crate::types::TargetAddr;

/// Decides whether a SOCKS5 connection target should bypass the tunnel.
///
/// Thin wrapper around [`CidrSet`] that adds inversion support.
///
/// `invert = false` (default): bypass IPs that ARE in the prefix list.
/// `invert = true`: bypass IPs NOT in the prefix list (tunnel only listed prefixes).
///
/// Domain targets are never bypassed — only IP addresses are matched.
#[derive(Debug, Clone)]
pub struct BypassList {
    inner: CidrSet,
    invert: bool,
}

impl BypassList {
    pub fn parse(prefixes: &[String], invert: bool) -> Result<Self> {
        Ok(Self { inner: CidrSet::parse(prefixes)?, invert })
    }

    pub fn is_bypassed(&self, target: &TargetAddr) -> bool {
        let in_list = self.inner.contains(target);
        if self.invert { !in_list } else { in_list }
    }
}

// ── File loading + hot-reload ─────────────────────────────────────────────────

/// Parse a bypass prefix file: one CIDR per line, `#` comments and blank lines
/// are ignored. Both IPv4 and IPv6 prefixes are accepted.
pub async fn load_from_file(path: &Path, invert: bool) -> Result<(BypassList, usize)> {
    let prefixes = read_prefixes_from_file(path).await?;
    let prefix_count = prefixes.len();
    let list = BypassList::parse(&prefixes, invert)
        .with_context(|| format!("failed to parse bypass file {}", path.display()))?;
    Ok((list, prefix_count))
}

/// Spawn a background task that polls `path` for mtime changes every
/// `interval` and replaces the list inside `shared` on change.
pub fn spawn_file_watcher(
    path: PathBuf,
    shared: Arc<RwLock<BypassList>>,
    invert: bool,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut last_mtime: Option<SystemTime> = None;
        loop {
            tokio::time::sleep(interval).await;
            let mtime = tokio::fs::metadata(&path).await.ok().and_then(|m| m.modified().ok());
            if mtime == last_mtime {
                continue;
            }
            last_mtime = mtime;
            match load_from_file(&path, invert).await {
                Ok((new_list, prefix_count)) => {
                    *shared.write().await = new_list;
                    info!(path = %path.display(), prefix_count, "bypass list reloaded");
                },
                Err(err) => {
                    warn!(path = %path.display(), error = %format!("{err:#}"), "failed to reload bypass list, keeping previous");
                },
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> TargetAddr {
        TargetAddr::IpV4(Ipv4Addr::new(a, b, c, d), 80)
    }

    fn v6(s: &str) -> TargetAddr {
        TargetAddr::IpV6(s.parse::<Ipv6Addr>().unwrap(), 80)
    }

    fn list(prefixes: &[&str]) -> BypassList {
        BypassList::parse(&prefixes.iter().map(|s| s.to_string()).collect::<Vec<_>>(), false)
            .unwrap()
    }

    #[test]
    fn cidr_v4_basic() {
        let l = list(&["192.168.0.0/16"]);
        assert!(l.is_bypassed(&v4(192, 168, 0, 0)));
        assert!(l.is_bypassed(&v4(192, 168, 1, 1)));
        assert!(l.is_bypassed(&v4(192, 168, 255, 255)));
        assert!(!l.is_bypassed(&v4(192, 169, 0, 0)));
    }

    #[test]
    fn invert() {
        let l = BypassList::parse(&["10.0.0.0/8".to_string()], true).unwrap();
        assert!(!l.is_bypassed(&v4(10, 0, 0, 1))); // in list → NOT bypassed
        assert!(l.is_bypassed(&v4(1, 1, 1, 1))); // not in list → bypassed
    }

    #[test]
    fn cidr_v6() {
        let l = list(&["fc00::/7"]);
        assert!(l.is_bypassed(&v6("fc00::1")));
        assert!(l.is_bypassed(&v6("fdff:ffff:ffff:ffff::1")));
        assert!(!l.is_bypassed(&v6("fe00::1")));
    }

    #[test]
    fn domain_never_bypassed() {
        let l = list(&["0.0.0.0/0"]);
        assert!(!l.is_bypassed(&TargetAddr::Domain("example.com".to_string(), 80)));
    }
}
