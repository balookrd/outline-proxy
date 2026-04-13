use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::types::TargetAddr;

/// Decides whether a SOCKS5 connection target should bypass the tunnel.
///
/// Internally stores sorted, merged IPv4 and IPv6 ranges for O(log n) lookup.
///
/// `invert = false` (default): bypass IPs that ARE in the prefix list.
/// `invert = true`: bypass IPs NOT in the prefix list (tunnel only listed prefixes).
///
/// Domain targets are never bypassed — only IP addresses are matched.
#[derive(Debug, Clone)]
pub struct BypassList {
    v4: Vec<[u32; 2]>,
    v6: Vec<[u128; 2]>,
    invert: bool,
}

impl BypassList {
    pub fn parse(prefixes: &[String], invert: bool) -> Result<Self> {
        let mut v4 = Vec::with_capacity(prefixes.len());
        let mut v6 = Vec::with_capacity(prefixes.len());

        for s in prefixes {
            let (addr_str, len_str) = match s.split_once('/') {
                Some((a, l)) => (a, Some(l)),
                None => (s.as_str(), None),
            };
            let addr: IpAddr = addr_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid IP address in prefix: {s}"))?;
            match addr {
                IpAddr::V4(ip) => {
                    let prefix_len = parse_prefix_len(len_str, 32, s)?;
                    v4.push(cidr_to_range_v4(ip, prefix_len));
                }
                IpAddr::V6(ip) => {
                    let prefix_len = parse_prefix_len(len_str, 128, s)?;
                    v6.push(cidr_to_range_v6(ip, prefix_len));
                }
            }
        }

        Ok(Self { v4: merge_v4(v4), v6: merge_v6(v6), invert })
    }

    pub fn is_bypassed(&self, target: &TargetAddr) -> bool {
        let in_list = match target {
            TargetAddr::IpV4(ip, _) => contains_v4(&self.v4, u32::from(*ip)),
            TargetAddr::IpV6(ip, _) => contains_v6(&self.v6, u128::from(*ip)),
            TargetAddr::Domain(_, _) => return false,
        };
        if self.invert { !in_list } else { in_list }
    }
}

// ── Binary search ────────────────────────────────────────────────────────────

fn contains_v4(ranges: &[[u32; 2]], ip: u32) -> bool {
    let i = ranges.partition_point(|r| r[0] <= ip);
    i > 0 && ip <= ranges[i - 1][1]
}

fn contains_v6(ranges: &[[u128; 2]], ip: u128) -> bool {
    let i = ranges.partition_point(|r| r[0] <= ip);
    i > 0 && ip <= ranges[i - 1][1]
}

// ── CIDR → [start, end] ──────────────────────────────────────────────────────

fn cidr_to_range_v4(addr: Ipv4Addr, prefix_len: u8) -> [u32; 2] {
    let addr = u32::from(addr);
    if prefix_len == 0 {
        return [0, u32::MAX];
    }
    let mask = !0u32 << (32 - prefix_len);
    let start = addr & mask;
    [start, start | !mask]
}

fn cidr_to_range_v6(addr: Ipv6Addr, prefix_len: u8) -> [u128; 2] {
    let addr = u128::from(addr);
    if prefix_len == 0 {
        return [0, u128::MAX];
    }
    let mask = !0u128 << (128 - prefix_len);
    let start = addr & mask;
    [start, start | !mask]
}

// ── Sort + merge overlapping/adjacent ranges ─────────────────────────────────

fn merge_v4(mut ranges: Vec<[u32; 2]>) -> Vec<[u32; 2]> {
    ranges.sort_unstable_by_key(|r| r[0]);
    let mut out: Vec<[u32; 2]> = Vec::with_capacity(ranges.len());
    for [start, end] in ranges {
        if let Some(last) = out.last_mut() {
            // merge overlapping or adjacent (saturating_add avoids u32::MAX wrap)
            if start <= last[1].saturating_add(1) {
                if end > last[1] {
                    last[1] = end;
                }
                continue;
            }
        }
        out.push([start, end]);
    }
    out
}

fn merge_v6(mut ranges: Vec<[u128; 2]>) -> Vec<[u128; 2]> {
    ranges.sort_unstable_by_key(|r| r[0]);
    let mut out: Vec<[u128; 2]> = Vec::with_capacity(ranges.len());
    for [start, end] in ranges {
        if let Some(last) = out.last_mut() {
            if start <= last[1].saturating_add(1) {
                if end > last[1] {
                    last[1] = end;
                }
                continue;
            }
        }
        out.push([start, end]);
    }
    out
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// ── File loading + hot-reload ─────────────────────────────────────────────────

/// Parse a bypass prefix file: one CIDR per line, `#` comments and blank lines
/// are ignored.  Both IPv4 and IPv6 prefixes are accepted.
pub async fn load_from_file(path: &Path, invert: bool) -> Result<BypassList> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read bypass file {}", path.display()))?;
    let prefixes: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    BypassList::parse(&prefixes, invert)
        .with_context(|| format!("failed to parse bypass file {}", path.display()))
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
                Ok(new_list) => {
                    *shared.write().await = new_list;
                    info!(path = %path.display(), "bypass list reloaded");
                }
                Err(err) => {
                    warn!(path = %path.display(), error = %format!("{err:#}"), "failed to reload bypass list, keeping previous");
                }
            }
        }
    });
}

fn parse_prefix_len(s: Option<&str>, max: u8, context: &str) -> Result<u8> {
    match s {
        None => Ok(max),
        Some(s) => {
            let n: u8 =
                s.parse().map_err(|_| anyhow::anyhow!("invalid prefix length in: {context}"))?;
            if n > max {
                bail!("prefix length {n} exceeds maximum {max} in: {context}");
            }
            Ok(n)
        }
    }
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
        assert!(!l.is_bypassed(&v4(192, 167, 255, 255)));
    }

    #[test]
    fn host_route_v4() {
        let l = list(&["8.8.8.8"]);
        assert!(l.is_bypassed(&v4(8, 8, 8, 8)));
        assert!(!l.is_bypassed(&v4(8, 8, 8, 7)));
        assert!(!l.is_bypassed(&v4(8, 8, 8, 9)));
    }

    #[test]
    fn default_route() {
        let l = list(&["0.0.0.0/0"]);
        assert!(l.is_bypassed(&v4(0, 0, 0, 0)));
        assert!(l.is_bypassed(&v4(1, 2, 3, 4)));
        assert!(l.is_bypassed(&v4(255, 255, 255, 255)));
    }

    #[test]
    fn multiple_prefixes_merged() {
        // These are adjacent: /25 + /25 = /24 after merge.
        let l = list(&["10.0.0.0/25", "10.0.0.128/25"]);
        assert!(l.is_bypassed(&v4(10, 0, 0, 0)));
        assert!(l.is_bypassed(&v4(10, 0, 0, 127)));
        assert!(l.is_bypassed(&v4(10, 0, 0, 128)));
        assert!(l.is_bypassed(&v4(10, 0, 0, 255)));
        assert!(!l.is_bypassed(&v4(10, 0, 1, 0)));
        // After merge, only one range should remain.
        assert_eq!(l.v4.len(), 1);
    }

    #[test]
    fn overlapping_prefixes_merged() {
        let l = list(&["10.0.0.0/8", "10.1.0.0/16"]);
        assert!(l.is_bypassed(&v4(10, 1, 0, 1)));
        assert_eq!(l.v4.len(), 1);
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
        assert!(!l.is_bypassed(&v6("2001:db8::1")));
    }

    #[test]
    fn domain_never_bypassed() {
        let l = list(&["0.0.0.0/0"]);
        assert!(!l.is_bypassed(&TargetAddr::Domain("example.com".to_string(), 80)));
    }

    #[test]
    fn boundary_v4() {
        let l = list(&["10.0.0.0/8"]);
        assert!(l.is_bypassed(&v4(10, 0, 0, 0))); // start
        assert!(l.is_bypassed(&v4(10, 255, 255, 255))); // end
        assert!(!l.is_bypassed(&v4(9, 255, 255, 255))); // before start
        assert!(!l.is_bypassed(&v4(11, 0, 0, 0))); // after end
    }

    #[test]
    fn parse_error_bad_addr() {
        assert!(BypassList::parse(&["notanip/24".to_string()], false).is_err());
    }

    #[test]
    fn parse_error_prefix_too_long() {
        assert!(BypassList::parse(&["1.2.3.4/33".to_string()], false).is_err());
    }
}
