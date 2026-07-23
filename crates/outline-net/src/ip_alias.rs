//! Source-IP → alias longest-prefix matcher.
//!
//! A pure, protocol-agnostic CIDR table mapping IPv4/IPv6 subnets to an alias
//! label. Used server-side to relabel an authenticated user's *accounting*
//! identity (metrics / NAT keying / logs only) by the client's source IP,
//! without pulling in a third-party CIDR dependency. It never participates in
//! authentication or access control.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

/// Error building an [`IpAliasTable`] from operator-supplied config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAliasError {
    /// An alias key was empty.
    EmptyAlias,
    /// A CIDR/IP string did not parse (carries the alias + offending value).
    InvalidCidr { alias: String, value: String },
    /// Two entries define the exact same network/prefix but map to different
    /// aliases — ambiguous, so the whole table is rejected.
    DuplicatePrefix {
        value: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for IpAliasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlias => write!(f, "empty alias name in ip aliases"),
            Self::InvalidCidr { alias, value } => {
                write!(f, "alias {alias:?}: invalid ip/cidr {value:?}")
            },
            Self::DuplicatePrefix { value, first, second } => {
                write!(f, "ip/cidr {value:?} mapped to two aliases {first:?} and {second:?}")
            },
        }
    }
}

impl std::error::Error for IpAliasError {}

#[derive(Debug, Clone)]
struct Entry {
    /// Network address masked to `prefix` bits, widened to `u128` (IPv4 lives
    /// in the low 32 bits).
    net: u128,
    prefix: u8,
    alias: Arc<str>,
}

/// Every network sharing one prefix length, sorted ascending by masked network
/// address. Within a group all networks are the same size and disjoint, so an
/// address can match at most one of them — which is what makes the binary
/// search in [`IpAliasTable::resolve`] exact rather than a range probe.
#[derive(Debug, Clone)]
struct PrefixGroup {
    prefix: u8,
    nets: Vec<(u128, Arc<str>)>,
}

/// Longest-prefix source-IP → alias lookup table. Separate v4/v6 buckets, each
/// a list of prefix-length groups ordered longest-first, so [`Self::resolve`]
/// returns the most specific match.
///
/// Lookup cost is `O(G · log n)`, where `G` is the number of *distinct* prefix
/// lengths in the config (bounded by 33 for IPv4 / 129 for IPv6, and in
/// practice a handful) — not `O(n)` over every configured subnet.
#[derive(Debug, Clone, Default)]
pub struct IpAliasTable {
    v4: Vec<PrefixGroup>,
    v6: Vec<PrefixGroup>,
}

impl IpAliasTable {
    /// Build from `(alias, &[cidr_or_ip])` pairs. Accepts a borrowed slice for
    /// each alias so callers can pass any value shape (single string or list)
    /// without this crate depending on their config types. Rejects empty alias
    /// names, malformed CIDRs/IPs, and exact-duplicate prefixes mapping to
    /// different aliases. Overlapping-but-distinct prefixes are allowed —
    /// longest-prefix wins at resolve time.
    pub fn build<'a, I>(entries: I) -> Result<Self, IpAliasError>
    where
        I: IntoIterator<Item = (&'a str, &'a [String])>,
    {
        let mut v4: Vec<Entry> = Vec::new();
        let mut v6: Vec<Entry> = Vec::new();
        for (alias, cidrs) in entries {
            if alias.is_empty() {
                return Err(IpAliasError::EmptyAlias);
            }
            let alias_arc: Arc<str> = Arc::from(alias);
            for cidr in cidrs {
                let (net, prefix, is_v4) =
                    parse_cidr(cidr).ok_or_else(|| IpAliasError::InvalidCidr {
                        alias: alias.to_owned(),
                        value: cidr.clone(),
                    })?;
                let bucket = if is_v4 { &mut v4 } else { &mut v6 };
                if let Some(existing) = bucket.iter().find(|e| e.net == net && e.prefix == prefix) {
                    // Same alias listing the same prefix twice is a harmless
                    // dedupe; a different alias on the same prefix is ambiguous.
                    if existing.alias.as_ref() != alias {
                        return Err(IpAliasError::DuplicatePrefix {
                            value: cidr.clone(),
                            first: existing.alias.to_string(),
                            second: alias.to_owned(),
                        });
                    }
                    continue;
                }
                bucket.push(Entry {
                    net,
                    prefix,
                    alias: Arc::clone(&alias_arc),
                });
            }
        }
        Ok(Self {
            v4: group_by_prefix(v4),
            v6: group_by_prefix(v6),
        })
    }

    /// The alias whose subnet most specifically contains `ip`, or `None`.
    /// IPv4-mapped IPv6 peers (`::ffff:a.b.c.d`, common on dual-stack
    /// listeners) are canonicalised to IPv4 so they match IPv4 subnets.
    pub fn resolve(&self, ip: IpAddr) -> Option<Arc<str>> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let (bits, width, bucket) = match ip {
            IpAddr::V4(v4) => (u32::from(v4) as u128, 32u8, &self.v4),
            IpAddr::V6(v6) => (u128::from(v6), 128u8, &self.v6),
        };
        // Groups run longest-prefix-first, so the first hit is the most
        // specific match and we can stop there.
        for group in bucket {
            let net = mask_bits(bits, group.prefix, width);
            if let Ok(i) = group.nets.binary_search_by(|(candidate, _)| candidate.cmp(&net)) {
                return Some(Arc::clone(&group.nets[i].1));
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Bucket entries by prefix length: groups ordered longest-prefix-first (so
/// `resolve` walks from most to least specific), networks sorted within each
/// group (so `resolve` can binary-search them).
fn group_by_prefix(mut entries: Vec<Entry>) -> Vec<PrefixGroup> {
    entries.sort_unstable_by(|a, b| b.prefix.cmp(&a.prefix).then(a.net.cmp(&b.net)));
    let mut groups: Vec<PrefixGroup> = Vec::new();
    for entry in entries {
        match groups.last_mut() {
            Some(group) if group.prefix == entry.prefix => {
                group.nets.push((entry.net, entry.alias))
            },
            _ => groups.push(PrefixGroup {
                prefix: entry.prefix,
                nets: vec![(entry.net, entry.alias)],
            }),
        }
    }
    groups
}

/// Mask `bits` to its top `prefix` bits within a `width`-bit address space
/// (32 for IPv4, 128 for IPv6).
fn mask_bits(bits: u128, prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    if prefix >= width {
        return bits;
    }
    let shift = width - prefix;
    (bits >> shift) << shift
}

/// Parse `"ip"` or `"ip/prefix"` into `(masked network, prefix, is_v4)`. A
/// bare address is treated as a host route (`/32` or `/128`). Host bits below
/// the prefix are masked off so `192.0.2.5/24` normalises to `192.0.2.0/24`.
fn parse_cidr(s: &str) -> Option<(u128, u8, bool)> {
    let s = s.trim();
    let (addr_part, prefix_part) = match s.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (s, None),
    };
    let ip: IpAddr = addr_part.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let prefix = match prefix_part {
                Some(p) => p.parse::<u8>().ok().filter(|&p| p <= 32)?,
                None => 32,
            };
            Some((mask_bits(u32::from(v4) as u128, prefix, 32), prefix, true))
        },
        IpAddr::V6(v6) => {
            let prefix = match prefix_part {
                Some(p) => p.parse::<u8>().ok().filter(|&p| p <= 128)?,
                None => 128,
            };
            Some((mask_bits(u128::from(v6), prefix, 128), prefix, false))
        },
    }
}

#[cfg(test)]
#[path = "tests/ip_alias.rs"]
mod tests;
