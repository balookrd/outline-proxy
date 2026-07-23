use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build a table from `(alias, &[cidr])` literals.
fn table(entries: &[(&str, &[&str])]) -> IpAliasTable {
    let owned: Vec<(String, Vec<String>)> = entries
        .iter()
        .map(|(a, cidrs)| (a.to_string(), cidrs.iter().map(|s| s.to_string()).collect()))
        .collect();
    IpAliasTable::build(owned.iter().map(|(a, c)| (a.as_str(), c.as_slice())))
        .expect("table should build")
}

fn try_build(entries: &[(&str, &[&str])]) -> Result<IpAliasTable, IpAliasError> {
    let owned: Vec<(String, Vec<String>)> = entries
        .iter()
        .map(|(a, cidrs)| (a.to_string(), cidrs.iter().map(|s| s.to_string()).collect()))
        .collect();
    IpAliasTable::build(owned.iter().map(|(a, c)| (a.as_str(), c.as_slice())))
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid ip")
}

fn resolve(t: &IpAliasTable, s: &str) -> Option<String> {
    t.resolve(ip(s)).map(|a| a.to_string())
}

#[test]
fn empty_table_is_empty_and_resolves_none() {
    let t = table(&[]);
    assert!(t.is_empty());
    assert_eq!(resolve(&t, "192.0.2.1"), None);
}

#[test]
fn matches_subnet_v4() {
    let t = table(&[("office", &["192.0.2.0/24"])]);
    assert_eq!(resolve(&t, "192.0.2.50"), Some("office".to_string()));
    assert_eq!(resolve(&t, "192.0.3.50"), None);
}

#[test]
fn longest_prefix_wins_v4() {
    // A more specific /25 must win over the enclosing /24.
    let t = table(&[("broad", &["192.0.2.0/24"]), ("narrow", &["192.0.2.0/25"])]);
    assert_eq!(resolve(&t, "192.0.2.10"), Some("narrow".to_string())); // in /25
    assert_eq!(resolve(&t, "192.0.2.200"), Some("broad".to_string())); // outside /25, in /24
}

#[test]
fn longest_prefix_wins_v6() {
    let t = table(&[("broad", &["2001:db8::/32"]), ("narrow", &["2001:db8:abcd::/48"])]);
    assert_eq!(resolve(&t, "2001:db8:abcd::1"), Some("narrow".to_string()));
    assert_eq!(resolve(&t, "2001:db8:0:1::1"), Some("broad".to_string()));
    assert_eq!(resolve(&t, "2001:dead::1"), None);
}

#[test]
fn bare_host_is_slash_32_and_128() {
    let t = table(&[("h4", &["203.0.113.7"]), ("h6", &["2001:db8::7"])]);
    assert_eq!(resolve(&t, "203.0.113.7"), Some("h4".to_string()));
    assert_eq!(resolve(&t, "203.0.113.8"), None);
    assert_eq!(resolve(&t, "2001:db8::7"), Some("h6".to_string()));
    assert_eq!(resolve(&t, "2001:db8::8"), None);
}

#[test]
fn one_alias_spans_multiple_subnets() {
    let t = table(&[("road", &["10.0.0.0/8", "203.0.113.0/24", "2001:db8::/32"])]);
    assert_eq!(resolve(&t, "10.1.2.3"), Some("road".to_string()));
    assert_eq!(resolve(&t, "203.0.113.5"), Some("road".to_string()));
    assert_eq!(resolve(&t, "2001:db8::abcd"), Some("road".to_string()));
    assert_eq!(resolve(&t, "192.0.2.1"), None);
}

#[test]
fn host_bits_below_prefix_are_masked() {
    // 192.0.2.5/24 must behave as 192.0.2.0/24.
    let t = table(&[("net", &["192.0.2.5/24"])]);
    assert_eq!(resolve(&t, "192.0.2.250"), Some("net".to_string()));
}

#[test]
fn ipv4_mapped_v6_peer_matches_v4_subnet() {
    let t = table(&[("office", &["192.0.2.0/24"])]);
    assert_eq!(resolve(&t, "::ffff:192.0.2.9"), Some("office".to_string()));
}

#[test]
fn empty_alias_rejected() {
    assert!(matches!(try_build(&[("", &["192.0.2.0/24"])]), Err(IpAliasError::EmptyAlias)));
}

#[test]
fn malformed_cidr_rejected() {
    assert!(matches!(
        try_build(&[("a", &["not-an-ip"])]),
        Err(IpAliasError::InvalidCidr { .. })
    ));
    assert!(matches!(
        try_build(&[("a", &["192.0.2.0/40"])]),
        Err(IpAliasError::InvalidCidr { .. })
    ));
    assert!(matches!(
        try_build(&[("a", &["2001:db8::/200"])]),
        Err(IpAliasError::InvalidCidr { .. })
    ));
}

#[test]
fn duplicate_prefix_different_alias_rejected() {
    assert!(matches!(
        try_build(&[("a", &["192.0.2.0/24"]), ("b", &["192.0.2.0/24"])]),
        Err(IpAliasError::DuplicatePrefix { .. })
    ));
}

#[test]
fn duplicate_prefix_same_alias_deduped() {
    // Same alias listing the same prefix twice is harmless.
    let t = table(&[("a", &["192.0.2.0/24", "192.0.2.0/24"])]);
    assert_eq!(resolve(&t, "192.0.2.1"), Some("a".to_string()));
}

// ── Differential tests against a brute-force reference ───────────────────────
//
// `resolve` is index-structure sensitive: it groups entries by prefix length
// and binary-searches each group. These tests pin its answers to a naive
// linear scan over the raw specs, so any lookup-layout change has to keep
// picking the exact same alias.

/// Overlapping/nested subnets across both families. Deliberately mixes
/// several entries that share one prefix length (the binary-searched groups)
/// with deeply nested chains (the descending-length walk).
const OVERLAPPING: &[(&str, &str)] = &[
    ("a8", "10.0.0.0/8"),
    ("a12", "10.16.0.0/12"),
    ("a16", "10.16.0.0/16"),
    ("a20", "10.16.32.0/20"),
    ("a24", "10.16.32.0/24"),
    ("a28", "10.16.32.0/28"),
    ("a32", "10.16.32.7"),
    ("b16", "10.17.0.0/16"),
    ("b24", "10.17.5.0/24"),
    ("c16", "172.16.0.0/16"),
    ("d24", "192.168.1.0/24"),
    ("d25", "192.168.1.128/25"),
    ("d32", "192.168.1.200"),
    ("v6a", "2001:db8::/32"),
    ("v6b", "2001:db8:abcd::/48"),
    ("v6c", "2001:db8:abcd:1234::/64"),
    ("v6d", "2001:db8:abcd:1234::9"),
    ("v6e", "2001:db8:beef::/48"),
    ("v6f", "fd00::/8"),
];

/// Build a table from flat `(alias, cidr)` specs, grouping repeated aliases.
fn table_from_specs(specs: &[(&str, &str)]) -> IpAliasTable {
    let mut by_alias: Vec<(String, Vec<String>)> = Vec::new();
    for (alias, cidr) in specs {
        match by_alias.iter_mut().find(|(a, _)| a == alias) {
            Some((_, cidrs)) => cidrs.push((*cidr).to_string()),
            None => by_alias.push(((*alias).to_string(), vec![(*cidr).to_string()])),
        }
    }
    IpAliasTable::build(by_alias.iter().map(|(a, c)| (a.as_str(), c.as_slice())))
        .expect("specs should build")
}

/// Brute-force longest-prefix match straight off the specs — the oracle the
/// real table must agree with.
fn reference_resolve(specs: &[(&str, &str)], addr: IpAddr) -> Option<String> {
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let (bits, width, want_v4) = match addr {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32u8, true),
        IpAddr::V6(v6) => (u128::from(v6), 128u8, false),
    };
    let mut best: Option<(u8, &str)> = None;
    for (alias, cidr) in specs {
        let (net, prefix, is_v4) = parse_cidr(cidr).expect("valid cidr");
        if is_v4 != want_v4 || mask_bits(bits, prefix, width) != net {
            continue;
        }
        if best.is_none_or(|(best_prefix, _)| prefix > best_prefix) {
            best = Some((prefix, alias));
        }
    }
    best.map(|(_, alias)| alias.to_string())
}

/// Deterministic probe generator — no `rand`, so a failure always reproduces.
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

/// Probes hugging every subnet boundary in `specs`, plus pseudo-random noise.
fn probe_addrs(specs: &[(&str, &str)]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for (_, cidr) in specs {
        let (net, prefix, is_v4) = parse_cidr(cidr).expect("valid cidr");
        let width = if is_v4 { 32u8 } else { 128u8 };
        let host_bits = width - prefix;
        let span = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        // Below the network, the network itself, inside it, its last address,
        // and one past the end.
        for candidate in [
            net.wrapping_sub(1),
            net,
            net.wrapping_add(span / 2),
            net.wrapping_add(span),
            net.wrapping_add(span).wrapping_add(1),
        ] {
            out.push(if is_v4 {
                IpAddr::from(Ipv4Addr::from(candidate as u32))
            } else {
                IpAddr::from(Ipv6Addr::from(candidate))
            });
        }
    }
    let mut rng = Lcg(0x5eed_1234_abcd_0001);
    for _ in 0..512 {
        out.push(IpAddr::from(Ipv4Addr::from(rng.next_u64() as u32)));
        out.push(IpAddr::from(Ipv6Addr::from(
            u128::from(rng.next_u64()) << 64 | u128::from(rng.next_u64()),
        )));
        // Keep most v6 probes inside 2001:db8::/32 so they actually hit.
        out.push(IpAddr::from(Ipv6Addr::from(
            0x2001_0db8_0000_0000_0000_0000_0000_0000u128 | u128::from(rng.next_u64()),
        )));
    }
    out
}

#[test]
fn resolve_matches_linear_scan_on_overlapping_subnets() {
    let t = table_from_specs(OVERLAPPING);
    for addr in probe_addrs(OVERLAPPING) {
        assert_eq!(
            t.resolve(addr).map(|a| a.to_string()),
            reference_resolve(OVERLAPPING, addr),
            "mismatch for {addr}"
        );
    }
}

#[test]
fn resolve_matches_linear_scan_with_many_same_length_prefixes() {
    // 256 sibling /24s under one /8: everything lands in a single
    // prefix-length group, which is exactly what a binary search must get
    // right — including the misses between the populated networks. Only even
    // third octets are populated, so half the probes fall into the gaps.
    let mut specs: Vec<(String, String)> = vec![("wide".to_string(), "10.0.0.0/8".to_string())];
    for i in 0..256u32 {
        let second = i / 128;
        let third = 2 * (i % 128);
        specs.push((format!("n{i}"), format!("10.{second}.{third}.0/24")));
    }
    let flat: Vec<(&str, &str)> = specs.iter().map(|(a, c)| (a.as_str(), c.as_str())).collect();
    let t = table_from_specs(&flat);

    for second in 0..2u8 {
        for third in 0..=255u8 {
            let addr = IpAddr::from(Ipv4Addr::new(10, second, third, 42));
            assert_eq!(
                t.resolve(addr).map(|a| a.to_string()),
                reference_resolve(&flat, addr),
                "mismatch for {addr}"
            );
        }
    }
    // Outside the /8 entirely.
    assert_eq!(resolve(&t, "11.0.0.1"), None);
}

#[test]
fn zero_prefix_is_a_catch_all_that_loses_to_longer_matches() {
    let specs: &[(&str, &str)] = &[("any", "0.0.0.0/0"), ("net", "192.0.2.0/24"), ("any6", "::/0")];
    let t = table_from_specs(specs);
    assert_eq!(resolve(&t, "192.0.2.7"), Some("net".to_string()));
    assert_eq!(resolve(&t, "8.8.8.8"), Some("any".to_string()));
    assert_eq!(resolve(&t, "2001:db8::1"), Some("any6".to_string()));
    for addr in probe_addrs(specs) {
        assert_eq!(t.resolve(addr).map(|a| a.to_string()), reference_resolve(specs, addr));
    }
}
