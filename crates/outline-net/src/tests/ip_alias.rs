use super::*;
use std::net::IpAddr;

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
