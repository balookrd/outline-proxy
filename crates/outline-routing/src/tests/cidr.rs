use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

fn v4(a: u8, b: u8, c: u8, d: u8) -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(a, b, c, d), 80)
}

fn v6(s: &str) -> TargetAddr {
    TargetAddr::IpV6(s.parse::<Ipv6Addr>().unwrap(), 80)
}

fn set(prefixes: &[&str]) -> CidrSet {
    CidrSet::parse(&prefixes.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
}

#[test]
fn cidr_v4_basic() {
    let s = set(&["192.168.0.0/16"]);
    assert!(s.contains(&v4(192, 168, 0, 0)));
    assert!(s.contains(&v4(192, 168, 1, 1)));
    assert!(s.contains(&v4(192, 168, 255, 255)));
    assert!(!s.contains(&v4(192, 169, 0, 0)));
    assert!(!s.contains(&v4(192, 167, 255, 255)));
}

#[test]
fn host_route_v4() {
    let s = set(&["8.8.8.8"]);
    assert!(s.contains(&v4(8, 8, 8, 8)));
    assert!(!s.contains(&v4(8, 8, 8, 7)));
    assert!(!s.contains(&v4(8, 8, 8, 9)));
}

#[test]
fn default_route() {
    let s = set(&["0.0.0.0/0"]);
    assert!(s.contains(&v4(0, 0, 0, 0)));
    assert!(s.contains(&v4(1, 2, 3, 4)));
    assert!(s.contains(&v4(255, 255, 255, 255)));
}

#[test]
fn multiple_prefixes_merged() {
    let s = set(&["10.0.0.0/25", "10.0.0.128/25"]);
    assert!(s.contains(&v4(10, 0, 0, 0)));
    assert!(s.contains(&v4(10, 0, 0, 127)));
    assert!(s.contains(&v4(10, 0, 0, 128)));
    assert!(s.contains(&v4(10, 0, 0, 255)));
    assert!(!s.contains(&v4(10, 0, 1, 0)));
    assert_eq!(s.v4_range_count(), 1);
}

#[test]
fn overlapping_prefixes_merged() {
    let s = set(&["10.0.0.0/8", "10.1.0.0/16"]);
    assert!(s.contains(&v4(10, 1, 0, 1)));
    assert_eq!(s.v4_range_count(), 1);
}

#[test]
fn cidr_v6() {
    let s = set(&["fc00::/7"]);
    assert!(s.contains(&v6("fc00::1")));
    assert!(s.contains(&v6("fdff:ffff:ffff:ffff::1")));
    assert!(!s.contains(&v6("fe00::1")));
    assert!(!s.contains(&v6("2001:db8::1")));
}

#[test]
fn domain_never_matches() {
    let s = set(&["0.0.0.0/0"]);
    assert!(!s.contains(&TargetAddr::Domain("example.com".to_string(), 80)));
}

#[test]
fn boundary_v4() {
    let s = set(&["10.0.0.0/8"]);
    assert!(s.contains(&v4(10, 0, 0, 0)));
    assert!(s.contains(&v4(10, 255, 255, 255)));
    assert!(!s.contains(&v4(9, 255, 255, 255)));
    assert!(!s.contains(&v4(11, 0, 0, 0)));
}

#[test]
fn parse_error_bad_addr() {
    assert!(CidrSet::parse(&["notanip/24".to_string()]).is_err());
}

#[test]
fn parse_error_prefix_too_long() {
    assert!(CidrSet::parse(&["1.2.3.4/33".to_string()]).is_err());
}
