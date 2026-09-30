use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[tokio::test]
async fn test_resolve_localhost_ipv4_only() {
    let cache = DnsCache::new(std::time::Duration::from_secs(60));
    let addrs = resolve_host_with_preference(&cache, "localhost", 80, "test", false, true)
        .await
        .expect("localhost should resolve");

    assert!(!addrs.is_empty(), "resolved addresses should not be empty");
    for addr in addrs.iter() {
        assert!(addr.is_ipv4(), "all addresses must be IPv4 when ipv4_only is true, got {addr}");
    }

    // Verify it is served from cache
    let cached = cache.get("localhost", 80, AddrPreference::from_client_flags(false, true));
    assert!(cached.is_some(), "entry must be cached under IPV4_ONLY preference");
    assert_eq!(cached.unwrap(), addrs);
}

#[tokio::test]
async fn test_resolve_preferences_cache_separation() {
    let cache = DnsCache::new(std::time::Duration::from_secs(60));
    let host = "test-host.example.com";
    let port = 8080;

    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), port);

    // Pre-populate cache directly with different preference keys
    let pref_v4_only = AddrPreference::from_client_flags(false, true);
    let pref_v6_first = AddrPreference::from_client_flags(true, false);
    let pref_v4_first = AddrPreference::from_client_flags(false, false);

    cache.insert(host, port, pref_v4_only, Arc::new([v4]));
    cache.insert(host, port, pref_v6_first, Arc::new([v6, v4]));
    cache.insert(host, port, pref_v4_first, Arc::new([v4, v6]));

    let r_v4_only = resolve_host_with_preference(&cache, host, port, "test", false, true)
        .await
        .unwrap();
    assert_eq!(r_v4_only.len(), 1);
    assert_eq!(r_v4_only[0], v4);

    let r_v6_first = resolve_host_with_preference(&cache, host, port, "test", true, false)
        .await
        .unwrap();
    assert_eq!(r_v6_first.len(), 2);
    assert_eq!(r_v6_first[0], v6);

    let r_v4_first = resolve_host_with_preference(&cache, host, port, "test", false, false)
        .await
        .unwrap();
    assert_eq!(r_v4_first.len(), 2);
    assert_eq!(r_v4_first[0], v4);
}
