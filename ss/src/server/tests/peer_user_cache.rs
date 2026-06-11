use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn v4(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
}

#[test]
fn lookup_after_record_returns_index() {
    let cache = PeerUserCache::with_capacity(8);
    let peer = v4(54321);
    cache.record(peer, 42);
    assert_eq!(cache.lookup(peer), Some(42));
}

#[test]
fn lookup_unknown_peer_misses() {
    let cache = PeerUserCache::with_capacity(8);
    cache.record(v4(1234), 7);
    assert_eq!(cache.lookup(v4(5678)), None);
}

#[test]
fn record_overwrites_previous_index() {
    let cache = PeerUserCache::with_capacity(8);
    let peer = v4(9000);
    cache.record(peer, 1);
    cache.record(peer, 2);
    assert_eq!(cache.lookup(peer), Some(2));
}

#[test]
fn ipv4_and_ipv6_with_same_port_are_distinct() {
    let cache = PeerUserCache::with_capacity(8);
    cache.record(v4(8080), 1);
    cache.record(v6(8080), 2);
    assert_eq!(cache.lookup(v4(8080)), Some(1));
    assert_eq!(cache.lookup(v6(8080)), Some(2));
}

#[test]
fn capacity_is_bounded() {
    // Per-shard cap = ceil(total / SHARD_COUNT). Insert far more than
    // total_capacity distinct peers and verify the aggregate population
    // never exceeds per_shard_cap * SHARD_COUNT. Distribution between
    // shards is hash-determined; what matters is that no shard grows
    // unbounded.
    let total = 64usize;
    let cache = PeerUserCache::with_capacity(total);
    let per_shard_cap = total.div_ceil(SHARD_COUNT).max(1);
    let upper_bound = per_shard_cap * SHARD_COUNT;
    for port in 0u16..1024 {
        cache.record(v4(port), port as usize);
    }
    assert!(
        cache.len() <= upper_bound,
        "len={} exceeds upper_bound={}",
        cache.len(),
        upper_bound
    );
}
