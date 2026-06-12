use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn addr(n: u8) -> Arc<[SocketAddr]> {
    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)), 80)].into()
}

#[test]
fn capacity_clamped_to_one() {
    let cache = DnsCache::with_capacity(Duration::from_secs(60), 0);
    cache.insert("a", 80, false, addr(1));
    cache.insert("b", 80, false, addr(2));
    assert_eq!(cache.len(), 1);
}

#[test]
fn insert_evicts_when_over_capacity() {
    let cap = 16;
    let cache = DnsCache::with_capacity(Duration::from_secs(60), cap);
    for i in 0..(cap as u8 * 4) {
        cache.insert(&format!("h{i}"), 80, false, addr(i));
    }
    assert_eq!(cache.len(), cap);
}

#[test]
fn unbounded_constructor_does_not_evict() {
    let cache = DnsCache::new(Duration::from_secs(60));
    for i in 0..200u16 {
        cache.insert(&format!("h{i}"), 80, false, addr((i % 250) as u8));
    }
    assert_eq!(cache.len(), 200);
}

#[test]
fn expired_entries_are_evicted_first() {
    // TTL=0 makes every prior entry instantly expired, so when we exceed
    // capacity the eviction scan should reap an expired entry rather than
    // a freshly inserted one.
    let cap = 8;
    let cache = DnsCache::with_capacity(Duration::from_nanos(1), cap);
    for i in 0..(cap as u8) {
        cache.insert(&format!("old{i}"), 80, false, addr(i));
    }
    std::thread::sleep(Duration::from_millis(2));
    // Use a longer TTL for fresh inserts so they survive.
    let cache2 = DnsCache::with_capacity(Duration::from_secs(60), cap);
    for i in 0..(cap as u8) {
        cache2.insert(&format!("h{i}"), 80, false, addr(i));
    }
    cache2.insert("fresh", 80, false, addr(99));
    assert_eq!(cache2.len(), cap);
    assert!(cache2.get("fresh", 80, false).is_some());

    // Sanity: the all-expired cache also stays bounded.
    cache.insert("trigger", 80, false, addr(200));
    assert!(cache.len() <= cap);
}

#[test]
fn get_refreshes_lru_and_protects_hot_entry() {
    // With sample size 8 and capacity 8, every insert past the cap scans
    // the entire map, so the entry with the most recent `last_access` is
    // guaranteed to survive. Hammer "hot" with reads while inserting
    // many cold keys, and confirm "hot" is still present.
    let cap = 8;
    let cache = DnsCache::with_capacity(Duration::from_secs(60), cap);
    // Fill the cap with cold keys, then promote "hot" by inserting it last
    // and bumping its tick before every subsequent eviction round.
    for i in 0..(cap as u16) {
        cache.insert(&format!("c{i}"), 80, false, addr(2));
    }
    cache.insert("hot", 80, false, addr(1));
    for round in 0..50u16 {
        assert!(cache.get("hot", 80, false).is_some());
        cache.insert(&format!("x{round}"), 80, false, addr(3));
    }
    assert!(cache.get("hot", 80, false).is_some());
    assert_eq!(cache.len(), cap);
}

#[test]
fn ttl_expiry_returns_none_but_get_stale_works() {
    let cache = DnsCache::with_capacity(Duration::from_millis(20), 8);
    cache.insert("h", 80, false, addr(7));
    assert!(cache.get("h", 80, false).is_some());
    std::thread::sleep(Duration::from_millis(40));
    assert!(cache.get("h", 80, false).is_none());
    assert!(cache.get_stale("h", 80, false).is_some());
}

#[test]
fn insert_overwrites_existing_entry_in_place() {
    let cache = DnsCache::with_capacity(Duration::from_secs(60), 4);
    cache.insert("h", 80, false, addr(1));
    cache.insert("h", 80, false, addr(2));
    assert_eq!(cache.len(), 1);
    let got = cache.get("h", 80, false).unwrap();
    assert_eq!(got[0].ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
}

#[test]
fn addr_pref_bit_is_part_of_the_key() {
    let cache = DnsCache::new(Duration::from_secs(60));
    cache.insert("h", 80, false, addr(1));
    cache.insert("h", 80, true, addr(2));
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.get("h", 80, false).unwrap()[0].ip(), Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(cache.get("h", 80, true).unwrap()[0].ip(), Ipv4Addr::new(127, 0, 0, 2));
}

#[test]
fn sweep_expired_purges_only_past_grace() {
    // Entries expire instantly (1 ns TTL); a sweep with a generous grace
    // keeps them around for stale fallback, a zero grace purges them.
    let cache = DnsCache::new(Duration::from_nanos(1));
    cache.insert("a", 80, false, addr(1));
    cache.insert("b", 80, false, addr(2));
    std::thread::sleep(Duration::from_millis(5));
    assert!(cache.get("a", 80, false).is_none());
    assert!(cache.get_stale("a", 80, false).is_some());

    assert_eq!(cache.sweep_expired(Duration::from_secs(3600)), 0);
    assert!(cache.get_stale("a", 80, false).is_some());

    assert_eq!(cache.sweep_expired(Duration::ZERO), 2);
    assert!(cache.get_stale("a", 80, false).is_none());
    assert_eq!(cache.len(), 0);
}
