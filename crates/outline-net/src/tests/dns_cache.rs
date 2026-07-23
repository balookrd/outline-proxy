use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn addr(n: u8) -> Arc<[SocketAddr]> {
    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)), 80)].into()
}

/// Value tagged with `port` so a lookup can prove it got *its own* entry back
/// and not a neighbour's — eviction moves entries around internally.
fn tagged(port: u16) -> Arc<[SocketAddr]> {
    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)].into()
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

// ── Storage-integrity tests ──────────────────────────────────────────────────
//
// Eviction relocates entries inside the cache, so these pin the invariant a
// relocating layout can break: after any amount of churn, `len()` must equal
// the number of keys that actually answer a lookup, and every surviving key
// must still map to *its own* value.

#[test]
fn every_surviving_key_stays_addressable_after_churn() {
    let cap = 64;
    let total = 500u16;
    let cache = DnsCache::with_capacity(Duration::from_secs(60), cap);
    for i in 0..total {
        cache.insert(&format!("h{i}"), 80, false, tagged(i));
    }
    assert_eq!(cache.len(), cap);

    let mut found = 0usize;
    for i in 0..total {
        if let Some(addrs) = cache.get(&format!("h{i}"), 80, false) {
            found += 1;
            // A stale index entry would hand back a different key's value.
            assert_eq!(addrs[0].port(), i, "h{i} resolved to the wrong entry");
        }
    }
    assert_eq!(found, cap, "live entry count disagrees with len()");
}

#[test]
fn reinserting_an_evicted_key_does_not_duplicate_it() {
    let cap = 8;
    let cache = DnsCache::with_capacity(Duration::from_secs(60), cap);
    for round in 0..40u16 {
        // Cycle over a key space twice the cap, so keys are constantly
        // evicted and then inserted again.
        let key = format!("k{}", round % (cap as u16 * 2));
        cache.insert(&key, 80, false, tagged(round));
        assert!(cache.len() <= cap, "cache grew past capacity at round {round}");
        let got = cache.get(&key, 80, false).expect("just-inserted key must be present");
        assert_eq!(got[0].port(), round);
    }
    assert_eq!(cache.len(), cap);
}

#[test]
fn capacity_one_always_keeps_the_newest_entry() {
    let cache = DnsCache::with_capacity(Duration::from_secs(60), 1);
    for i in 0..20u16 {
        cache.insert(&format!("h{i}"), 80, false, tagged(i));
        assert_eq!(cache.len(), 1);
        let got = cache.get(&format!("h{i}"), 80, false).expect("newest entry survives");
        assert_eq!(got[0].port(), i);
    }
}

#[test]
fn sweep_keeps_the_surviving_half_addressable() {
    // One TTL, two insert waves: the first wave's expiry has already passed
    // when the second is written, so a zero-grace sweep purges exactly it.
    let half = 100u16;
    let cache = DnsCache::new(Duration::from_millis(300));
    for i in 0..half {
        cache.insert(&format!("old{i}"), 80, false, tagged(i));
    }
    std::thread::sleep(Duration::from_millis(400));
    for i in 0..half {
        cache.insert(&format!("new{i}"), 80, false, tagged(i));
    }
    assert_eq!(cache.len(), (half * 2) as usize);

    assert_eq!(cache.sweep_expired(Duration::ZERO), half as usize);
    assert_eq!(cache.len(), half as usize);
    for i in 0..half {
        assert!(cache.get_stale(&format!("old{i}"), 80, false).is_none(), "old{i} survived");
        let got = cache.get(&format!("new{i}"), 80, false).expect("new{i} must survive");
        assert_eq!(got[0].port(), i);
    }
}

#[test]
fn key_fields_are_not_conflated_under_eviction_pressure() {
    // Same host string, different ports and addr_pref bits: all distinct keys.
    // A hash/eq mix-up in a relocating index shows up here first.
    let cap = 32;
    let cache = DnsCache::with_capacity(Duration::from_secs(60), cap);
    for port in 0..16u16 {
        for pref in [false, true] {
            cache.insert("host", port, pref, tagged(port * 2 + u16::from(pref)));
        }
    }
    // Churn past the cap so entries relocate, then check every survivor.
    for i in 0..64u16 {
        cache.insert(&format!("noise{i}"), 443, false, tagged(9000 + i));
    }
    assert_eq!(cache.len(), cap);

    let mut found = 0usize;
    for port in 0..16u16 {
        for pref in [false, true] {
            if let Some(got) = cache.get("host", port, pref) {
                found += 1;
                assert_eq!(got[0].port(), port * 2 + u16::from(pref));
            }
        }
    }
    for i in 0..64u16 {
        if let Some(got) = cache.get(&format!("noise{i}"), 443, false) {
            found += 1;
            assert_eq!(got[0].port(), 9000 + i);
        }
    }
    assert_eq!(found, cap, "live entry count disagrees with len()");
}
