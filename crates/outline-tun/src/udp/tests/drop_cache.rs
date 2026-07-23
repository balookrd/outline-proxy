//! Bounds and invalidation of the dropped-route memory: it must never grow
//! past its cap, never outlive its (absolute, non-refreshing) TTL, and never
//! survive a routing-rule reload — a negative verdict that stuck would keep
//! dropping traffic the operator has just re-allowed.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;
use crate::wire::IpVersion;

const TTL: Duration = Duration::from_secs(10);

fn key(client_port: u16) -> UdpFlowKey {
    UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        local_port: client_port,
        remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        remote_port: 443,
    }
}

#[test]
fn recalls_the_drop_verdict_for_the_same_flow_key() {
    let now = Instant::now();
    let mut cache = DropRouteCache::new(4, TTL);
    cache.remember(&key(40000), 7, now);

    assert!(cache.is_dropped(&key(40000), 7, now));
    // A different client port is a different flow: it gets its own verdict.
    assert!(!cache.is_dropped(&key(40001), 7, now));
}

#[test]
fn cap_evicts_least_recently_used_entry() {
    let now = Instant::now();
    let mut cache = DropRouteCache::new(2, TTL);
    cache.remember(&key(1), 0, now);
    cache.remember(&key(2), 0, now);
    // Touch the oldest so the *next* insert evicts key(2), not key(1).
    assert!(cache.is_dropped(&key(1), 0, now));
    cache.remember(&key(3), 0, now);

    assert_eq!(cache.len(), 2, "cache must never exceed its cap");
    assert!(!cache.is_dropped(&key(2), 0, now), "LRU entry must be evicted");
    assert!(cache.is_dropped(&key(1), 0, now));
    assert!(cache.is_dropped(&key(3), 0, now));
}

#[test]
fn routing_table_reload_invalidates_entry() {
    let now = Instant::now();
    let mut cache = DropRouteCache::new(4, TTL);
    cache.remember(&key(40010), 3, now);

    // The rules that produced the drop are gone: the verdict must be re-taken
    // against the live table, not replayed from before the reload.
    assert!(!cache.is_dropped(&key(40010), 4, now));
    assert_eq!(cache.len(), 0, "a stale entry must be dropped, not left to age out");
}

#[test]
fn entry_expires_after_ttl() {
    let now = Instant::now();
    let mut cache = DropRouteCache::new(4, TTL);
    cache.remember(&key(40020), 0, now);

    assert!(cache.is_dropped(&key(40020), 0, now + TTL - Duration::from_secs(1)));
    assert!(!cache.is_dropped(&key(40020), 0, now + TTL), "TTL must be enforced");
    assert_eq!(cache.len(), 0, "an expired entry must be dropped, not kept");
}

/// Unlike the sniffed-SNI memory, a hit must NOT restart the clock. This is a
/// negative verdict: a client that keeps hammering a dropped destination would
/// otherwise refresh its own entry forever and never let the engine re-check
/// the routing table.
#[test]
fn a_hit_does_not_refresh_the_ttl() {
    let now = Instant::now();
    let mut cache = DropRouteCache::new(4, TTL);
    cache.remember(&key(40030), 0, now);

    let midway = now + TTL / 2;
    assert!(cache.is_dropped(&key(40030), 0, midway));
    assert!(
        !cache.is_dropped(&key(40030), 0, now + TTL),
        "the TTL runs from the verdict, so a steady stream of datagrams cannot pin it",
    );
}
