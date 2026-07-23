//! Bounds and invalidation of the sniffed-SNI memory: it must never grow past
//! its cap, never serve an entry across a routing-rule reload, and never serve
//! one older than its TTL.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;
use crate::wire::IpVersion;

const TTL: Duration = Duration::from_secs(300);

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
fn recalls_domain_for_same_flow_key() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(4, TTL);
    cache.remember(&key(40000), "video.example.com", 7, now);

    assert_eq!(cache.recall(&key(40000), 7, now).as_deref(), Some("video.example.com"));
    // A different client port is a different connection: no route to inherit.
    assert!(cache.recall(&key(40001), 7, now).is_none());
}

#[test]
fn cap_evicts_least_recently_used_entry() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(2, TTL);
    cache.remember(&key(1), "a.example.com", 0, now);
    cache.remember(&key(2), "b.example.com", 0, now);
    // Touch the oldest so the *next* insert evicts key(2), not key(1).
    assert!(cache.recall(&key(1), 0, now).is_some());
    cache.remember(&key(3), "c.example.com", 0, now);

    assert_eq!(cache.len(), 2, "cache must never exceed its cap");
    assert!(cache.recall(&key(2), 0, now).is_none(), "LRU entry must be evicted");
    assert!(cache.recall(&key(1), 0, now).is_some());
    assert!(cache.recall(&key(3), 0, now).is_some());
}

#[test]
fn routing_table_reload_invalidates_entry() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(4, TTL);
    cache.remember(&key(40010), "video.example.com", 3, now);

    // Version bumped by a rule reload: the remembered domain predates the
    // current rules and must not steer anything.
    assert!(cache.recall(&key(40010), 4, now).is_none());
    // ...and the stale entry is dropped rather than lingering until its TTL.
    assert_eq!(cache.len(), 0);
}

#[test]
fn entry_expires_after_ttl() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(4, TTL);
    cache.remember(&key(40020), "video.example.com", 0, now);

    assert!(cache.recall(&key(40020), 0, now + TTL).is_none(), "TTL must be enforced");
    assert_eq!(cache.len(), 0, "an expired entry must be dropped, not kept");
}

#[test]
fn entry_survives_right_up_to_the_ttl() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(4, TTL);
    cache.remember(&key(40025), "video.example.com", 0, now);

    assert!(
        cache
            .recall(&key(40025), 0, now + TTL - Duration::from_secs(1))
            .is_some()
    );
}

#[test]
fn hit_refreshes_the_ttl() {
    let now = Instant::now();
    let mut cache = SniRouteCache::new(4, TTL);
    cache.remember(&key(40030), "video.example.com", 0, now);

    // A connection that keeps rebuilding its flow keeps its route: the TTL is
    // idle-based, restarted by each hit rather than counted from the original
    // sniff. Two gaps just under the TTL therefore both hit, even though their
    // sum is well past it.
    let first = now + TTL - Duration::from_secs(1);
    let second = first + TTL - Duration::from_secs(1);
    assert!(cache.recall(&key(40030), 0, first).is_some());
    assert!(cache.recall(&key(40030), 0, second).is_some());
    // ...and a full TTL of silence *after the last hit* still expires it.
    assert!(cache.recall(&key(40030), 0, second + TTL).is_none());
}
