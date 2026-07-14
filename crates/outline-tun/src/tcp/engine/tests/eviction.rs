use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::wire::IpVersion;

use super::*;

fn key(client_port: u16) -> TcpFlowKey {
    TcpFlowKey {
        version: IpVersion::V4,
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        client_port,
        remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        remote_port: 443,
    }
}

#[test]
fn pop_oldest_follows_activity_updates() {
    let index = FlowEvictionIndex::new();
    let first = key(40000);
    let second = key(40001);
    let now = Instant::now();

    index.upsert(first.clone(), 1, now);
    index.upsert(second.clone(), 2, now + Duration::from_millis(1));
    index.upsert(first.clone(), 1, now + Duration::from_millis(2));

    let evicted = index.pop_oldest().unwrap();
    assert_eq!(evicted.key, second);
    assert_eq!(evicted.flow_id, 2);
    let evicted = index.pop_oldest().unwrap();
    assert_eq!(evicted.key, first);
    assert_eq!(evicted.flow_id, 1);
    assert!(index.pop_oldest().is_none());
}

#[test]
fn remove_drops_entry_from_ordered_index() {
    let index = FlowEvictionIndex::new();
    let first = key(40000);
    let second = key(40001);
    let now = Instant::now();

    index.upsert(first.clone(), 1, now);
    index.upsert(second.clone(), 2, now + Duration::from_millis(1));

    assert!(index.remove(&first, 1));
    assert!(!index.remove(&first, 1));
    let evicted = index.pop_oldest().unwrap();
    assert_eq!(evicted.key, second);
    assert_eq!(evicted.flow_id, 2);
    assert!(index.pop_oldest().is_none());
}

#[test]
fn stale_activity_cannot_replace_newer_flow_generation() {
    let index = FlowEvictionIndex::new();
    let key = key(40000);
    let now = Instant::now();

    index.upsert(key.clone(), 2, now + Duration::from_millis(1));
    index.upsert(key.clone(), 1, now);

    let evicted = index.pop_oldest().unwrap();
    assert_eq!(evicted.key, key);
    assert_eq!(evicted.flow_id, 2);
    assert!(index.pop_oldest().is_none());
}

#[test]
fn refresh_is_quantised_but_keeps_a_busy_flow_ahead_of_an_idle_one() {
    let index = FlowEvictionIndex::new();
    let busy = key(40000);
    let idle = key(40001);
    let start = Instant::now();

    // Both flows are seen at the same moment; `idle` never sends again.
    index.upsert(busy.clone(), 1, start);
    index.upsert(idle.clone(), 2, start + Duration::from_millis(1));

    // `busy` then takes a packet every millisecond for five seconds. The index
    // is only refreshed when the quantum has elapsed, so the 5000 packets cost
    // 5 re-index operations, not 5000.
    let mut indexed_last_seen = start;
    let mut refreshes = 0;
    for tick in 1..=5_000u64 {
        let last_seen = start + Duration::from_millis(tick);
        if eviction_index_needs_refresh(indexed_last_seen, last_seen) {
            indexed_last_seen = last_seen;
            index.upsert(busy.clone(), 1, last_seen);
            refreshes += 1;
        }
    }
    assert_eq!(refreshes, 5, "expected one refresh per elapsed quantum");

    // Eviction order is still correct: the quantised entry of the busy flow is
    // at most one quantum stale, which is far newer than the flow that has been
    // quiet for the whole five seconds.
    let evicted = index.pop_oldest().expect("idle flow is the eviction candidate");
    assert_eq!(evicted.key, idle, "the idle flow must be evicted first");
    let evicted = index.pop_oldest().expect("busy flow evicted only once alone");
    assert_eq!(evicted.key, busy);
    assert!(index.pop_oldest().is_none());
}

#[test]
fn sub_quantum_activity_does_not_reindex() {
    let start = Instant::now();
    assert!(!eviction_index_needs_refresh(start, start));
    assert!(!eviction_index_needs_refresh(
        start,
        start + TCP_EVICTION_INDEX_QUANTUM - Duration::from_millis(1)
    ));
    assert!(eviction_index_needs_refresh(start, start + TCP_EVICTION_INDEX_QUANTUM));
}
