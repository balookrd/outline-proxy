use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Live, PeerPool};

struct MockPeer {
    live: AtomicBool,
    id: u32,
}

impl MockPeer {
    fn new(id: u32) -> Arc<Self> {
        Arc::new(Self { live: AtomicBool::new(true), id })
    }
    fn kill(&self) {
        self.live.store(false, Ordering::Relaxed);
    }
}

impl Live for MockPeer {
    fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }
}

fn pool(max: usize) -> Arc<PeerPool<MockPeer>> {
    PeerPool::new(Arc::from("reverse"), max)
}

#[test]
fn insert_and_pick_single() {
    let p = pool(8);
    assert!(p.try_insert(MockPeer::new(1)));
    assert_eq!(p.live_count(), 1);
    assert_eq!(p.pick_live().unwrap().id, 1);
}

#[test]
fn empty_pool_picks_none() {
    let p = pool(8);
    assert!(p.pick_live().is_none());
    assert_eq!(p.live_count(), 0);
}

#[test]
fn round_robin_spreads_across_live_peers() {
    let p = pool(8);
    p.try_insert(MockPeer::new(1));
    p.try_insert(MockPeer::new(2));
    p.try_insert(MockPeer::new(3));
    // Three live peers, cursor advances each pick → see all three ids.
    let ids: Vec<u32> = (0..3).map(|_| p.pick_live().unwrap().id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![1, 2, 3]);
}

#[test]
fn dead_peer_is_evicted_on_pick_and_count() {
    let p = pool(8);
    let a = MockPeer::new(1);
    let b = MockPeer::new(2);
    p.try_insert(Arc::clone(&a));
    p.try_insert(Arc::clone(&b));
    a.kill();
    assert_eq!(p.live_count(), 1);
    for _ in 0..5 {
        assert_eq!(p.pick_live().unwrap().id, 2);
    }
    b.kill();
    assert!(p.pick_live().is_none());
}

#[test]
fn capacity_rejects_excess_but_reclaims_dead_slots() {
    let p = pool(2);
    let a = MockPeer::new(1);
    p.try_insert(Arc::clone(&a));
    assert!(p.try_insert(MockPeer::new(2)));
    // At capacity (2 live) → third rejected.
    assert!(!p.try_insert(MockPeer::new(3)));
    // Kill one → a dead slot is reclaimed, insert succeeds again.
    a.kill();
    assert!(p.try_insert(MockPeer::new(4)));
    assert_eq!(p.live_count(), 2);
}
