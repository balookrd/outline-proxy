//! Unit tests for the SS-UDP-over-WS stream state that lives in
//! `server::transport::udp` — currently the bounded set of NAT keys a stream
//! owns.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{NAT_KEYS_RECONCILE_FLOOR, StreamNatKeys};
use crate::server::nat::NatKey;

fn key(port: u16) -> NatKey {
    let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid target");
    NatKey {
        user_id: Arc::from("user"),
        fwmark: None,
        target,
        scope: None,
    }
}

#[test]
fn tracking_below_the_threshold_keeps_every_key() {
    let mut keys = StreamNatKeys::new();
    for port in 0..8u16 {
        keys.track(key(port), |_| true);
    }
    assert_eq!(keys.len(), 8);
}

#[test]
fn duplicate_targets_are_deduplicated() {
    let mut keys = StreamNatKeys::new();
    for _ in 0..100 {
        keys.track(key(1), |_| true);
    }
    assert_eq!(keys.len(), 1);
}

#[test]
fn evicted_nat_entries_are_reconciled_away() {
    // A long-lived stream touching a stream of one-shot targets: every NAT
    // entry but the most recent has since been idle-evicted. The tracked set
    // must not grow without bound.
    let mut keys = StreamNatKeys::new();
    let mut live: Option<NatKey> = None;
    for port in 0..1000u16 {
        let key = key(port);
        live = Some(key.clone());
        let live_key = live.clone().expect("just set");
        keys.track(key, |candidate| *candidate == live_key);
        assert!(
            keys.len() <= NAT_KEYS_RECONCILE_FLOOR,
            "tracked set grew past the reconcile threshold: {}",
            keys.len()
        );
    }
    // The surviving key is the one whose NAT entry is still live.
    let parked: HashSet<NatKey> = keys.take();
    assert!(parked.contains(&live.expect("at least one key tracked")));
}

#[test]
fn live_keys_survive_reconciliation_and_raise_the_threshold() {
    // Every entry stays live: reconciliation must keep all of them and re-arm
    // at twice the live count, so the sweep stays amortised.
    let mut keys = StreamNatKeys::new();
    let total = NAT_KEYS_RECONCILE_FLOOR * 3;
    for port in 0..total as u16 {
        keys.track(key(port), |_| true);
    }
    assert_eq!(keys.len(), total);
}

#[test]
fn take_drains_the_set_and_resets_the_threshold() {
    let mut keys = StreamNatKeys::new();
    for port in 0..4u16 {
        keys.track(key(port), |_| true);
    }
    let drained = keys.take();
    assert_eq!(drained.len(), 4);
    assert_eq!(keys.len(), 0);

    // Re-armed at the floor: a fresh run of dead targets is reconciled again.
    for port in 100..(100 + NAT_KEYS_RECONCILE_FLOOR as u16 + 1) {
        keys.track(key(port), |_| false);
    }
    assert!(keys.len() <= 1, "reconcile did not re-arm after take: {}", keys.len());
}

#[test]
fn adopted_resume_keys_are_tracked() {
    let mut keys = StreamNatKeys::new();
    keys.adopt(vec![key(1), key(2)]);
    assert_eq!(keys.len(), 2);
    assert!(keys.take().contains(&key(2)));
}
