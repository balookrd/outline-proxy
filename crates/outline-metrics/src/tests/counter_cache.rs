//! Tests for [`crate::FailoverCounter`]: the `(group, uplink)` handle cache
//! must re-resolve onto the new series when a flow fails over mid-stream, and
//! must not re-resolve while the label `Arc`s stay ptr-stable.
//!
//! These assert on absolute counter values, so they must hold [`test_guard`]:
//! `init()` calls `bytes_total.reset()`, which drops *every* child series of the
//! vec — unique labels are no defence. Racing an `init()` test would orphan the
//! cached handle (it keeps incrementing a detached `IntCounter`) while the
//! assertion re-creates the series at zero.

use std::sync::Arc;

use super::test_guard;
use crate::{FailoverCounter, flow_bytes_counter};

fn down_bytes_series(group: &str, uplink: &str) -> u64 {
    crate::METRICS
        .bytes_total
        .with_label_values(&["tcp", "down", group, uplink])
        .get()
}

#[test]
fn reresolves_on_uplink_change_and_leaves_old_series_frozen() {
    let _guard = test_guard();
    let group: Arc<str> = Arc::from("fo_grp");
    let uplink_a: Arc<str> = Arc::from("fo_up_a");
    let uplink_b: Arc<str> = Arc::from("fo_up_b");

    let mut cache = FailoverCounter::new();

    // Two writes on uplink A share the cached handle.
    cache
        .get(&group, &uplink_a, |g, u| flow_bytes_counter("tcp", "down", g, u))
        .add(100);
    cache
        .get(&group, &uplink_a, |g, u| flow_bytes_counter("tcp", "down", g, u))
        .add(200);
    assert_eq!(down_bytes_series("fo_grp", "fo_up_a"), 300);

    // A mid-flow failover installs a *new* uplink `Arc`; the handle re-resolves
    // onto B's series, and A's series must stop growing.
    cache
        .get(&group, &uplink_b, |g, u| flow_bytes_counter("tcp", "down", g, u))
        .add(50);
    assert_eq!(down_bytes_series("fo_grp", "fo_up_b"), 50);
    assert_eq!(down_bytes_series("fo_grp", "fo_up_a"), 300);

    // Failing back (a fresh `Arc` carrying A's name again) targets A once more.
    let uplink_a_again: Arc<str> = Arc::from("fo_up_a");
    cache
        .get(&group, &uplink_a_again, |g, u| flow_bytes_counter("tcp", "down", g, u))
        .add(10);
    assert_eq!(down_bytes_series("fo_grp", "fo_up_a"), 310);
    assert_eq!(down_bytes_series("fo_grp", "fo_up_b"), 50);
}

#[test]
fn resolves_once_while_labels_are_ptr_stable() {
    let _guard = test_guard();
    let group: Arc<str> = Arc::from("fo_resolve_grp");
    let uplink_a: Arc<str> = Arc::from("fo_resolve_a");
    let uplink_b: Arc<str> = Arc::from("fo_resolve_b");

    let mut cache = FailoverCounter::new();
    let mut resolves = 0u32;

    // Same `(group, uplink)` identity twice ⇒ resolve exactly once.
    cache
        .get(&group, &uplink_a, |g, u| {
            resolves += 1;
            flow_bytes_counter("tcp", "down", g, u)
        })
        .add(1);
    cache
        .get(&group, &uplink_a, |g, u| {
            resolves += 1;
            flow_bytes_counter("tcp", "down", g, u)
        })
        .add(1);
    assert_eq!(resolves, 1, "ptr-stable key must not re-resolve");

    // A different uplink `Arc` forces a re-resolve.
    cache
        .get(&group, &uplink_b, |g, u| {
            resolves += 1;
            flow_bytes_counter("tcp", "down", g, u)
        })
        .add(1);
    assert_eq!(resolves, 2, "changed uplink must re-resolve");

    // Back to the (still-alive) B key ⇒ no further resolve.
    cache
        .get(&group, &uplink_b, |g, u| {
            resolves += 1;
            flow_bytes_counter("tcp", "down", g, u)
        })
        .add(1);
    assert_eq!(resolves, 2, "stable key after switch must not re-resolve");
}

#[test]
fn caches_across_ptr_stable_arc_clones() {
    // Cloning an `Arc` preserves its allocation pointer, so passing fresh clones
    // of a stable label each call (as `key_group_and_uplink` does) still hits
    // the cache — the exported value must be exact.
    let _guard = test_guard();
    let group: Arc<str> = Arc::from("fo_stable_grp");
    let uplink: Arc<str> = Arc::from("fo_stable_up");

    let mut cache = FailoverCounter::new();
    for _ in 0..5 {
        cache
            .get(&Arc::clone(&group), &Arc::clone(&uplink), |g, u| {
                flow_bytes_counter("tcp", "down", g, u)
            })
            .add(7);
    }
    assert_eq!(down_bytes_series("fo_stable_grp", "fo_stable_up"), 35);
}
