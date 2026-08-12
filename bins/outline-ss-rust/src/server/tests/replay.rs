use std::sync::Arc;

use super::*;

/// Distinct authenticated user id for the store-level tests.
fn user(n: u8) -> Arc<str> {
    Arc::from(format!("user-{n}"))
}

#[test]
fn fresh_packet_ids_accepted_in_order() {
    let mut w = ReplayWindow::new();
    for id in 0..100 {
        assert!(w.check_and_mark(id), "id={id}");
    }
}

#[test]
fn immediate_duplicate_rejected() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(42));
    assert!(!w.check_and_mark(42));
}

#[test]
fn reordered_within_window_accepted_once() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(10));
    assert!(w.check_and_mark(20));
    assert!(w.check_and_mark(15)); // reordered
    assert!(!w.check_and_mark(15)); // replay
}

#[test]
fn old_packet_outside_window_rejected() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(5));
    assert!(w.check_and_mark(5 + WINDOW_BITS + 10));
    assert!(!w.check_and_mark(5)); // shifted out
}

#[test]
fn big_jump_does_not_preserve_old_bits() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(10));
    assert!(w.check_and_mark(10 + WINDOW_BITS + 100));
    // id 10 is now far outside the window
    assert!(!w.check_and_mark(10));
    // id equal to new highest is a replay
    assert!(!w.check_and_mark(10 + WINDOW_BITS + 100));
}

#[test]
fn store_isolates_sessions() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    let a = [1_u8; 8];
    let b = [2_u8; 8];
    assert_eq!(store.check_and_mark(&u, a, 7), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(&u, b, 7), ReplayCheck::Fresh); // different session, same id ok
    assert_eq!(store.check_and_mark(&u, a, 7), ReplayCheck::Replay);
    assert_eq!(store.check_and_mark(&u, b, 7), ReplayCheck::Replay);
}

#[test]
fn store_rejects_new_sessions_when_at_global_cap() {
    // Per-user cap disabled: only the global cap can fire, and it reports `Global`.
    let store = ReplayStore::new(Duration::from_secs(60), 2, 0);
    let u = user(1);
    let a = [1_u8; 8];
    let b = [2_u8; 8];
    let c = [3_u8; 8];
    assert_eq!(store.check_and_mark(&u, a, 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(&u, b, 1), ReplayCheck::Fresh);
    // Third distinct csid spills over the global cap and is dropped.
    assert_eq!(store.check_and_mark(&u, c, 1), ReplayCheck::StoreFull(ReplayFull::Global));
    // Already-known sessions continue to work at the cap.
    assert_eq!(store.check_and_mark(&u, a, 2), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(&u, a, 2), ReplayCheck::Replay);
}

#[test]
fn store_cap_zero_disables_limit() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    for i in 0..1_000_u16 {
        let mut csid = [0_u8; 8];
        csid[..2].copy_from_slice(&i.to_be_bytes());
        assert_eq!(store.check_and_mark(&u, csid, 1), ReplayCheck::Fresh);
    }
}

#[test]
fn window_boundary_at_edge() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(2000));
    // id = highest - (WINDOW_BITS - 1): inside window
    assert!(w.check_and_mark(2000 - (WINDOW_BITS - 1)));
    // id = highest - WINDOW_BITS: outside
    assert!(!w.check_and_mark(2000 - WINDOW_BITS));
}

#[test]
fn replay_across_word_boundary() {
    let mut w = ReplayWindow::new();
    assert!(w.check_and_mark(100));
    assert!(w.check_and_mark(100 + 65)); // spans across word boundary on shift
    assert!(!w.check_and_mark(100)); // must still be detected
}

#[test]
fn legacy_salt_fresh_then_replay() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    let salt = [7_u8; 32];
    assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Replay);
}

#[test]
fn legacy_salt_distinct_salts_are_independent() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    let a = [1_u8; 32];
    let mut b = [1_u8; 32];
    b[0] = 2;
    assert_eq!(store.check_and_mark_legacy_salt(&u, a), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&u, b), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&u, a), ReplayCheck::Replay);
}

#[test]
fn legacy_salt_rejects_new_salts_at_global_cap() {
    let store = ReplayStore::new(Duration::from_secs(60), 2, 0);
    let u = user(1);
    let a = [1_u8; 32];
    let b = [2_u8; 32];
    let c = [3_u8; 32];
    assert_eq!(store.check_and_mark_legacy_salt(&u, a), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&u, b), ReplayCheck::Fresh);
    // A third distinct salt spills over the global cap and is dropped.
    assert_eq!(
        store.check_and_mark_legacy_salt(&u, c),
        ReplayCheck::StoreFull(ReplayFull::Global)
    );
    // An already-known salt is still detected as a replay at the cap.
    assert_eq!(store.check_and_mark_legacy_salt(&u, a), ReplayCheck::Replay);
}

#[test]
fn legacy_salt_cap_zero_disables_limit() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    for i in 0..1_000_u16 {
        let mut salt = [0_u8; 32];
        salt[..2].copy_from_slice(&i.to_be_bytes());
        assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Fresh);
    }
}

#[test]
fn legacy_salt_cap_is_independent_of_session_windows() {
    // The legacy salt map and the SS-2022 session map each carry their own global
    // cap; filling one must not lock out the other.
    let store = ReplayStore::new(Duration::from_secs(60), 1, 0);
    let u = user(1);
    assert_eq!(store.check_and_mark(&u, [1_u8; 8], 1), ReplayCheck::Fresh);
    // SS-2022 map is now at its cap, but a legacy salt still registers.
    assert_eq!(store.check_and_mark_legacy_salt(&u, [9_u8; 32]), ReplayCheck::Fresh);
}

#[test]
fn legacy_salt_forgotten_after_idle_eviction() {
    let store = ReplayStore::new(Duration::from_secs(60), 0, 0);
    let u = user(1);
    let salt = [9_u8; 32];
    let t = crate::clock::current_unix_secs();
    assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Replay);
    // Past the idle window the salt is dropped, so a later datagram reusing it
    // reads fresh again — the documented leaky-window limit of legacy UDP,
    // which has no counter or timestamp to bound the memory otherwise.
    store.sweep(t + 61);
    assert_eq!(store.check_and_mark_legacy_salt(&u, salt), ReplayCheck::Fresh);
}

// --- Per-user cap: one tenant cannot evict another (the DoS this closes) ---

#[test]
fn per_user_cap_isolates_ss2022_tenants() {
    // Global cap is generous; the per-user share is 2. One user filling its
    // share must not stop a *different* user from registering fresh sessions.
    let store = ReplayStore::new(Duration::from_secs(60), 1_000, 2);
    let a = user(1);
    let b = user(2);
    assert_eq!(store.check_and_mark(&a, [1_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(&a, [2_u8; 8], 1), ReplayCheck::Fresh);
    // User A is at its per-user share: a third csid is dropped as PerUser, not Global.
    assert_eq!(
        store.check_and_mark(&a, [3_u8; 8], 1),
        ReplayCheck::StoreFull(ReplayFull::PerUser)
    );
    // User B is unaffected — A cannot starve it.
    assert_eq!(store.check_and_mark(&b, [3_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(&b, [4_u8; 8], 1), ReplayCheck::Fresh);
}

#[test]
fn per_user_cap_isolates_legacy_tenants() {
    let store = ReplayStore::new(Duration::from_secs(60), 1_000, 2);
    let a = user(1);
    let b = user(2);
    assert_eq!(store.check_and_mark_legacy_salt(&a, [1_u8; 32]), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&a, [2_u8; 32]), ReplayCheck::Fresh);
    assert_eq!(
        store.check_and_mark_legacy_salt(&a, [3_u8; 32]),
        ReplayCheck::StoreFull(ReplayFull::PerUser)
    );
    // A different user still has its own share.
    assert_eq!(store.check_and_mark_legacy_salt(&b, [3_u8; 32]), ReplayCheck::Fresh);
}

#[test]
fn per_user_cap_counts_across_both_maps() {
    // A user's SS-2022 windows and legacy salts share one per-user budget, so a
    // user cannot double its footprint by straddling both maps.
    let store = ReplayStore::new(Duration::from_secs(60), 1_000, 2);
    let a = user(1);
    assert_eq!(store.check_and_mark(&a, [1_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&a, [1_u8; 32]), ReplayCheck::Fresh);
    // Budget of 2 is now spent across the two maps; either kind of new entry is dropped.
    assert_eq!(
        store.check_and_mark(&a, [2_u8; 8], 1),
        ReplayCheck::StoreFull(ReplayFull::PerUser)
    );
    assert_eq!(
        store.check_and_mark_legacy_salt(&a, [2_u8; 32]),
        ReplayCheck::StoreFull(ReplayFull::PerUser)
    );
}

#[test]
fn per_user_cap_zero_disables_per_user_limit() {
    // With the per-user cap off, a single user may fill up to the global cap.
    let store = ReplayStore::new(Duration::from_secs(60), 500, 0);
    let a = user(1);
    for i in 0..500_u16 {
        let mut csid = [0_u8; 8];
        csid[..2].copy_from_slice(&i.to_be_bytes());
        assert_eq!(store.check_and_mark(&a, csid, 1), ReplayCheck::Fresh, "i={i}");
    }
    // The 501st new session hits the global cap.
    assert_eq!(
        store.check_and_mark(&a, [0xff; 8], 1),
        ReplayCheck::StoreFull(ReplayFull::Global)
    );
}

#[test]
fn per_user_slot_returns_after_idle_eviction() {
    // A user at its per-user share regains room once its idle entries are reaped,
    // across both the SS-2022 and the legacy maps.
    let store = ReplayStore::new(Duration::from_secs(60), 0, 2);
    let a = user(1);
    let t = crate::clock::current_unix_secs();
    assert_eq!(store.check_and_mark(&a, [1_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&a, [1_u8; 32]), ReplayCheck::Fresh);
    assert_eq!(
        store.check_and_mark(&a, [2_u8; 8], 1),
        ReplayCheck::StoreFull(ReplayFull::PerUser)
    );
    // Idle eviction reaps both entries and hands the per-user slots back.
    store.sweep(t + 61);
    assert_eq!(store.check_and_mark(&a, [2_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_legacy_salt(&a, [2_u8; 32]), ReplayCheck::Fresh);
}

#[test]
fn global_cap_fires_before_per_user_when_both_reachable() {
    // Global cap smaller than the per-user share: the global limit is reported.
    let store = ReplayStore::new(Duration::from_secs(60), 1, 100);
    let a = user(1);
    assert_eq!(store.check_and_mark(&a, [1_u8; 8], 1), ReplayCheck::Fresh);
    assert_eq!(
        store.check_and_mark(&a, [2_u8; 8], 1),
        ReplayCheck::StoreFull(ReplayFull::Global)
    );
}
