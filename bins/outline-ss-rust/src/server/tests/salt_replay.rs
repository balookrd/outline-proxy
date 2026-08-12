use std::sync::Arc;
use std::time::Duration;

use super::*;

fn salt(byte: u8, len: usize) -> Arc<[u8]> {
    Arc::from(vec![byte; len].into_boxed_slice())
}

#[test]
fn distinct_salts_are_fresh_and_repeat_is_replay() {
    let store = SaltReplayStore::new(Duration::from_secs(60), 0);
    let a = salt(1, 32);
    let b = salt(2, 32);

    assert_eq!(store.check_and_mark_at(Arc::clone(&a), 1_000), SaltReplayCheck::Fresh);
    // A different salt at the same instant is independent.
    assert_eq!(store.check_and_mark_at(Arc::clone(&b), 1_000), SaltReplayCheck::Fresh);
    // Re-presenting either captured salt within the window is a replay.
    assert_eq!(store.check_and_mark_at(a, 1_001), SaltReplayCheck::Replay);
    assert_eq!(store.check_and_mark_at(b, 1_001), SaltReplayCheck::Replay);
}

#[test]
fn salts_of_different_lengths_do_not_collide() {
    // Legacy ciphers use a 16-byte salt, SS-2022 aes-256 / chacha use 32.
    // Same byte pattern, different length must be treated as distinct keys.
    let store = SaltReplayStore::new(Duration::from_secs(60), 0);
    let short = salt(7, 16);
    let long = salt(7, 32);

    assert_eq!(store.check_and_mark_at(Arc::clone(&short), 1_000), SaltReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_at(Arc::clone(&long), 1_000), SaltReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_at(short, 1_000), SaltReplayCheck::Replay);
    assert_eq!(store.check_and_mark_at(long, 1_000), SaltReplayCheck::Replay);
}

#[test]
fn new_salt_over_cap_reports_store_full() {
    let store = SaltReplayStore::new(Duration::from_secs(60), 2);
    let a = salt(1, 32);
    let b = salt(2, 32);
    let c = salt(3, 32);

    assert_eq!(store.check_and_mark_at(Arc::clone(&a), 1_000), SaltReplayCheck::Fresh);
    assert_eq!(store.check_and_mark_at(b, 1_000), SaltReplayCheck::Fresh);
    // Third distinct salt spills over the cap.
    assert_eq!(store.check_and_mark_at(c, 1_000), SaltReplayCheck::StoreFull);
    // An already-known salt is still detected as a replay while at capacity.
    assert_eq!(store.check_and_mark_at(a, 1_000), SaltReplayCheck::Replay);
}

#[test]
fn cap_zero_disables_the_limit() {
    let store = SaltReplayStore::new(Duration::from_secs(60), 0);
    for i in 0..1_000_u16 {
        let mut bytes = [0_u8; 32];
        bytes[..2].copy_from_slice(&i.to_be_bytes());
        let s: Arc<[u8]> = Arc::from(&bytes[..]);
        assert_eq!(store.check_and_mark_at(s, 1_000), SaltReplayCheck::Fresh);
    }
}

#[test]
fn idle_salts_are_evicted_after_ttl() {
    let store = SaltReplayStore::new(Duration::from_secs(60), 0);
    let a = salt(1, 32);
    assert_eq!(store.check_and_mark_at(Arc::clone(&a), 1_000), SaltReplayCheck::Fresh);

    // Still inside the TTL window: the entry survives and the salt is a replay.
    assert_eq!(store.evict_idle_at(1_030), 0);
    assert_eq!(store.check_and_mark_at(Arc::clone(&a), 1_030), SaltReplayCheck::Replay);

    // Past the TTL: the entry is reaped, so the same salt reads as fresh again.
    assert_eq!(store.evict_idle_at(1_000 + 61), 1);
    assert_eq!(store.check_and_mark_at(a, 1_100), SaltReplayCheck::Fresh);
}

#[test]
fn evict_idle_returns_number_reaped() {
    let store = SaltReplayStore::new(Duration::from_secs(60), 0);
    store.check_and_mark_at(salt(1, 32), 1_000);
    store.check_and_mark_at(salt(2, 32), 1_000);
    store.check_and_mark_at(salt(3, 32), 1_050); // fresher, survives

    // threshold = 1_070 - 60 = 1_010; the two 1_000 entries fall out.
    assert_eq!(store.evict_idle_at(1_070), 2);
}
