use super::*;

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
    let store = ReplayStore::new(Duration::from_secs(60), 0);
    let a = [1_u8; 8];
    let b = [2_u8; 8];
    assert_eq!(store.check_and_mark(a, 7), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(b, 7), ReplayCheck::Fresh); // different session, same id ok
    assert_eq!(store.check_and_mark(a, 7), ReplayCheck::Replay);
    assert_eq!(store.check_and_mark(b, 7), ReplayCheck::Replay);
}

#[test]
fn store_rejects_new_sessions_when_at_cap() {
    let store = ReplayStore::new(Duration::from_secs(60), 2);
    let a = [1_u8; 8];
    let b = [2_u8; 8];
    let c = [3_u8; 8];
    assert_eq!(store.check_and_mark(a, 1), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(b, 1), ReplayCheck::Fresh);
    // Third distinct csid spills over the cap and is dropped.
    assert_eq!(store.check_and_mark(c, 1), ReplayCheck::StoreFull);
    // Already-known sessions continue to work at the cap.
    assert_eq!(store.check_and_mark(a, 2), ReplayCheck::Fresh);
    assert_eq!(store.check_and_mark(a, 2), ReplayCheck::Replay);
}

#[test]
fn store_cap_zero_disables_limit() {
    let store = ReplayStore::new(Duration::from_secs(60), 0);
    for i in 0..1_000_u16 {
        let mut csid = [0_u8; 8];
        csid[..2].copy_from_slice(&i.to_be_bytes());
        assert_eq!(store.check_and_mark(csid, 1), ReplayCheck::Fresh);
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
