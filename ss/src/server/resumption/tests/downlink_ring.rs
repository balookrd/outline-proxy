//! Unit tests for the server-side downlink ring buffer backing v2
//! Symmetric Downlink Replay.

use super::super::downlink_ring::{DownlinkRing, ReplayOutcome};

#[test]
fn empty_ring_has_zero_total_and_oldest() {
    let ring = DownlinkRing::new(64);
    assert_eq!(ring.total_sent(), 0);
    assert_eq!(ring.oldest_offset(), 0);
    assert_eq!(ring.buffered_bytes(), 0);
}

#[test]
fn empty_push_is_noop() {
    let mut ring = DownlinkRing::new(64);
    ring.push(&[]);
    assert_eq!(ring.total_sent(), 0);
    assert_eq!(ring.buffered_bytes(), 0);
}

#[test]
fn single_push_under_cap_retains_all_bytes() {
    let mut ring = DownlinkRing::new(64);
    ring.push(b"hello");
    assert_eq!(ring.total_sent(), 5);
    assert_eq!(ring.oldest_offset(), 0);
    assert_eq!(ring.buffered_bytes(), 5);
    assert_eq!(ring.replay_from(0), ReplayOutcome::Available(b"hello".to_vec()));
}

#[test]
fn replay_from_exact_total_returns_empty() {
    let mut ring = DownlinkRing::new(64);
    ring.push(b"abcd");
    assert_eq!(ring.replay_from(4), ReplayOutcome::Available(Vec::new()));
}

#[test]
fn replay_from_offset_in_middle_of_chunk_returns_tail() {
    let mut ring = DownlinkRing::new(64);
    ring.push(b"abcdefghij");
    assert_eq!(ring.replay_from(3), ReplayOutcome::Available(b"defghij".to_vec()));
}

#[test]
fn replay_from_spanning_two_chunks_concatenates() {
    let mut ring = DownlinkRing::new(64);
    ring.push(b"first");
    ring.push(b"second");
    assert_eq!(ring.replay_from(2), ReplayOutcome::Available(b"rstsecond".to_vec()));
}

#[test]
fn replay_from_past_total_reports_offset_ahead() {
    let mut ring = DownlinkRing::new(64);
    ring.push(b"abc");
    assert_eq!(ring.replay_from(99), ReplayOutcome::OffsetAhead);
}

#[test]
fn fifo_eviction_when_new_chunk_pushes_oldest_out() {
    // Capacity 6, sequence: [3 + 4] → first 3 evicted to fit 4.
    let mut ring = DownlinkRing::new(6);
    ring.push(b"AAA");
    ring.push(b"BBBB");
    assert_eq!(ring.total_sent(), 7);
    assert_eq!(ring.oldest_offset(), 3);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(3), ReplayOutcome::Available(b"BBBB".to_vec()));
}

#[test]
fn replay_from_evicted_offset_reports_truncated() {
    let mut ring = DownlinkRing::new(4);
    ring.push(b"AAAA");
    ring.push(b"BBBB"); // forces eviction of first chunk
    assert_eq!(ring.oldest_offset(), 4);
    assert_eq!(ring.replay_from(0), ReplayOutcome::Truncated);
    assert_eq!(ring.replay_from(2), ReplayOutcome::Truncated);
}

#[test]
fn oversized_chunk_retains_only_trailing_capacity() {
    // Capacity 4, single chunk of 10 bytes — the last 4 must be kept,
    // and total_sent advances by the full chunk length.
    let mut ring = DownlinkRing::new(4);
    ring.push(b"0123456789");
    assert_eq!(ring.total_sent(), 10);
    assert_eq!(ring.oldest_offset(), 6);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(6), ReplayOutcome::Available(b"6789".to_vec()));
    assert_eq!(ring.replay_from(0), ReplayOutcome::Truncated);
    assert_eq!(ring.replay_from(5), ReplayOutcome::Truncated);
    assert_eq!(ring.replay_from(10), ReplayOutcome::Available(Vec::new()));
}

#[test]
fn oversized_chunk_evicts_pre_existing_entries() {
    // Pre-existing chunk + oversized push → all prior entries must go.
    let mut ring = DownlinkRing::new(4);
    ring.push(b"AB");
    ring.push(b"01234567"); // bigger than cap → drops "AB" + drops "0123"
    assert_eq!(ring.total_sent(), 10);
    assert_eq!(ring.oldest_offset(), 6);
    assert_eq!(ring.replay_from(6), ReplayOutcome::Available(b"4567".to_vec()));
    assert_eq!(ring.replay_from(0), ReplayOutcome::Truncated);
}

#[test]
fn zero_capacity_ring_advances_total_but_retains_nothing() {
    let mut ring = DownlinkRing::new(0);
    ring.push(b"hello");
    assert_eq!(ring.total_sent(), 5);
    assert_eq!(ring.oldest_offset(), 5);
    assert_eq!(ring.buffered_bytes(), 0);
    assert_eq!(ring.replay_from(0), ReplayOutcome::Truncated);
    assert_eq!(ring.replay_from(5), ReplayOutcome::Available(Vec::new()));
}

#[test]
fn many_small_pushes_with_eviction_preserve_recent_window() {
    // 100 single-byte pushes with capacity 10 — only the last 10
    // bytes (offsets 90..100) should remain.
    let mut ring = DownlinkRing::new(10);
    for i in 0..100u8 {
        ring.push(&[i]);
    }
    assert_eq!(ring.total_sent(), 100);
    assert_eq!(ring.oldest_offset(), 90);
    assert_eq!(ring.buffered_bytes(), 10);
    let expected: Vec<u8> = (90u8..100u8).collect();
    assert_eq!(ring.replay_from(90), ReplayOutcome::Available(expected));
    assert_eq!(ring.replay_from(89), ReplayOutcome::Truncated);
}

#[test]
fn replay_partial_when_offset_falls_mid_chunk_after_eviction() {
    // [chunk1 = "AAA"] [chunk2 = "BBB"] [chunk3 = "CCC"], capacity 6
    // → after chunk3 push, chunk1 evicted; offsets 3..9 retained.
    let mut ring = DownlinkRing::new(6);
    ring.push(b"AAA");
    ring.push(b"BBB");
    ring.push(b"CCC");
    assert_eq!(ring.oldest_offset(), 3);
    assert_eq!(ring.replay_from(4), ReplayOutcome::Available(b"BBCCC".to_vec()));
    assert_eq!(ring.replay_from(2), ReplayOutcome::Truncated);
}
