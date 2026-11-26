use proptest::prelude::*;

use super::{PushError, ReplayError, ReplayRing};

#[test]
fn push_strict_rejects_oversized_without_mutating_state() {
    let mut ring = ReplayRing::new(8);
    ring.push_strict(b"abcd").unwrap();
    assert_eq!(
        ring.push_strict(b"012345678"),
        Err(PushError::OversizedSingleChunk { chunk_len: 9, capacity_bytes: 8 }),
    );
    assert_eq!(ring.total_sent(), 4);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(0), Ok(b"abcd".to_vec()));
}

#[test]
fn push_strict_evicts_fifo_and_replays_partial_chunk_suffix() {
    let mut ring = ReplayRing::new(6);
    ring.push_strict(b"aaa").unwrap();
    ring.push_strict(b"bbb").unwrap();
    ring.push_strict(b"cc").unwrap();
    assert_eq!(ring.oldest_offset(), 3);
    assert_eq!(
        ring.replay_from(2),
        Err(ReplayError::OffsetEvicted { requested: 2, oldest_available: 3 }),
    );
    assert_eq!(ring.replay_from(4), Ok(b"bbcc".to_vec()));
    assert_eq!(ring.replay_from(8), Ok(Vec::new()));
    assert_eq!(
        ring.replay_from(9),
        Err(ReplayError::OffsetAhead { requested: 9, total_sent: 8 }),
    );
}

#[test]
fn push_strict_reuses_evicted_buffer_without_oversized_pinning() {
    let mut ring = ReplayRing::new(16);
    ring.push_strict(&[b'x'; 16]).unwrap();
    let first_ptr = ring.entries.front().unwrap().payload.as_ptr();

    // Evicts the 16-byte entry; 16 <= 10 * 2, so the buffer is recycled in place.
    ring.push_strict(&[b'y'; 10]).unwrap();
    assert_eq!(ring.entries.back().unwrap().payload.as_ptr(), first_ptr);

    // A tiny 2-byte push that evicts the 16-cap buffer must NOT pin it (16 > 2 * 2).
    ring.push_strict(&[b'z'; 6]).unwrap();
    ring.push_strict(&[b'w'; 2]).unwrap();
    assert!(ring.entries.back().unwrap().payload.capacity() <= 4);
}

#[test]
fn push_truncating_retains_tail_of_oversized_chunk_and_handles_zero_cap() {
    let mut zero = ReplayRing::new(0);
    zero.push_truncating(b"hello");
    assert_eq!(zero.total_sent(), 5);
    assert_eq!(zero.buffered_bytes(), 0);
    assert_eq!(
        zero.replay_from(0),
        Err(ReplayError::OffsetEvicted { requested: 0, oldest_available: 5 }),
    );
    assert_eq!(zero.replay_from(5), Ok(Vec::new()));

    let mut ring = ReplayRing::new(4);
    ring.push_truncating(b"ab");
    ring.push_truncating(b"012345");
    assert_eq!(ring.total_sent(), 8);
    assert_eq!(ring.oldest_offset(), 4);
    assert_eq!(ring.buffered_bytes(), 4);
    assert_eq!(ring.replay_from(4), Ok(b"2345".to_vec()));
    assert_eq!(ring.replay_from(6), Ok(b"45".to_vec()));
}

proptest! {
    #[test]
    fn replay_ring_truncating_matches_reference_stream(
        cap in 0usize..64,
        chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..48), 0..20),
    ) {
        let mut ring = ReplayRing::new(cap);
        let mut reference = Vec::new();
        for chunk in &chunks {
            ring.push_truncating(chunk);
            reference.extend_from_slice(chunk);
        }
        prop_assert_eq!(ring.total_sent(), reference.len() as u64);
        prop_assert!(ring.buffered_bytes() <= cap);
        let oldest = ring.oldest_offset() as usize;
        for offset in 0..=reference.len() {
            let res = ring.replay_from(offset as u64);
            if offset < oldest {
                let is_evicted = matches!(res, Err(ReplayError::OffsetEvicted { .. }));
                prop_assert!(is_evicted);
            } else {
                prop_assert_eq!(res, Ok(reference[offset..].to_vec()));
            }
        }
    }
}
