use super::*;

#[test]
fn empty_ring_reports_zero_total_and_oldest() {
    let ring = ClientUpstreamRingBuffer::new(64);
    assert_eq!(ring.capacity_bytes(), 64);
    assert_eq!(ring.total_sent(), 0);
    assert_eq!(ring.buffered_bytes(), 0);
    // With no entries the oldest offset folds into total_sent so
    // `replay_from(0)` is unambiguously "nothing buffered, offset
    // already covers it" and not an "evicted" error.
    assert_eq!(ring.oldest_offset(), 0);
}

#[test]
fn empty_push_is_noop() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"").unwrap();
    assert_eq!(ring.total_sent(), 0);
    assert_eq!(ring.buffered_bytes(), 0);
}

#[test]
fn push_records_chunk_and_advances_total() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    ring.push(b"world").unwrap();
    assert_eq!(ring.total_sent(), 10);
    assert_eq!(ring.buffered_bytes(), 10);
    assert_eq!(ring.oldest_offset(), 0);
}

#[test]
fn replay_from_zero_returns_full_buffered_stream() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    ring.push(b"world").unwrap();
    let replay = ring.replay_from(0).unwrap();
    assert_eq!(replay, b"helloworld");
}

#[test]
fn replay_from_total_sent_is_empty_vec() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    let replay = ring.replay_from(5).unwrap();
    assert!(replay.is_empty(), "offset == total_sent must be a valid empty replay");
}

#[test]
fn replay_from_mid_chunk_returns_only_the_tail() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    ring.push(b"world").unwrap();
    // Cursor inside "hello" — drop the first 3 bytes of it but keep
    // the trailing "lo" plus the entire next chunk.
    let replay = ring.replay_from(3).unwrap();
    assert_eq!(replay, b"loworld");
}

#[test]
fn replay_from_chunk_boundary_returns_subsequent_chunks() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    ring.push(b"world").unwrap();
    let replay = ring.replay_from(5).unwrap();
    assert_eq!(replay, b"world");
}

#[test]
fn replay_from_offset_past_total_sent_errors() {
    let mut ring = ClientUpstreamRingBuffer::new(64);
    ring.push(b"hello").unwrap();
    let err = ring.replay_from(99).unwrap_err();
    assert_eq!(err, ReplayError::OffsetAhead { requested: 99, total_sent: 5 },);
}

#[test]
fn fifo_eviction_drops_oldest_chunks_to_fit_new_push() {
    // Cap = 6, push three 2-byte chunks (fits), then a 4-byte chunk
    // which forces eviction of the first two so the new chunk + the
    // remaining held bytes ≤ 6.
    let mut ring = ClientUpstreamRingBuffer::new(6);
    ring.push(b"AA").unwrap();
    ring.push(b"BB").unwrap();
    ring.push(b"CC").unwrap();
    assert_eq!(ring.buffered_bytes(), 6);
    assert_eq!(ring.oldest_offset(), 0);

    ring.push(b"DDDD").unwrap();
    assert_eq!(ring.total_sent(), 10);
    assert_eq!(ring.buffered_bytes(), 6, "must hold exactly the cap, not exceed it");
    // First two chunks evicted (4 bytes), oldest is now "CC" at offset 4.
    assert_eq!(ring.oldest_offset(), 4);

    // Replay from the new oldest covers "CC" + "DDDD".
    assert_eq!(ring.replay_from(4).unwrap(), b"CCDDDD");
}

#[test]
fn replay_from_offset_below_oldest_errors_with_evicted() {
    let mut ring = ClientUpstreamRingBuffer::new(6);
    ring.push(b"AA").unwrap();
    ring.push(b"BB").unwrap();
    ring.push(b"CC").unwrap();
    ring.push(b"DDDD").unwrap();

    // Bytes 0-3 ("AABB") are evicted; asking for 0 must surface that
    // unambiguously rather than silently returning the surviving
    // suffix.
    let err = ring.replay_from(0).unwrap_err();
    assert_eq!(err, ReplayError::OffsetEvicted { requested: 0, oldest_available: 4 },);
}

#[test]
fn push_larger_than_capacity_is_rejected() {
    let mut ring = ClientUpstreamRingBuffer::new(4);
    let err = ring.push(b"too-big").unwrap_err();
    assert_eq!(err, PushError::OversizedSingleChunk { chunk_len: 7, capacity_bytes: 4 },);
    // Failed push must not corrupt the bookkeeping.
    assert_eq!(ring.total_sent(), 0);
    assert_eq!(ring.buffered_bytes(), 0);
}

#[test]
fn capacity_zero_rejects_every_non_empty_push() {
    let mut ring = ClientUpstreamRingBuffer::new(0);
    let err = ring.push(b"x").unwrap_err();
    assert_eq!(err, PushError::OversizedSingleChunk { chunk_len: 1, capacity_bytes: 0 },);
    // Empty pushes still succeed — keeps unconditional caller wiring
    // safe even when retry is disabled.
    ring.push(b"").unwrap();
    assert_eq!(ring.total_sent(), 0);
}

#[test]
fn replay_from_after_full_eviction_handles_tail_only_correctly() {
    // Cap = 4. Push three 2-byte chunks; after the third push the
    // first one is evicted. Replay from the boundary between the
    // evicted chunk and the surviving ones must return both.
    let mut ring = ClientUpstreamRingBuffer::new(4);
    ring.push(b"AA").unwrap();
    ring.push(b"BB").unwrap();
    ring.push(b"CC").unwrap();
    assert_eq!(ring.oldest_offset(), 2);
    assert_eq!(ring.replay_from(2).unwrap(), b"BBCC");
    assert_eq!(ring.replay_from(3).unwrap(), b"BCC");
    assert_eq!(ring.replay_from(6).unwrap(), b"");
}

#[test]
fn many_small_pushes_stay_within_capacity() {
    let mut ring = ClientUpstreamRingBuffer::new(16);
    // Push 100 chunks of 1 byte each. Cap is 16, so the ring must
    // converge on holding exactly the last 16 bytes.
    for i in 0..100u8 {
        ring.push(&[i]).unwrap();
    }
    assert_eq!(ring.total_sent(), 100);
    assert_eq!(ring.buffered_bytes(), 16);
    assert_eq!(ring.oldest_offset(), 84);
    // Replay from oldest must produce exactly the last 16 byte
    // values.
    let expected: Vec<u8> = (84u8..100u8).collect();
    assert_eq!(ring.replay_from(84).unwrap(), expected);
}

#[test]
fn replay_from_after_eviction_below_oldest_still_errors() {
    let mut ring = ClientUpstreamRingBuffer::new(16);
    for i in 0..100u8 {
        ring.push(&[i]).unwrap();
    }
    // oldest is 84; offset 50 was evicted.
    let err = ring.replay_from(50).unwrap_err();
    assert_eq!(err, ReplayError::OffsetEvicted { requested: 50, oldest_available: 84 },);
}
