//! Read-chunk compaction on the TUN direct path.
//!
//! The reader allocates a fixed 16 KiB buffer per read and hands it to `Bytes`,
//! which takes ownership of the whole allocation — so a 100-byte read kept
//! 16 KiB alive for as long as the chunk sat in the flow's downlink queue.
//! Worse, the queue is charged `chunk.len()`, so the engine-wide
//! `pending_server_budget_bytes` counted those 100 bytes and stayed blind to the
//! 16 KiB actually held: the budget could be overrun manyfold without noticing.

use super::super::tasks::upstream::direct_reader::{compact_read_chunk, should_compact_read_chunk};

#[test]
fn a_read_that_barely_filled_the_buffer_is_compacted() {
    assert!(
        should_compact_read_chunk(100, 16_384),
        "100 bytes must not keep a 16 KiB allocation alive"
    );
    assert!(should_compact_read_chunk(1, 16_384));
    assert!(should_compact_read_chunk(4_000, 16_384));
}

/// Copying is only worth it while the waste dominates. A nearly-full buffer is
/// handed over as-is: the copy would cost the same bytes it saves.
#[test]
fn a_nearly_full_buffer_is_handed_over_as_is() {
    assert!(!should_compact_read_chunk(16_384, 16_384));
    assert!(!should_compact_read_chunk(9_000, 16_384));
}

#[test]
fn an_empty_read_is_never_compacted() {
    assert!(!should_compact_read_chunk(0, 16_384), "nothing to copy");
}

/// Whatever branch is taken, the chunk must carry exactly the bytes that were
/// read — compaction is an allocation concern, never a data one.
#[test]
fn compaction_preserves_the_payload() {
    let mut small = Vec::with_capacity(16_384);
    small.extend_from_slice(b"hello");
    let chunk = compact_read_chunk(small, 5);
    assert_eq!(&chunk[..], b"hello");
    assert_eq!(chunk.len(), 5);

    let mut full = Vec::with_capacity(8);
    full.extend_from_slice(b"12345678");
    let chunk = compact_read_chunk(full, 8);
    assert_eq!(&chunk[..], b"12345678");
}

/// `try_read_buf` appends, so the buffer may already hold data from an earlier
/// poll; the chunk must be cut to what the caller says was filled.
#[test]
fn compaction_cuts_to_the_filled_length() {
    let mut buf = Vec::with_capacity(16_384);
    buf.extend_from_slice(b"abcdefghij");
    let chunk = compact_read_chunk(buf, 4);
    assert_eq!(&chunk[..], b"abcd");
}
