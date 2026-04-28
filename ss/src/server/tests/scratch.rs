use super::*;

fn pool_len() -> usize {
    SCRATCH_POOL.with(|cell| cell.borrow().len())
}

fn drain_pool() {
    SCRATCH_POOL.with(|cell| cell.borrow_mut().clear());
}

#[test]
fn take_then_drop_returns_buffer_to_pool() {
    drain_pool();
    {
        let mut buf = ScratchBuf::take();
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
    }
    assert_eq!(pool_len(), 1);
}

#[test]
fn buffer_is_cleared_on_return() {
    drain_pool();
    {
        let mut buf = ScratchBuf::take();
        buf.extend_from_slice(b"dirty data");
    }
    let buf = ScratchBuf::take();
    assert!(buf.is_empty());
    assert!(buf.capacity() >= MAX_CHUNK_SIZE);
}

#[test]
fn pool_capped_at_max_cached() {
    drain_pool();
    let bufs: Vec<_> = (0..MAX_CACHED + 2).map(|_| ScratchBuf::take()).collect();
    drop(bufs);
    assert_eq!(pool_len(), MAX_CACHED);
}

#[test]
fn fresh_take_when_pool_empty_has_chunk_capacity() {
    drain_pool();
    let buf = ScratchBuf::take();
    assert!(buf.capacity() >= MAX_CHUNK_SIZE);
}
