use super::*;
use ring::aead::{AES_128_GCM, LessSafeKey, UnboundKey};

fn dummy_key() -> Arc<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_128_GCM, &[0u8; 16]).unwrap();
    Arc::new(LessSafeKey::new(unbound))
}

#[test]
fn put_then_get_returns_same_arc() {
    let cache = SessionKeyCache::new(NonZeroUsize::new(8).unwrap());
    let key = dummy_key();
    cache.insert(0, b"saltsaltsaltsalt", Arc::clone(&key));

    let fetched = cache.get(0, b"saltsaltsaltsalt").expect("hit");
    assert!(Arc::ptr_eq(&fetched, &key));
}

#[test]
fn miss_on_different_user_index() {
    let cache = SessionKeyCache::new(NonZeroUsize::new(8).unwrap());
    cache.insert(0, b"saltsaltsaltsalt", dummy_key());
    assert!(cache.get(1, b"saltsaltsaltsalt").is_none());
}

#[test]
fn miss_on_different_salt() {
    let cache = SessionKeyCache::new(NonZeroUsize::new(8).unwrap());
    cache.insert(0, b"saltsaltsaltsalt", dummy_key());
    assert!(cache.get(0, b"different_saltxx").is_none());
}

#[test]
fn capacity_is_enforced() {
    // Per-shard cap = ceil(total / SHARD_COUNT). Insert far more than
    // `total_capacity` distinct (user, salt) pairs and verify the
    // aggregate population never exceeds the per-shard cap × shards.
    // Distribution between shards is hash-determined; what matters is
    // that no shard grows unbounded.
    let total_capacity = NonZeroUsize::new(64).unwrap();
    let cache = SessionKeyCache::new(total_capacity);
    let per_shard_cap = total_capacity.get().div_ceil(SHARD_COUNT).max(1);
    let upper_bound = per_shard_cap * SHARD_COUNT;
    for i in 0u64..1024 {
        cache.insert(i as usize, &i.to_be_bytes(), dummy_key());
    }
    assert!(
        cache.len() <= upper_bound,
        "len={} exceeds upper_bound={}",
        cache.len(),
        upper_bound
    );
}

#[test]
fn rejects_oversize_salt() {
    let cache = SessionKeyCache::new(NonZeroUsize::new(2).unwrap());
    cache.insert(0, &[0u8; 64], dummy_key());
    assert_eq!(cache.len(), 0);
    assert!(cache.get(0, &[0u8; 64]).is_none());
}
