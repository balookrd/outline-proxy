//! Bounded LRU mapping `(user_index, salt) -> derived AEAD session key`.
//!
//! UDP decrypt is the hot path: `build_session_key` runs blake3 (or HKDF) plus
//! a ring `UnboundKey` AES key schedule for every incoming datagram, even when
//! the session is already authenticated. At hundreds of users × thousands of
//! packets per second this becomes the dominant CPU cost. A hit here turns a
//! key derivation into a hashmap lookup; a miss falls through to the existing
//! derive path and back-fills the entry on success.
//!
//! Entries are written only after AEAD verification, so spoofed datagrams with
//! random salts cannot poison the cache.
//!
//! ## Sharding
//!
//! The cache is sharded into [`SHARD_COUNT`] independent LRU partitions keyed
//! by an FNV-1a mix of `(user_index, salt[..8])`. A single global mutex would
//! serialize every UDP datagram across all worker threads — at high pps the
//! lock itself becomes the bottleneck even though each critical section is
//! tiny. Splitting reduces contention by `SHARD_COUNT`× without changing the
//! external API. `SHARD_COUNT` is a power of two so the modulo selection
//! folds to a bitmask.

use std::{num::NonZeroUsize, sync::Arc};

use lru::LruCache;
use parking_lot::Mutex;
use ring::aead::LessSafeKey;

/// Largest salt the cache key needs to hold. Covers every supported cipher:
/// 16 B (AES-128 legacy), 32 B (AES-256 / ChaCha20 legacy), and 8 B (SS-2022
/// `client_session_id` / `server_session_id`).
const MAX_SALT_LEN: usize = 32;

/// Default LRU capacity. ~16k unique `(user, salt)` entries comfortably hold
/// every active session for a multi-tenant deployment without unbounded
/// growth. At ~256 B/entry this is ~4 MB of resident memory.
const DEFAULT_SESSION_KEY_CACHE_CAPACITY: usize = 16_384;

/// Number of independent LRU shards. Power of two so `% SHARD_COUNT` folds to
/// a bitmask. 16 is a sweet spot: enough to defuse contention even on dual-
/// socket boxes, small enough to keep per-shard LRU eviction cheap and the
/// total memory overhead negligible.
const SHARD_COUNT: usize = 16;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct CacheKey {
    user_index: u32,
    salt_len: u8,
    salt: [u8; MAX_SALT_LEN],
}

impl CacheKey {
    fn new(user_index: usize, salt: &[u8]) -> Option<Self> {
        if salt.len() > MAX_SALT_LEN || user_index > u32::MAX as usize {
            return None;
        }
        let mut buf = [0u8; MAX_SALT_LEN];
        buf[..salt.len()].copy_from_slice(salt);
        Some(Self {
            user_index: user_index as u32,
            salt_len: salt.len() as u8,
            salt: buf,
        })
    }
}

/// Thread-safe bounded LRU cache of derived session keys. Cloning the
/// `Arc<LessSafeKey>` is a refcount bump; the wrapped `UnboundKey` is read-only
/// and shareable across threads.
///
/// Internally split into [`SHARD_COUNT`] LRU partitions, each guarded by its
/// own [`parking_lot::Mutex`]. The total capacity is divided evenly between
/// shards (rounded up). Lookups and inserts pick a shard via FNV-1a over
/// `(user_index, salt[..8])` so the same `(user, salt)` always hits the same
/// shard.
pub struct SessionKeyCache {
    shards: Box<[Mutex<LruCache<CacheKey, Arc<LessSafeKey>>>]>,
}

impl SessionKeyCache {
    pub fn new(total_capacity: NonZeroUsize) -> Self {
        // Round up so `total_capacity = 1` still gives every shard an entry
        // worth of headroom rather than a degenerate zero-cap LRU.
        let per_shard = total_capacity.get().div_ceil(SHARD_COUNT).max(1);
        let cap = NonZeroUsize::new(per_shard).expect("per-shard capacity > 0");
        let shards: Vec<_> = (0..SHARD_COUNT).map(|_| Mutex::new(LruCache::new(cap))).collect();
        Self { shards: shards.into_boxed_slice() }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(
            NonZeroUsize::new(DEFAULT_SESSION_KEY_CACHE_CAPACITY)
                .expect("non-zero default capacity"),
        )
    }

    /// Pick the shard for a given cache key. Folds `user_index` together with
    /// the first 8 salt bytes via FNV-1a; the 8-byte prefix is enough to
    /// distinguish SS-2022 8-byte session IDs as well as scattered legacy
    /// 16/32-byte salts.
    #[inline]
    fn shard_for(&self, key: &CacheKey) -> &Mutex<LruCache<CacheKey, Arc<LessSafeKey>>> {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for b in (key.user_index as u64).to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        let prefix_len = (key.salt_len as usize).min(8);
        for &b in &key.salt[..prefix_len] {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        // SHARD_COUNT is a power of two — `& (N - 1)` is the modulo.
        &self.shards[(h as usize) & (SHARD_COUNT - 1)]
    }

    pub fn get(&self, user_index: usize, salt: &[u8]) -> Option<Arc<LessSafeKey>> {
        let key = CacheKey::new(user_index, salt)?;
        self.shard_for(&key).lock().get(&key).cloned()
    }

    pub fn insert(&self, user_index: usize, salt: &[u8], value: Arc<LessSafeKey>) {
        let Some(key) = CacheKey::new(user_index, salt) else {
            return;
        };
        self.shard_for(&key).lock().put(key, value);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

impl std::fmt::Debug for SessionKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.shards.iter().map(|s| s.lock().len()).sum();
        f.debug_struct("SessionKeyCache")
            .field("shards", &SHARD_COUNT)
            .field("len", &total)
            .finish()
    }
}

#[cfg(test)]
mod tests {
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
}
