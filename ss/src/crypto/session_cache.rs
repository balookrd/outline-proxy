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
pub struct SessionKeyCache {
    inner: Mutex<LruCache<CacheKey, Arc<LessSafeKey>>>,
}

impl SessionKeyCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self { inner: Mutex::new(LruCache::new(capacity)) }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(
            NonZeroUsize::new(DEFAULT_SESSION_KEY_CACHE_CAPACITY)
                .expect("non-zero default capacity"),
        )
    }

    pub fn get(&self, user_index: usize, salt: &[u8]) -> Option<Arc<LessSafeKey>> {
        let key = CacheKey::new(user_index, salt)?;
        self.inner.lock().get(&key).cloned()
    }

    pub fn insert(&self, user_index: usize, salt: &[u8], value: Arc<LessSafeKey>) {
        let Some(key) = CacheKey::new(user_index, salt) else {
            return;
        };
        self.inner.lock().put(key, value);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl std::fmt::Debug for SessionKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeyCache").field("len", &self.inner.lock().len()).finish()
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
        let cache = SessionKeyCache::new(NonZeroUsize::new(2).unwrap());
        cache.insert(0, b"a", dummy_key());
        cache.insert(1, b"b", dummy_key());
        cache.insert(2, b"c", dummy_key());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn rejects_oversize_salt() {
        let cache = SessionKeyCache::new(NonZeroUsize::new(2).unwrap());
        cache.insert(0, &[0u8; 64], dummy_key());
        assert_eq!(cache.len(), 0);
        assert!(cache.get(0, &[0u8; 64]).is_none());
    }
}
