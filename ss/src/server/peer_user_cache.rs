//! Bounded LRU mapping `peer_addr -> user_index` consulted before each TCP
//! handshake.
//!
//! TCP handshake at [`crate::crypto::AeadStreamDecryptor::ensure_session_key`]
//! runs `build_session_key` (HKDF + AEAD `UnboundKey` schedule) for every
//! candidate user until one decrypts. With hundreds of users this is the
//! dominant per-connection cost. A hit here orders the candidate scan to try
//! the previously-seen user first; on miss the full scan still runs and the
//! cache back-fills with the freshly observed index.
//!
//! Entries are written *only* after AEAD verification succeeds, so a spoofed
//! source address cannot poison another peer's hint.
//!
//! ## Sharding
//!
//! Mirrors [`crate::crypto::SessionKeyCache`]: independent LRU partitions,
//! each guarded by a [`parking_lot::Mutex`], shard chosen by FNV-1a over the
//! `SocketAddr`. A single global mutex would serialise every TCP handshake
//! across all worker threads, defeating the point.
//!
//! ## Per-route scope
//!
//! Each [`crate::server::state::TransportRoute`] owns its own cache because
//! `user_index` is meaningful only within that route's `users` slice. On
//! config reload (control-plane mutation, file edit) the route is rebuilt and
//! the old cache is dropped — there is no cross-route pollution.

use std::{net::SocketAddr, num::NonZeroUsize};

use lru::LruCache;
use parking_lot::Mutex;

/// Number of independent LRU shards. Power of two so `& (N - 1)` folds the
/// shard selection to a bitmask. 16 matches `SessionKeyCache`.
const SHARD_COUNT: usize = 16;

/// Thread-safe bounded LRU cache of `peer_addr -> user_index`.
///
/// Internally split into [`SHARD_COUNT`] LRU partitions. Total capacity is
/// divided evenly between shards (rounded up so a tiny capacity still gives
/// every shard at least one slot).
pub(in crate::server) struct PeerUserCache {
    shards: Box<[Mutex<LruCache<SocketAddr, usize>>]>,
}

impl PeerUserCache {
    pub(in crate::server) fn new(total_capacity: NonZeroUsize) -> Self {
        let per_shard = total_capacity.get().div_ceil(SHARD_COUNT).max(1);
        let cap = NonZeroUsize::new(per_shard).expect("per-shard capacity > 0");
        let shards: Vec<_> = (0..SHARD_COUNT).map(|_| Mutex::new(LruCache::new(cap))).collect();
        Self { shards: shards.into_boxed_slice() }
    }

    pub(in crate::server) fn with_capacity(total_capacity: usize) -> Self {
        let cap = NonZeroUsize::new(total_capacity.max(1)).expect("non-zero after max(1)");
        Self::new(cap)
    }

    /// Returns the user index previously recorded for `peer`, if any. The
    /// caller must treat the result as a hint: validate that the index is in
    /// bounds for the current `users[]` slice and fall back to the full scan
    /// on AEAD-verification failure.
    pub(in crate::server) fn lookup(&self, peer: SocketAddr) -> Option<usize> {
        self.shard_for(&peer).lock().get(&peer).copied()
    }

    /// Records the most recently authenticated user index for `peer`. Safe to
    /// call repeatedly; subsequent connections from the same peer overwrite
    /// the stored hint, which is what we want when the operator rotates a
    /// password under the same client.
    pub(in crate::server) fn record(&self, peer: SocketAddr, user_index: usize) {
        self.shard_for(&peer).lock().put(peer, user_index);
    }

    #[inline]
    fn shard_for(&self, peer: &SocketAddr) -> &Mutex<LruCache<SocketAddr, usize>> {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        // Mix the canonical SocketAddr representation: address bytes + port.
        match peer {
            SocketAddr::V4(v4) => {
                for b in v4.ip().octets() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
                for b in v4.port().to_le_bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            },
            SocketAddr::V6(v6) => {
                for b in v6.ip().octets() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
                for b in v6.port().to_le_bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            },
        }
        &self.shards[(h as usize) & (SHARD_COUNT - 1)]
    }

    #[cfg(test)]
    pub(in crate::server) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }
}

impl std::fmt::Debug for PeerUserCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.shards.iter().map(|s| s.lock().len()).sum();
        f.debug_struct("PeerUserCache")
            .field("shards", &SHARD_COUNT)
            .field("len", &total)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    #[test]
    fn lookup_after_record_returns_index() {
        let cache = PeerUserCache::with_capacity(8);
        let peer = v4(54321);
        cache.record(peer, 42);
        assert_eq!(cache.lookup(peer), Some(42));
    }

    #[test]
    fn lookup_unknown_peer_misses() {
        let cache = PeerUserCache::with_capacity(8);
        cache.record(v4(1234), 7);
        assert_eq!(cache.lookup(v4(5678)), None);
    }

    #[test]
    fn record_overwrites_previous_index() {
        let cache = PeerUserCache::with_capacity(8);
        let peer = v4(9000);
        cache.record(peer, 1);
        cache.record(peer, 2);
        assert_eq!(cache.lookup(peer), Some(2));
    }

    #[test]
    fn ipv4_and_ipv6_with_same_port_are_distinct() {
        let cache = PeerUserCache::with_capacity(8);
        cache.record(v4(8080), 1);
        cache.record(v6(8080), 2);
        assert_eq!(cache.lookup(v4(8080)), Some(1));
        assert_eq!(cache.lookup(v6(8080)), Some(2));
    }

    #[test]
    fn capacity_is_bounded() {
        // Per-shard cap = ceil(total / SHARD_COUNT). Insert far more than
        // total_capacity distinct peers and verify the aggregate population
        // never exceeds per_shard_cap * SHARD_COUNT. Distribution between
        // shards is hash-determined; what matters is that no shard grows
        // unbounded.
        let total = 64usize;
        let cache = PeerUserCache::with_capacity(total);
        let per_shard_cap = total.div_ceil(SHARD_COUNT).max(1);
        let upper_bound = per_shard_cap * SHARD_COUNT;
        for port in 0u16..1024 {
            cache.record(v4(port), port as usize);
        }
        assert!(
            cache.len() <= upper_bound,
            "len={} exceeds upper_bound={}",
            cache.len(),
            upper_bound
        );
    }
}
