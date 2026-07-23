//! In-memory DNS cache shared by the client transport stack and the
//! server's upstream-connect path.
//!
//! Entries map `(port, addr_pref, host)` to a ready-to-use
//! `Arc<[SocketAddr]>` slice. The `addr_pref` bit is opaque to the
//! cache — it is simply part of the key, encoding the caller's
//! address-ordering preference (`ipv6_first` on the client,
//! `prefer_ipv4_upstream` on the server) so differently-ordered
//! resolutions never alias.
//!
//! Entries live in a dense `Vec` of slots with a `HashTable` of slot
//! indices on top. `get` / `get_stale` probe that index with a borrowed
//! `&str` — one hash computation, one table probe, no heap allocation on
//! the hot path — while the dense vector gives eviction O(1) random
//! sampling (walking hash buckets to reach the n-th entry would be O(n)).
//! Expired entries are kept in memory so `get_stale` can serve them as a
//! last-ditch fallback when the upstream resolver fails; fresh data
//! overwrites them in place.
//!
//! Two bounding strategies, picked by constructor:
//! - [`DnsCache::with_capacity`] — approximate LRU à la Redis
//!   `allkeys-lru`: when full, `insert` reaps an expired sample or
//!   evicts the least-recently-accessed of a random sample. Used by
//!   the client, where direct-target DNS would otherwise grow the map
//!   for the lifetime of the process.
//! - [`DnsCache::new`] — unbounded; pair it with a periodic
//!   [`DnsCache::sweep_expired`] tick. Used by the server, which keeps
//!   stale entries around for resolver-outage fallback and purges them
//!   on a janitor schedule instead of at insert time.

use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hashbrown::{DefaultHashBuilder, HashTable};
use parking_lot::RwLock;
use rand::Rng;

/// Default TTL used by [`DnsCache::default`] — matches typical DNS record
/// windows and the previous global cache behaviour.
pub const DEFAULT_DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Default capacity used by [`DnsCache::default`]. Sized to comfortably hold
/// the working set for an active proxy session (direct-target DNS dominates
/// the entry count) while keeping memory usage bounded — at ~120 bytes per
/// entry plus the 1-2 sockaddrs the heap footprint stays under ~1 MiB.
pub const DEFAULT_DNS_CACHE_CAPACITY: usize = 4096;

/// Number of entries sampled per eviction round when the cache is full.
/// Approximate-LRU à la Redis `allkeys-lru`: the larger this is, the closer
/// to true LRU, at higher per-insert cost. 8 keeps insert O(1) in practice
/// while evicting "old enough" entries with high probability.
const EVICTION_SAMPLE: usize = 8;

type CacheKey = (u16, bool, Box<str>);

#[derive(Debug)]
struct Entry {
    /// Already sorted according to the `addr_pref` bit in the key —
    /// callers receive a ready-to-use ordered slice without re-sorting on
    /// each hit.
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
    /// Monotonic tick of the last access (insert or get). Updated under the
    /// read lock with `Relaxed` ordering — eviction only needs an
    /// approximate ordering, exact happens-before is not required.
    last_access: AtomicU64,
}

/// One stored mapping. The key's hash is cached alongside it so relocating a
/// slot — on eviction, on sweep, or when the index grows — never has to hash
/// the host string again.
#[derive(Debug)]
struct Slot {
    hash: u64,
    key: CacheKey,
    entry: Entry,
}

/// Dense slot vector plus a hash index into it.
///
/// The dense vector is what keeps eviction O(1): a random sample is a slice
/// of consecutive slots, and removal is `swap_remove` plus a single index
/// fix-up for the slot that moved. A plain `HashMap` can only be sampled by
/// walking buckets from the start, which is O(len) per eviction.
#[derive(Debug)]
struct Store {
    hasher: DefaultHashBuilder,
    slots: Vec<Slot>,
    /// Slot indices, keyed by the slot's cached hash.
    index: HashTable<usize>,
}

impl Store {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            hasher: DefaultHashBuilder::default(),
            slots: Vec::with_capacity(capacity),
            index: HashTable::with_capacity(capacity),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    fn hash_key(&self, port: u16, addr_pref: bool, host: &str) -> u64 {
        make_hash(&self.hasher, port, addr_pref, host)
    }

    /// Slot index for the key, or `None`.
    #[inline]
    fn find(&self, hash: u64, port: u16, addr_pref: bool, host: &str) -> Option<usize> {
        self.index
            .find(hash, |&i| key_eq(&self.slots[i].key, port, addr_pref, host))
            .copied()
    }

    /// Append a slot for a key known to be absent.
    fn push(&mut self, hash: u64, key: CacheKey, entry: Entry) {
        let Self { slots, index, .. } = self;
        slots.push(Slot { hash, key, entry });
        let idx = slots.len() - 1;
        index.insert_unique(hash, idx, |&i| slots[i].hash);
    }

    /// Drop the slot at `idx`. `swap_remove` moves the last slot into the
    /// hole, so its index entry is repointed at the new position. The
    /// `debug_assert`s pin the slots↔index invariant: every live slot is
    /// reachable through the index under its cached hash.
    fn remove_at(&mut self, idx: usize) {
        let Self { slots, index, .. } = self;
        let last = slots.len() - 1;
        let hash = slots[idx].hash;
        let victim = index.find_entry(hash, |&i| i == idx);
        debug_assert!(victim.is_ok(), "slot {idx} is not in the index");
        if let Ok(occupied) = victim {
            let _ = occupied.remove();
        }
        slots.swap_remove(idx);
        if idx != last {
            let moved = index.find_mut(slots[idx].hash, |&i| i == last);
            debug_assert!(moved.is_some(), "relocated slot {last} is not in the index");
            if let Some(moved) = moved {
                *moved = idx;
            }
        }
    }

    /// Drop every slot whose entry fails `keep`; returns how many went away.
    /// Iterates back to front so the slot `remove_at` relocates has already
    /// been visited.
    fn retain(&mut self, mut keep: impl FnMut(&Entry) -> bool) -> usize {
        let mut removed = 0usize;
        let mut idx = self.slots.len();
        while idx > 0 {
            idx -= 1;
            if !keep(&self.slots[idx].entry) {
                self.remove_at(idx);
                removed += 1;
            }
        }
        removed
    }
}

/// In-memory cache of resolved `(port, addr_pref, host) → Arc<[SocketAddr]>`
/// mappings. See the module docs for the two bounding strategies.
#[derive(Debug)]
pub struct DnsCache {
    inner: RwLock<Store>,
    ttl: Duration,
    capacity: Option<NonZeroUsize>,
    tick: AtomicU64,
}

#[inline]
fn make_hash(bh: &impl BuildHasher, port: u16, addr_pref: bool, host: &str) -> u64 {
    let mut h = bh.build_hasher();
    port.hash(&mut h);
    addr_pref.hash(&mut h);
    host.hash(&mut h);
    h.finish()
}

#[inline]
fn key_eq(k: &CacheKey, port: u16, addr_pref: bool, host: &str) -> bool {
    k.0 == port && k.1 == addr_pref && k.2.as_ref() == host
}

impl DnsCache {
    /// Unbounded cache with the given TTL. Pair with a periodic
    /// [`DnsCache::sweep_expired`] tick, or prefer
    /// [`DnsCache::with_capacity`] for paths that resolve untrusted hosts.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(Store::with_capacity(0)),
            ttl,
            capacity: None,
            tick: AtomicU64::new(0),
        }
    }

    /// Cache bounded to at most `capacity` entries (clamped to >=1). Once
    /// the cap is hit, `insert` evicts via approximate LRU.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: RwLock::new(Store::with_capacity(cap.get())),
            ttl,
            capacity: Some(cap),
            tick: AtomicU64::new(0),
        }
    }

    #[inline]
    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the cached addresses when the entry is still fresh.
    pub fn get(&self, host: &str, port: u16, addr_pref: bool) -> Option<Arc<[SocketAddr]>> {
        let store = self.inner.read();
        let hash = store.hash_key(port, addr_pref, host);
        let entry = &store.slots[store.find(hash, port, addr_pref, host)?].entry;
        if Instant::now() < entry.expires_at {
            entry.last_access.store(self.next_tick(), Ordering::Relaxed);
            Some(Arc::clone(&entry.addrs))
        } else {
            None
        }
    }

    /// Returns cached addresses regardless of expiry. Intended as a
    /// last-ditch fallback when the upstream resolver fails — prefer
    /// [`DnsCache::get`] for the hot path.
    pub fn get_stale(&self, host: &str, port: u16, addr_pref: bool) -> Option<Arc<[SocketAddr]>> {
        let store = self.inner.read();
        let hash = store.hash_key(port, addr_pref, host);
        let entry = &store.slots[store.find(hash, port, addr_pref, host)?].entry;
        entry.last_access.store(self.next_tick(), Ordering::Relaxed);
        Some(Arc::clone(&entry.addrs))
    }

    /// Upserts the resolution for the key, stamping `now + ttl` as expiry.
    /// On a bounded cache, evicts past-capacity entries (expired first,
    /// then approximate-LRU).
    pub fn insert(&self, host: &str, port: u16, addr_pref: bool, addrs: Arc<[SocketAddr]>) {
        let mut store = self.inner.write();
        let hash = store.hash_key(port, addr_pref, host);
        let tick = self.next_tick();
        let new_entry = Entry {
            addrs,
            expires_at: Instant::now() + self.ttl,
            last_access: AtomicU64::new(tick),
        };
        match store.find(hash, port, addr_pref, host) {
            Some(idx) => {
                store.slots[idx].entry = new_entry;
                return;
            },
            None => store.push(hash, (port, addr_pref, host.into()), new_entry),
        }

        if let Some(cap) = self.capacity {
            while store.len() > cap.get() {
                if !evict_one(&mut store) {
                    break;
                }
            }
        }
    }

    /// Removes entries whose expiry is older than `stale_grace` — callers
    /// that keep stale entries around for fallback pass a grace period
    /// longer than the cache TTL. Returns the number of purged entries.
    /// This is the janitor companion to the unbounded constructor; bounded
    /// caches usually rely on insert-time eviction instead.
    pub fn sweep_expired(&self, stale_grace: Duration) -> usize {
        let Some(cutoff) = Instant::now().checked_sub(stale_grace) else {
            return 0;
        };
        self.inner.write().retain(|entry| entry.expires_at > cutoff)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().len()
    }
}

/// Pick one entry to evict and remove it. Returns `false` if the store is
/// empty (defensive — the caller already checked `len > capacity`).
///
/// Strategy: scan a random window of up to [`EVICTION_SAMPLE`] consecutive
/// slots. Evict the first expired entry seen; otherwise evict the one with
/// the smallest `last_access` tick. Sampling and removal are both O(1) in
/// the number of cached entries — the window is a slice, and the victim's
/// slot index is already known, so nothing gets re-hashed.
fn evict_one(store: &mut Store) -> bool {
    let len = store.len();
    if len == 0 {
        return false;
    }
    let now = Instant::now();
    let sample = EVICTION_SAMPLE.min(len);
    let start = if len > sample {
        rand::rng().random_range(0..len - sample + 1)
    } else {
        0
    };

    let mut victim = start;
    let mut oldest_tick = u64::MAX;
    for (offset, slot) in store.slots[start..start + sample].iter().enumerate() {
        if slot.entry.expires_at <= now {
            victim = start + offset;
            break;
        }
        let tick = slot.entry.last_access.load(Ordering::Relaxed);
        if tick < oldest_tick {
            oldest_tick = tick;
            victim = start + offset;
        }
    }

    store.remove_at(victim);
    true
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_DNS_CACHE_TTL, DEFAULT_DNS_CACHE_CAPACITY)
    }
}

#[cfg(test)]
#[path = "tests/dns_cache.rs"]
mod tests;
