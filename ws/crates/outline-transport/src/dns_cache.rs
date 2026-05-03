use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use hashbrown::hash_map::RawEntryMut;
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
    /// Already sorted according to the `ipv6_first` bit in the key —
    /// callers receive a ready-to-use ordered slice without re-sorting on
    /// each hit.
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
    /// Monotonic tick of the last access (insert or get). Updated under the
    /// read lock with `Relaxed` ordering — eviction only needs an
    /// approximate ordering, exact happens-before is not required.
    last_access: AtomicU64,
}

/// In-memory cache of resolved `(port, ipv6_first, host) → Arc<[SocketAddr]>`
/// mappings.
///
/// Flat `HashMap<(u16, bool, Box<str>), Entry>` keyed by a single compound
/// hash.  `get` / `get_stale` use the raw-entry API to probe with `&str`
/// directly — one hash computation, one table probe, no heap allocation.
/// `insert` takes a write lock once and updates in-place on a hit.
///
/// Optionally bounded by `capacity`. When full, `insert` first reaps any
/// expired entry it samples; otherwise it picks the oldest of
/// [`EVICTION_SAMPLE`] random entries (approximate LRU). Direct-target DNS
/// is the dominant source of new entries, so an unbounded cache would grow
/// for the lifetime of the process — the bound caps that growth.
#[derive(Debug)]
pub struct DnsCache {
    inner: RwLock<HashMap<CacheKey, Entry>>,
    ttl: Duration,
    capacity: Option<NonZeroUsize>,
    tick: AtomicU64,
}

#[inline]
fn make_hash(bh: &impl BuildHasher, port: u16, ipv6_first: bool, host: &str) -> u64 {
    let mut h = bh.build_hasher();
    port.hash(&mut h);
    ipv6_first.hash(&mut h);
    host.hash(&mut h);
    h.finish()
}

#[inline]
fn key_eq(k: &CacheKey, port: u16, ipv6_first: bool, host: &str) -> bool {
    k.0 == port && k.1 == ipv6_first && k.2.as_ref() == host
}

impl DnsCache {
    /// Unbounded cache with the given TTL. Prefer
    /// [`DnsCache::with_capacity`] for production paths that resolve
    /// untrusted hosts.
    pub fn new(ttl: Duration) -> Self {
        Self { inner: RwLock::new(HashMap::new()), ttl, capacity: None, tick: AtomicU64::new(0) }
    }

    /// Cache bounded to at most `capacity` entries (clamped to >=1). Once
    /// the cap is hit, `insert` evicts via approximate LRU.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: RwLock::new(HashMap::with_capacity(cap.get())),
            ttl,
            capacity: Some(cap),
            tick: AtomicU64::new(0),
        }
    }

    #[inline]
    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get(&self, host: &str, port: u16, ipv6_first: bool) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        let hash = make_hash(map.hasher(), port, ipv6_first, host);
        let (_, entry) = map
            .raw_entry()
            .from_hash(hash, |k| key_eq(k, port, ipv6_first, host))?;
        if Instant::now() < entry.expires_at {
            entry.last_access.store(self.next_tick(), Ordering::Relaxed);
            Some(Arc::clone(&entry.addrs))
        } else {
            None
        }
    }

    pub fn get_stale(
        &self,
        host: &str,
        port: u16,
        ipv6_first: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        let hash = make_hash(map.hasher(), port, ipv6_first, host);
        let (_, entry) = map
            .raw_entry()
            .from_hash(hash, |k| key_eq(k, port, ipv6_first, host))?;
        entry.last_access.store(self.next_tick(), Ordering::Relaxed);
        Some(Arc::clone(&entry.addrs))
    }

    pub fn insert(&self, host: &str, port: u16, ipv6_first: bool, addrs: Arc<[SocketAddr]>) {
        let mut map = self.inner.write();
        // Clone the BuildHasher before the mutable borrow so we can reuse it
        // inside `insert_with_hasher` without a second borrow of `map`.
        let bh = map.hasher().clone();
        let hash = make_hash(&bh, port, ipv6_first, host);
        let tick = self.next_tick();
        let new_entry = Entry {
            addrs,
            expires_at: Instant::now() + self.ttl,
            last_access: AtomicU64::new(tick),
        };
        match map.raw_entry_mut().from_hash(hash, |k| key_eq(k, port, ipv6_first, host)) {
            RawEntryMut::Occupied(mut o) => {
                *o.get_mut() = new_entry;
                return;
            }
            RawEntryMut::Vacant(v) => {
                v.insert_with_hasher(hash, (port, ipv6_first, host.into()), new_entry, |k| {
                    make_hash(&bh, k.0, k.1, &k.2)
                });
            }
        }

        if let Some(cap) = self.capacity {
            while map.len() > cap.get() {
                if !evict_one(&mut map) {
                    break;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().len()
    }
}

/// Pick one entry to evict and remove it. Returns `false` if the map is
/// empty (defensive — the caller already checked `len > capacity`).
///
/// Strategy: scan a random window of up to [`EVICTION_SAMPLE`] entries.
/// Evict the first expired entry seen; otherwise evict the one with the
/// smallest `last_access` tick.
fn evict_one(map: &mut HashMap<CacheKey, Entry>) -> bool {
    let len = map.len();
    if len == 0 {
        return false;
    }
    let now = Instant::now();
    let sample = EVICTION_SAMPLE.min(len);
    let skip = if len > sample { rand::thread_rng().gen_range(0..len - sample + 1) } else { 0 };

    let mut victim_hash: Option<u64> = None;
    let mut victim_key: Option<CacheKey> = None;
    let mut oldest_tick = u64::MAX;
    let bh = map.hasher().clone();

    for (k, e) in map.iter().skip(skip).take(sample) {
        if e.expires_at <= now {
            victim_key = Some(k.clone());
            victim_hash = Some(make_hash(&bh, k.0, k.1, &k.2));
            break;
        }
        let tick = e.last_access.load(Ordering::Relaxed);
        if tick < oldest_tick {
            oldest_tick = tick;
            victim_key = Some(k.clone());
            victim_hash = Some(make_hash(&bh, k.0, k.1, &k.2));
        }
    }

    let (Some(hash), Some(key)) = (victim_hash, victim_key) else { return false };
    if let RawEntryMut::Occupied(o) = map
        .raw_entry_mut()
        .from_hash(hash, |k| key_eq(k, key.0, key.1, &key.2))
    {
        o.remove_entry();
        true
    } else {
        false
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_DNS_CACHE_TTL, DEFAULT_DNS_CACHE_CAPACITY)
    }
}

#[cfg(test)]
#[path = "tests/dns_cache.rs"]
mod tests;
