use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use hashbrown::hash_map::RawEntryMut;
use parking_lot::RwLock;

/// Default TTL used by [`DnsCache::default`] — matches typical DNS record
/// windows and the previous global cache behaviour.
pub const DEFAULT_DNS_CACHE_TTL: Duration = Duration::from_secs(60);

type CacheKey = (u16, bool, Box<str>);

#[derive(Debug)]
struct Entry {
    /// Already sorted according to the `ipv6_first` bit in the key —
    /// callers receive a ready-to-use ordered slice without re-sorting on
    /// each hit.
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
}

/// In-memory cache of resolved `(port, ipv6_first, host) → Arc<[SocketAddr]>`
/// mappings.
///
/// Flat `HashMap<(u16, bool, Box<str>), Entry>` keyed by a single compound
/// hash.  `get` / `get_stale` use the raw-entry API to probe with `&str`
/// directly — one hash computation, one table probe, no heap allocation.
/// `insert` takes a write lock once and updates in-place on a hit.
#[derive(Debug)]
pub struct DnsCache {
    inner: RwLock<HashMap<CacheKey, Entry>>,
    ttl: Duration,
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
    pub fn new(ttl: Duration) -> Self {
        Self { inner: RwLock::new(HashMap::new()), ttl }
    }

    pub fn get(&self, host: &str, port: u16, ipv6_first: bool) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        let hash = make_hash(map.hasher(), port, ipv6_first, host);
        let (_, entry) = map
            .raw_entry()
            .from_hash(hash, |k| key_eq(k, port, ipv6_first, host))?;
        (Instant::now() < entry.expires_at).then(|| Arc::clone(&entry.addrs))
    }

    pub fn get_stale(
        &self,
        host: &str,
        port: u16,
        ipv6_first: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        let hash = make_hash(map.hasher(), port, ipv6_first, host);
        map.raw_entry()
            .from_hash(hash, |k| key_eq(k, port, ipv6_first, host))
            .map(|(_, entry)| Arc::clone(&entry.addrs))
    }

    pub fn insert(&self, host: &str, port: u16, ipv6_first: bool, addrs: Arc<[SocketAddr]>) {
        let mut map = self.inner.write();
        // Clone the BuildHasher before the mutable borrow so we can reuse it
        // inside `insert_with_hasher` without a second borrow of `map`.
        let bh = map.hasher().clone();
        let hash = make_hash(&bh, port, ipv6_first, host);
        let new_entry = Entry { addrs, expires_at: Instant::now() + self.ttl };
        match map.raw_entry_mut().from_hash(hash, |k| key_eq(k, port, ipv6_first, host)) {
            RawEntryMut::Occupied(mut o) => {
                *o.get_mut() = new_entry;
            }
            RawEntryMut::Vacant(v) => {
                v.insert_with_hasher(hash, (port, ipv6_first, host.into()), new_entry, |k| {
                    make_hash(&bh, k.0, k.1, &k.2)
                });
            }
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_CACHE_TTL)
    }
}
