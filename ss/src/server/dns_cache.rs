//! In-memory DNS cache shared by the websocket/H3 server and the native
//! Shadowsocks listeners.
//!
//! Entries are keyed by `(port, prefer_ipv4_upstream, host)` and store the
//! fully filtered set of resolved [`SocketAddr`]s. TCP callers consume the
//! whole slice for Happy Eyeballs ordering; UDP callers pick the first entry.
//! Expired entries are kept in memory so that [`lookup_all_stale`] can serve
//! them as a fallback when the upstream resolver temporarily fails; fresh
//! data overwrites them on the next successful lookup.

use std::{
    collections::HashMap as StdHashMap,
    future::Future,
    hash::{BuildHasher, Hash, Hasher},
    net::SocketAddr,
    sync::{Arc, Weak},
};

use anyhow::Result;
use futures_util::future::{BoxFuture, FutureExt, Shared};
use hashbrown::{DefaultHashBuilder, HashMap, hash_map::RawEntryMut};
use parking_lot::{Mutex, RwLock};
use tokio::time::Duration;

type SharedResolve =
    Shared<BoxFuture<'static, std::result::Result<Arc<[SocketAddr]>, Arc<anyhow::Error>>>>;
type InFlightKey = (u16, bool, Box<str>);

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    resolved: Arc<[SocketAddr]>,
    expires_at: std::time::Instant,
}

// Tuple layout matches hash computation order: port, prefer_ipv4_upstream, host.
struct CacheKey(u16, bool, Box<str>);

impl CacheKey {
    fn matches(&self, port: u16, prefer_ipv4_upstream: bool, host: &str) -> bool {
        self.0 == port && self.1 == prefer_ipv4_upstream && &*self.2 == host
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2.hash(state);
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}

impl Eq for CacheKey {}

fn compute_hash(bh: &impl BuildHasher, port: u16, prefer_ipv4_upstream: bool, host: &str) -> u64 {
    let mut h = bh.build_hasher();
    port.hash(&mut h);
    prefer_ipv4_upstream.hash(&mut h);
    host.hash(&mut h);
    h.finish()
}

pub(super) struct DnsCache {
    entries: RwLock<HashMap<CacheKey, DnsCacheEntry, DefaultHashBuilder>>,
    // Stored separately so raw_entry_mut closures can borrow it without
    // aliasing the mutable map borrow in insert_with_hasher's rehash closure.
    build_hasher: DefaultHashBuilder,
    // Singleflight map: coalesces concurrent misses on the same key so only
    // one `lookup_host` call is in-flight per (port, prefer_ipv4, host).
    // Stores `Weak` so slots that were dropped before completion don't pin
    // memory — the next caller overwrites the stale weak.
    in_flight: Mutex<StdHashMap<InFlightKey, Weak<SharedResolve>>>,
    me: Weak<Self>,
    ttl: Duration,
}

impl DnsCache {
    pub(super) fn new(ttl: Duration) -> Arc<Self> {
        let build_hasher = DefaultHashBuilder::default();
        Arc::new_cyclic(|me| Self {
            entries: RwLock::new(HashMap::with_hasher(build_hasher)),
            build_hasher,
            in_flight: Mutex::new(StdHashMap::new()),
            me: me.clone(),
            ttl,
        })
    }

    pub(super) fn lookup_all(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        let now = std::time::Instant::now();
        let hash = compute_hash(&self.build_hasher, port, prefer_ipv4_upstream, host);
        let entries = self.entries.read();
        let (_, entry) = entries
            .raw_entry()
            .from_hash(hash, |k| k.matches(port, prefer_ipv4_upstream, host))?;
        (entry.expires_at > now).then(|| Arc::clone(&entry.resolved))
    }

    /// Returns cached addresses regardless of expiry. Intended as a last-ditch
    /// fallback when the upstream resolver fails — prefer [`lookup_all`] for
    /// the hot path.
    pub(super) fn lookup_all_stale(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        let hash = compute_hash(&self.build_hasher, port, prefer_ipv4_upstream, host);
        let entries = self.entries.read();
        let (_, entry) = entries
            .raw_entry()
            .from_hash(hash, |k| k.matches(port, prefer_ipv4_upstream, host))?;
        Some(Arc::clone(&entry.resolved))
    }

    pub(super) fn lookup_one(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<SocketAddr> {
        self.lookup_all(host, port, prefer_ipv4_upstream)
            .and_then(|addrs| addrs.first().copied())
    }

    pub(super) fn store(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
        resolved: Arc<[SocketAddr]>,
    ) {
        let hash = compute_hash(&self.build_hasher, port, prefer_ipv4_upstream, host);
        let new_entry = DnsCacheEntry {
            resolved,
            expires_at: std::time::Instant::now() + self.ttl,
        };
        // `self.build_hasher` is independent of `entries`, so the rehash closure
        // below can borrow it while `entries` is mutably borrowed.
        let mut entries = self.entries.write();
        match entries
            .raw_entry_mut()
            .from_hash(hash, |k| k.matches(port, prefer_ipv4_upstream, host))
        {
            RawEntryMut::Occupied(mut occ) => {
                *occ.get_mut() = new_entry;
            }
            RawEntryMut::Vacant(vac) => {
                vac.insert_with_hasher(
                    hash,
                    CacheKey(port, prefer_ipv4_upstream, host.into()),
                    new_entry,
                    |k| compute_hash(&self.build_hasher, k.0, k.1, &k.2),
                );
            }
        }
    }

    /// Coalesces concurrent DNS misses for the same key: the first caller
    /// drives `loader`, followers await the same shared future. The result
    /// is also checked under the in-flight lock to avoid racing with a
    /// loader that just finished and populated the cache.
    pub(super) async fn resolve_or_join<F, Fut>(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
        loader: F,
    ) -> Result<Arc<[SocketAddr]>>
    where
        F: FnOnce(Arc<Self>) -> Fut,
        Fut: Future<Output = Result<Arc<[SocketAddr]>>> + Send + 'static,
    {
        if let Some(hit) = self.lookup_all(host, port, prefer_ipv4_upstream) {
            return Ok(hit);
        }

        let me = self.me.upgrade().expect("DnsCache dropped while in use");
        let shared: Arc<SharedResolve> = {
            let mut in_flight = self.in_flight.lock();
            // Re-check under the lock: a loader may have finished and stored
            // to the cache between our first check and acquiring this lock.
            if let Some(hit) = self.lookup_all(host, port, prefer_ipv4_upstream) {
                return Ok(hit);
            }
            let key: InFlightKey = (port, prefer_ipv4_upstream, Box::<str>::from(host));
            if let Some(existing) = in_flight.get(&key).and_then(Weak::upgrade) {
                existing
            } else {
                let cleanup_key = key.clone();
                let cleanup_cache = Arc::clone(&me);
                let loader_fut = loader(Arc::clone(&me));
                let fut: BoxFuture<'static, _> = async move {
                    let result = loader_fut.await.map_err(Arc::new);
                    cleanup_cache.in_flight.lock().remove(&cleanup_key);
                    result
                }
                .boxed();
                let arc = Arc::new(fut.shared());
                in_flight.insert(key, Arc::downgrade(&arc));
                arc
            }
        };

        (*shared)
            .clone()
            .await
            .map_err(|e| anyhow::anyhow!("{:#}", e))
    }

    /// Removes entries whose expiry is older than `stale_grace` — callers that
    /// want to keep stale entries around for fallback should pass a grace
    /// period longer than the cache TTL. Returns the number of purged entries.
    pub(super) fn sweep_expired(&self, stale_grace: Duration) -> usize {
        let cutoff = std::time::Instant::now().checked_sub(stale_grace);
        let Some(cutoff) = cutoff else {
            return 0;
        };
        let mut purged = 0usize;
        self.entries.write().retain(|_, entry| {
            let keep = entry.expires_at > cutoff;
            if !keep {
                purged += 1;
            }
            keep
        });
        purged
    }
}
