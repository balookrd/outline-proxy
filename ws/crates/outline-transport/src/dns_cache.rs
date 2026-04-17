use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Default TTL used by [`DnsCache::default`] — matches typical DNS record
/// windows and the previous global cache behaviour.
pub const DEFAULT_DNS_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Entry {
    /// Already sorted according to the `ipv6_first` bit in the outer key —
    /// callers receive a ready-to-use ordered slice without re-sorting on
    /// each hit.
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
}

/// In-memory cache of resolved `(port, ipv6_first, host) → Arc<[SocketAddr]>`
/// mappings.
///
/// The `ipv6_first` preference is baked into the key and the stored slice is
/// pre-sorted accordingly, so a cache hit is one hash + one `Arc::clone`
/// with no allocation and no sort work on the hot path.
///
/// Constructed explicitly and passed by reference to the transport resolve
/// functions; the main binary owns a single `Arc<DnsCache>` and threads it
/// through the uplink / tun / proxy paths. This makes the cache injectable
/// for tests instead of a process-global `OnceLock` that leaks state
/// between test cases.
#[derive(Debug)]
pub struct DnsCache {
    // Outer key: (port, ipv6_first). Inner key: host (String).
    // `HashMap::get(&str)` works against `HashMap<String, _>` via
    // `Borrow<str>` — no allocation per lookup.
    inner: RwLock<HashMap<(u16, bool), HashMap<String, Entry>>>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self { inner: RwLock::new(HashMap::new()), ttl }
    }

    pub fn get(&self, host: &str, port: u16, ipv6_first: bool) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        let entry = map.get(&(port, ipv6_first))?.get(host)?;
        (Instant::now() < entry.expires_at).then(|| Arc::clone(&entry.addrs))
    }

    pub fn get_stale(
        &self,
        host: &str,
        port: u16,
        ipv6_first: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        let map = self.inner.read();
        map.get(&(port, ipv6_first))?
            .get(host)
            .map(|entry| Arc::clone(&entry.addrs))
    }

    pub fn insert(&self, host: &str, port: u16, ipv6_first: bool, addrs: Arc<[SocketAddr]>) {
        let mut map = self.inner.write();
        map.entry((port, ipv6_first))
            .or_default()
            .insert(host.to_owned(), Entry { addrs, expires_at: Instant::now() + self.ttl });
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_CACHE_TTL)
    }
}
