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
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use parking_lot::RwLock;
use tokio::time::Duration;

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    resolved: Arc<[SocketAddr]>,
    expires_at: std::time::Instant,
}

// Outer key: (port, prefer_ipv4_upstream) — cheap to construct without allocation.
// Inner key: host String — supports &str lookup via String: Borrow<str>.
pub(super) struct DnsCache {
    entries: RwLock<HashMap<(u16, bool), HashMap<String, DnsCacheEntry>>>,
    ttl: Duration,
}

impl DnsCache {
    pub(super) fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
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
        let entries = self.entries.read();
        let entry = entries.get(&(port, prefer_ipv4_upstream)).and_then(|inner| inner.get(host))?;
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
        let entries = self.entries.read();
        entries
            .get(&(port, prefer_ipv4_upstream))
            .and_then(|inner| inner.get(host))
            .map(|entry| Arc::clone(&entry.resolved))
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
        let entry = DnsCacheEntry {
            resolved,
            expires_at: std::time::Instant::now() + self.ttl,
        };
        self.entries
            .write()
            .entry((port, prefer_ipv4_upstream))
            .or_default()
            .insert(host.to_owned(), entry);
    }

    /// Removes entries whose expiry is older than `stale_grace` — callers that
    /// want to keep stale entries around for fallback should pass a grace
    /// period longer than the cache TTL. Returns the number of purged entries.
    pub(super) fn sweep_expired(&self, stale_grace: Duration) -> usize {
        let cutoff = std::time::Instant::now().checked_sub(stale_grace);
        let Some(cutoff) = cutoff else {
            return 0;
        };
        let mut purged = 0;
        let mut entries = self.entries.write();
        entries.retain(|_, inner| {
            inner.retain(|_, entry| {
                let keep = entry.expires_at > cutoff;
                if !keep {
                    purged += 1;
                }
                keep
            });
            !inner.is_empty()
        });
        purged
    }
}
