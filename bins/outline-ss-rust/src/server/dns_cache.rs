//! In-memory DNS cache shared by the websocket/H3 server and the native
//! Shadowsocks listeners.
//!
//! The map itself — keyed by `(port, prefer_ipv4_upstream, host)`, raw-entry
//! probing, stale-fallback reads, janitor sweep — is the shared
//! [`outline_net::dns_cache::DnsCache`] core. This wrapper adds the
//! server-only singleflight layer: concurrent misses on the same key
//! coalesce onto one in-flight `lookup_host` future. TCP callers consume
//! the whole slice for Happy Eyeballs ordering; UDP callers pick the first
//! entry.
//!
//! The host half of the key is the client-supplied destination, so the
//! production cache is built bounded ([`DnsCache::with_capacity`], sized by
//! `tuning.dns_cache_max_entries`): a client resolving unique names is capped
//! by insert-time approximate-LRU eviction instead of growing the map for the
//! whole TTL + stale-grace window. The periodic [`DnsCache::sweep_expired`]
//! tick still runs — it purges entries past the stale-grace fallback window
//! that eviction may never reach — and is the *only* reclaim path when the
//! cap is disabled ([`DnsCache::new`], the unbounded flavour).

use std::{
    collections::HashMap as StdHashMap,
    future::Future,
    net::SocketAddr,
    sync::{Arc, Weak},
};

use anyhow::Result;
use futures_util::future::{BoxFuture, FutureExt, Shared};
use parking_lot::Mutex;
use tokio::time::Duration;

type SharedResolve =
    Shared<BoxFuture<'static, std::result::Result<Arc<[SocketAddr]>, Arc<anyhow::Error>>>>;
type InFlightKey = (u16, bool, Box<str>);

pub(super) struct DnsCache {
    core: outline_net::dns_cache::DnsCache,
    // Singleflight map: coalesces concurrent misses on the same key so only
    // one `lookup_host` call is in-flight per (port, prefer_ipv4, host).
    // Stores `Weak` so slots that were dropped before completion don't pin
    // memory — the next caller overwrites the stale weak.
    in_flight: Mutex<StdHashMap<InFlightKey, Weak<SharedResolve>>>,
    me: Weak<Self>,
}

impl DnsCache {
    /// Unbounded cache: entries are reclaimed only by the periodic
    /// [`Self::sweep_expired`] janitor. Prefer [`Self::with_capacity`] on
    /// paths that resolve client-controlled hosts.
    pub(super) fn new(ttl: Duration) -> Arc<Self> {
        Self::wrap(outline_net::dns_cache::DnsCache::new(ttl))
    }

    /// Cache bounded to `max_entries` (insert-time approximate-LRU eviction).
    /// `max_entries == 0` is the documented opt-out and yields the unbounded
    /// [`Self::new`] flavour.
    pub(super) fn with_capacity(ttl: Duration, max_entries: usize) -> Arc<Self> {
        match max_entries {
            0 => Self::new(ttl),
            cap => Self::wrap(outline_net::dns_cache::DnsCache::with_capacity(ttl, cap)),
        }
    }

    fn wrap(core: outline_net::dns_cache::DnsCache) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            core,
            in_flight: Mutex::new(StdHashMap::new()),
            me: me.clone(),
        })
    }

    pub(super) fn lookup_all(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        self.core.get(host, port, prefer_ipv4_upstream)
    }

    /// Returns cached addresses regardless of expiry. Intended as a last-ditch
    /// fallback when the upstream resolver fails — prefer [`Self::lookup_all`]
    /// for the hot path.
    pub(super) fn lookup_all_stale(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<Arc<[SocketAddr]>> {
        self.core.get_stale(host, port, prefer_ipv4_upstream)
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
        self.core.insert(host, port, prefer_ipv4_upstream, resolved);
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

        (*shared).clone().await.map_err(|e| anyhow::anyhow!("{:#}", e))
    }

    /// Removes entries whose expiry is older than `stale_grace` — callers that
    /// want to keep stale entries around for fallback should pass a grace
    /// period longer than the cache TTL. Returns the number of purged entries.
    pub(super) fn sweep_expired(&self, stale_grace: Duration) -> usize {
        self.core.sweep_expired(stale_grace)
    }
}
