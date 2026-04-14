//! Shared application state and the UDP DNS cache used by the websocket/H3 server.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use tokio::time::Duration;

use crate::{crypto::UserKey, metrics::Metrics, nat::NatTable};

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) users: Arc<[UserKey]>,
    pub(super) tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    pub(super) udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) nat_table: Arc<NatTable>,
    pub(super) udp_dns_cache: Arc<UdpDnsCache>,
    pub(super) prefer_ipv4_upstream: bool,
    pub(super) http_root_auth: bool,
    pub(super) http_root_realm: Arc<str>,
}

#[derive(Clone)]
pub(super) struct TransportRoute {
    pub(super) users: Arc<[UserKey]>,
    pub(super) candidate_users: Arc<[String]>,
}

pub(super) fn empty_transport_route() -> TransportRoute {
    TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<String>::new().into_boxed_slice()),
    }
}

#[derive(Clone, Copy, Debug)]
struct UdpDnsCacheEntry {
    resolved: SocketAddr,
    expires_at: std::time::Instant,
}

// Outer key: (port, prefer_ipv4_upstream) — cheap to construct without allocation.
// Inner key: host String — supports &str lookup via String: Borrow<str>.
pub(super) struct UdpDnsCache {
    entries: RwLock<HashMap<(u16, bool), HashMap<String, UdpDnsCacheEntry>>>,
    ttl: Duration,
}

impl UdpDnsCache {
    pub(super) fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        })
    }

    pub(super) fn lookup(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
    ) -> Option<SocketAddr> {
        let now = std::time::Instant::now();
        {
            let entries = self.entries.read().expect("udp dns cache poisoned");
            if let Some(entry) = entries
                .get(&(port, prefer_ipv4_upstream))
                .and_then(|inner| inner.get(host))
                .copied()
            {
                if entry.expires_at > now {
                    return Some(entry.resolved);
                }
            } else {
                return None;
            }
        }
        // Entry exists but is expired — acquire write lock to evict it.
        let mut entries = self.entries.write().expect("udp dns cache poisoned");
        if let Some(inner) = entries.get_mut(&(port, prefer_ipv4_upstream)) {
            if inner.get(host).is_some_and(|e| e.expires_at <= now) {
                inner.remove(host);
            }
        }
        None
    }

    pub(super) fn store(
        &self,
        host: &str,
        port: u16,
        prefer_ipv4_upstream: bool,
        resolved: SocketAddr,
    ) {
        let entry = UdpDnsCacheEntry {
            resolved,
            expires_at: std::time::Instant::now() + self.ttl,
        };
        self.entries
            .write()
            .expect("udp dns cache poisoned")
            .entry((port, prefer_ipv4_upstream))
            .or_default()
            .insert(host.to_owned(), entry);
    }
}
