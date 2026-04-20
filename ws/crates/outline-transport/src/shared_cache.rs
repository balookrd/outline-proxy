//! Generic helpers for the H2 / H3 shared-connection caches.
//!
//! Both caches are `RwLock<HashMap<Key, Arc<Conn>>>` and share the same
//! two-phase GC pattern: scan under a read-lock, then upgrade to a write-lock
//! only if something was stale, and re-check under the write-lock to avoid
//! evicting a connection that became healthy between the two critical
//! sections.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Hostname-based identity of a cached shared connection.
///
/// The key is deliberately hostname-based rather than IP-based: if the DNS
/// answer for a server name changes, the old cached connection keeps serving
/// existing traffic until it fails naturally, at which point a fresh
/// connection is made to the (now re-resolved) new address. `fwmark` is part
/// of the key because connections bound with different fwmarks must not be
/// shared (they take different egress paths on Linux policy-routed hosts).
///
/// H2 additionally distinguishes `wss://` from `ws://`; it composes this
/// struct with its own `use_tls` flag. H3 is always TLS-over-QUIC so it uses
/// this struct directly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ConnectionKey {
    pub(crate) server_name: Arc<str>,
    pub(crate) server_port: u16,
    pub(crate) fwmark: Option<u32>,
}

impl ConnectionKey {
    pub(crate) fn new(server_name: &str, server_port: u16, fwmark: Option<u32>) -> Self {
        Self { server_name: Arc::from(server_name), server_port, fwmark }
    }
}

/// Remove every entry for which `is_open(&value)` returns `false`.
///
/// Called from the warm-standby maintenance loop so dead entries do not
/// linger indefinitely when no new request re-checks their key (e.g. after
/// DNS rotation changes the resolved address for a server name).
pub(crate) async fn gc_stale_entries<K, V, F>(
    lock: &RwLock<HashMap<K, Arc<V>>>,
    is_open: F,
) where
    K: Eq + Hash + Clone,
    F: Fn(&V) -> bool,
{
    // Fast path: scan under a read-lock. If nothing is stale we avoid the
    // write-lock entirely, so a healthy GC tick does not interfere with
    // concurrent lookups.
    let stale_keys: Vec<K> = {
        let map = lock.read().await;
        map.iter()
            .filter(|(_, conn)| !is_open(conn))
            .map(|(k, _)| k.clone())
            .collect()
    };
    if stale_keys.is_empty() {
        return;
    }
    let mut map = lock.write().await;
    for key in stale_keys {
        if map.get(&key).is_some_and(|conn| !is_open(conn)) {
            map.remove(&key);
        }
    }
}
