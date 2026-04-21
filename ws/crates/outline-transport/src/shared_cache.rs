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

// ── CachedEntry ───────────────────────────────────────────────────────────────

/// Minimum interface a cached connection value must expose.
///
/// Both `SharedH2Connection` and `SharedH3Connection` implement this so the
/// generic cache helpers below work over either type without knowing the
/// transport-specific details.
pub(crate) trait CachedEntry {
    fn conn_id(&self) -> u64;
    fn is_open(&self) -> bool;
}

// ── ConnectLocks ──────────────────────────────────────────────────────────────

/// Serialises concurrent connection-establishment attempts per cache key.
///
/// Both H2 and H3 use this pattern to prevent a thundering herd when the
/// shared connection drops: the first task to acquire the inner
/// `tokio::sync::Mutex` for a given key establishes the new connection and
/// caches it; all other tasks re-check the cache after acquiring the lock and
/// reuse the result.  Lock entries are never removed; they remain as empty
/// `Mutex<()>` values (a few bytes each) — acceptable because the set of
/// distinct server keys is small.
pub(crate) struct ConnectLocks<K>(parking_lot::Mutex<HashMap<K, Arc<tokio::sync::Mutex<()>>>>);

impl<K: Eq + Hash + Clone> ConnectLocks<K> {
    pub(crate) fn new() -> Self {
        Self(parking_lot::Mutex::new(HashMap::new()))
    }

    pub(crate) fn get_lock(&self, key: &K) -> Arc<tokio::sync::Mutex<()>> {
        self.0.lock().entry(key.clone()).or_default().clone()
    }
}

// ── Generic cache helpers ─────────────────────────────────────────────────────

/// Returns `true` if `source` should reuse a shared connection rather than
/// opening a fresh one.  Probe sources always open fresh connections so their
/// measurements reflect the cost of a cold path.
pub(crate) fn should_reuse_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
}

/// Look up an open cached connection for `key`, evicting a stale entry if one
/// is found.  Takes only a read-lock on the happy path.
pub(crate) async fn cached_connection<K, V>(
    lock: &RwLock<HashMap<K, Arc<V>>>,
    key: &K,
) -> Option<Arc<V>>
where
    K: Eq + Hash + Clone,
    V: CachedEntry,
{
    let candidate = {
        let map = lock.read().await;
        map.get(key).cloned()
    };
    match candidate {
        Some(conn) if conn.is_open() => Some(conn),
        Some(stale) => {
            // Slow path: take the write-lock only to evict the stale entry,
            // and re-check under it — another waiter may have already replaced
            // the entry with a fresh connection between our read/write locks.
            let mut map = lock.write().await;
            if map.get(key).is_some_and(|c| c.conn_id() == stale.conn_id()) {
                map.remove(key);
            }
            None
        },
        None => None,
    }
}

/// Insert `connection` under `key` unless a live connection already occupies
/// the slot (a concurrent task may have raced ahead and cached one first).
pub(crate) async fn cache_connection<K, V>(
    lock: &RwLock<HashMap<K, Arc<V>>>,
    key: K,
    connection: Arc<V>,
)
where
    K: Eq + Hash,
    V: CachedEntry,
{
    let mut map = lock.write().await;
    match map.get(&key) {
        Some(existing) if existing.is_open() => {},
        _ => {
            map.insert(key, connection);
        },
    }
}

/// Remove the entry for `key` from `lock` only if it still matches `id`.
/// A cheap read-lock pre-check avoids the write-lock on the common path
/// (entry gone or already replaced by a fresh connection).
pub(crate) async fn invalidate_if_current<K, V>(
    lock: &RwLock<HashMap<K, Arc<V>>>,
    key: &K,
    id: u64,
)
where
    K: Eq + Hash,
    V: CachedEntry,
{
    let needs_evict = {
        let map = lock.read().await;
        map.get(key).is_some_and(|c| c.conn_id() == id)
    };
    if !needs_evict {
        return;
    }
    let mut map = lock.write().await;
    if map.get(key).is_some_and(|c| c.conn_id() == id) {
        map.remove(key);
    }
}

/// Remove every entry for which `is_open(&value)` returns `false`.
///
/// Called from the warm-standby maintenance loop so dead entries do not
/// linger indefinitely when no new request re-checks their key (e.g.
/// after DNS rotation changes the resolved address for a server name).
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
