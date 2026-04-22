//! Generic helpers for the H2 / H3 shared-connection caches.
//!
//! Both caches are `RwLock<HashMap<Key, Arc<Conn>>>` and share the same
//! two-phase GC pattern: scan under a read-lock, then upgrade to a write-lock
//! only if something was stale, and re-check under the write-lock to avoid
//! evicting a connection that became healthy between the two critical
//! sections.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{error, info};

// ── Error classification ──────────────────────────────────────────────────────

/// Classify a connection-close error by substring match against `table`.
/// Returns the first matching category (table order), or `fallback`.
///
/// The caller is responsible for any normalization (e.g. H2 lowercases `err`
/// once before calling; H3 matches mixed case directly).
pub(crate) fn classify_by_substrings(
    err: &str,
    table: &[(&[&str], &'static str)],
    fallback: &'static str,
) -> &'static str {
    for (needles, category) in table {
        if needles.iter().any(|n| err.contains(n)) {
            return category;
        }
    }
    fallback
}

// ── Connection-close logging ──────────────────────────────────────────────────

/// Identity fields common to every `conn_life` log line emitted from a driver
/// task.  Packaging them in a struct keeps the call site short and guarantees
/// H2 and H3 produce the same schema.
pub(crate) struct ConnCloseLog<'a> {
    pub id: u64,
    pub peer: &'a str,
    pub mode: &'static str,
    pub age_secs: u64,
    pub streams: u64,
}

/// Emit the standard `outline_transport::conn_life` close log.
///
/// `error_text = None` signals a clean close (`Ok(())` from the driver).
/// Otherwise `class` describes the error bucket and `is_expected` gates whether
/// an additional `error!` line is emitted; expected closes (graceful shutdown,
/// local cancel, idle timeout already reported elsewhere) stay at info level
/// to avoid log noise.
pub(crate) fn log_conn_close(
    fields: ConnCloseLog<'_>,
    error_text: Option<&str>,
    class: &'static str,
    is_expected: bool,
) {
    let ConnCloseLog { id, peer, mode, age_secs, streams } = fields;
    match error_text {
        None => {
            info!(
                target: "outline_transport::conn_life",
                id, peer, mode, age_secs, streams, class,
                "{mode} connection closed"
            );
        }
        Some(err) if is_expected => {
            info!(
                target: "outline_transport::conn_life",
                id, peer, mode, age_secs, streams, class, error = %err,
                "{mode} connection closed"
            );
        }
        Some(err) => {
            info!(
                target: "outline_transport::conn_life",
                id, peer, mode, age_secs, streams, class, error = %err,
                "{mode} connection closed with error"
            );
            error!("{mode} connection error: {err}");
        }
    }
}

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
struct ConnectLocks<K>(parking_lot::Mutex<HashMap<K, Arc<tokio::sync::Mutex<()>>>>);

impl<K: Eq + Hash + Clone> ConnectLocks<K> {
    fn new() -> Self {
        Self(parking_lot::Mutex::new(HashMap::new()))
    }

    fn get_lock(&self, key: &K) -> Arc<tokio::sync::Mutex<()>> {
        self.0.lock().entry(key.clone()).or_default().clone()
    }
}

// ── should_reuse ──────────────────────────────────────────────────────────────

/// Returns `true` if `source` should reuse a shared connection rather than
/// opening a fresh one.  Probe sources always open fresh connections so their
/// measurements reflect the cost of a cold path.
pub(crate) fn should_reuse_connection(source: &'static str) -> bool {
    !source.starts_with("probe_")
}

// ── SharedConnectionRegistry ──────────────────────────────────────────────────

/// Bundles the three pieces of state that every shared-connection cache needs:
/// a `RwLock<HashMap>` of live entries, an `AtomicU64` connection-id counter,
/// and a per-key `ConnectLocks` set that serialises reconnect attempts.
///
/// One instance per protocol lives behind a `OnceLock`; both H2 and H3 use this
/// type so neither has to reimplement the read-lock/write-lock dance, the
/// id-allocation pattern, or the connect-lock plumbing.
pub(crate) struct SharedConnectionRegistry<K, V> {
    map: RwLock<HashMap<K, Arc<V>>>,
    locks: ConnectLocks<K>,
    next_id: AtomicU64,
}

impl<K, V> SharedConnectionRegistry<K, V>
where
    K: Eq + Hash + Clone,
    V: CachedEntry,
{
    pub(crate) fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            locks: ConnectLocks::new(),
            // Start at 1 so a zeroed id is recognisably "uninitialised" if it
            // ever leaks into a log line.
            next_id: AtomicU64::new(1),
        }
    }

    /// Allocate the next unique connection id.  Used by the dial path when
    /// constructing a `SharedH2Connection` / `SharedH3Connection`.
    pub(crate) fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get (or create) the per-key reconnect mutex.
    pub(crate) fn connect_lock(&self, key: &K) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.get_lock(key)
    }

    /// Look up an open cached connection for `key`, evicting a stale entry if
    /// one is found.  Takes only a read-lock on the happy path.
    pub(crate) async fn cached(&self, key: &K) -> Option<Arc<V>> {
        let candidate = {
            let map = self.map.read().await;
            map.get(key).cloned()
        };
        match candidate {
            Some(conn) if conn.is_open() => Some(conn),
            Some(stale) => {
                // Slow path: take the write-lock only to evict the stale entry,
                // and re-check under it — another waiter may have already
                // replaced the entry with a fresh connection between our
                // read/write locks.
                let mut map = self.map.write().await;
                if map.get(key).is_some_and(|c| c.conn_id() == stale.conn_id()) {
                    map.remove(key);
                }
                None
            },
            None => None,
        }
    }

    /// Insert `connection` under `key` unless a live connection already
    /// occupies the slot (a concurrent task may have raced ahead and cached
    /// one first).
    pub(crate) async fn insert(&self, key: K, connection: Arc<V>) {
        let mut map = self.map.write().await;
        match map.get(&key) {
            Some(existing) if existing.is_open() => {},
            _ => {
                map.insert(key, connection);
            },
        }
    }

    /// Remove the entry for `key` only if it still matches `id`. A cheap
    /// read-lock pre-check avoids the write-lock on the common path (entry
    /// gone or already replaced by a fresh connection).
    pub(crate) async fn invalidate_if_current(&self, key: &K, id: u64) {
        let needs_evict = {
            let map = self.map.read().await;
            map.get(key).is_some_and(|c| c.conn_id() == id)
        };
        if !needs_evict {
            return;
        }
        let mut map = self.map.write().await;
        if map.get(key).is_some_and(|c| c.conn_id() == id) {
            map.remove(key);
        }
    }

    /// Remove every entry whose value reports `is_open() == false`.
    ///
    /// Called from the warm-standby maintenance loop so dead entries do not
    /// linger indefinitely when no new request re-checks their key (e.g.
    /// after DNS rotation changes the resolved address for a server name).
    pub(crate) async fn gc(&self) {
        // Fast path: scan under a read-lock. If nothing is stale we avoid the
        // write-lock entirely, so a healthy GC tick does not interfere with
        // concurrent lookups.
        let stale_keys: Vec<K> = {
            let map = self.map.read().await;
            map.iter()
                .filter(|(_, conn)| !conn.is_open())
                .map(|(k, _)| k.clone())
                .collect()
        };
        if stale_keys.is_empty() {
            return;
        }
        let mut map = self.map.write().await;
        for key in stale_keys {
            if map.get(&key).is_some_and(|conn| !conn.is_open()) {
                map.remove(&key);
            }
        }
    }
}

// ── with_reuse ────────────────────────────────────────────────────────────────

/// Skeleton for the "reuse-or-dial" connect path used by both H2 and H3.
///
/// The flow is identical for both transports:
///   1. Fast path: look up a cached connection and try `open_existing` on it.
///      Success returns immediately; failure invalidates the cache entry.
///   2. Take the per-key connect lock so concurrent reconnect attempts share
///      the result rather than each starting their own handshake.
///   3. Re-check the cache under the lock — another waiter may have raced
///      ahead and established a fresh connection.
///   4. Call `dial` to do whatever transport-specific work is needed (DNS
///      resolution, address-list iteration, TLS, h2/h3 handshake) and produce
///      both the new shared connection and the first stream opened on it.
///   5. Insert the new connection into the cache and return the stream.
///
/// `open_existing` is responsible for protocol-specific logging and metric
/// emission; `dial` is responsible for the DNS / handshake / metric handling
/// of the cold path.  Anything that returns `Err` from `open_existing` is
/// treated as a sick connection — the entry is invalidated and we fall through
/// to the dial path.
pub(crate) async fn with_reuse<K, V, T, OFut, DFut>(
    registry: &SharedConnectionRegistry<K, V>,
    key: K,
    open_existing: impl Fn(Arc<V>) -> OFut,
    dial: impl FnOnce() -> DFut,
) -> Result<T>
where
    K: Eq + Hash + Clone,
    V: CachedEntry,
    OFut: Future<Output = Result<T>>,
    DFut: Future<Output = Result<(Arc<V>, T)>>,
{
    if let Some(shared) = registry.cached(&key).await {
        let id = shared.conn_id();
        match open_existing(shared).await {
            Ok(stream) => return Ok(stream),
            Err(_) => registry.invalidate_if_current(&key, id).await,
        }
    }

    let connect_lock = registry.connect_lock(&key);
    let _connect_guard = connect_lock.lock().await;

    if let Some(shared) = registry.cached(&key).await {
        let id = shared.conn_id();
        match open_existing(shared).await {
            Ok(stream) => return Ok(stream),
            Err(_) => registry.invalidate_if_current(&key, id).await,
        }
    }

    let (shared, stream) = dial().await?;
    registry.insert(key, shared).await;
    Ok(stream)
}
