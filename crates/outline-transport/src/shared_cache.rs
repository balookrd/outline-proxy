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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

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

// ── Connection-lifecycle logging ──────────────────────────────────────────────

/// Class recorded on a connection that died because *we* dropped it — the
/// driver task never observed a protocol close because its `AbortOnDrop`
/// cancelled it first.
pub(crate) const CONN_CLASS_LOCAL_DROP: &str = "local_drop";

/// Verbosity of the open/close pair a connection emits on
/// `outline_transport::conn_life`.
///
/// A cached (shared) carrier is what an operator reasons about — how long it
/// lived, how many streams rode it, how it died — so it logs at `info`. A probe
/// connection is one-shot (dialled, measured, dropped) and outnumbers real
/// carriers by orders of magnitude — 34 515 opens in 48 h on one production
/// node — so it logs the very same pair at `debug`: the lifecycle stays fully
/// traceable when debug is on, without burying the carriers that matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnLifeLevel {
    Shared,
    Probe,
}

impl ConnLifeLevel {
    /// A dial that carries no cache key never enters the shared-connection
    /// registry — that is exactly the probe path in `shared_dial`.
    pub(crate) fn for_cached(is_cached: bool) -> Self {
        if is_cached { Self::Shared } else { Self::Probe }
    }
}

/// One connection's `conn_life` identity plus the "already logged" latch.
///
/// Two independent paths can observe the death of a shared H2/H3 connection:
/// the driver task (which sees the protocol-level close) and `Drop` (which runs
/// when the last `Arc` goes away, aborting the driver task before it can report
/// anything). Both go through [`ConnLife::close`]; the latch guarantees exactly
/// one close line per open line, so `opened`/`closed` counts in the log balance
/// and a genuine connection leak is visible as a real gap between them.
pub(crate) struct ConnLife {
    id: u64,
    peer: String,
    mode: &'static str,
    level: ConnLifeLevel,
    opened_at: Instant,
    /// Monotonic count of WS streams opened on this connection, shared with the
    /// connection itself so the close line reports the final total.
    streams_opened: Arc<AtomicU64>,
    closed: AtomicBool,
}

impl ConnLife {
    /// Log the connection open and return the tracker shared by the driver task
    /// and the connection's [`ConnLifeGuard`].
    pub(crate) fn open(
        id: u64,
        peer: String,
        mode: &'static str,
        level: ConnLifeLevel,
        streams_opened: Arc<AtomicU64>,
    ) -> Arc<Self> {
        match level {
            ConnLifeLevel::Shared => info!(
                target: "outline_transport::conn_life",
                id, peer = %peer, mode, "{mode} connection opened"
            ),
            ConnLifeLevel::Probe => debug!(
                target: "outline_transport::conn_life",
                id, peer = %peer, mode, "{mode} connection opened"
            ),
        }
        Arc::new(Self {
            id,
            peer,
            mode,
            level,
            opened_at: Instant::now(),
            streams_opened,
            closed: AtomicBool::new(false),
        })
    }

    /// Emit the close line, at most once per connection. Returns `true` when
    /// this call was the one that logged.
    ///
    /// `error_text = None` signals a close with no error to report (a clean
    /// `Ok(())` from the driver, or a local drop). Otherwise `class` describes
    /// the error bucket and `is_expected` gates the additional `error!` line;
    /// expected closes (graceful shutdown, local cancel, idle timeout already
    /// reported elsewhere) stay at the connection's own level to avoid noise.
    pub(crate) fn close(
        &self,
        error_text: Option<&str>,
        class: &'static str,
        is_expected: bool,
    ) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        let (id, peer, mode) = (self.id, self.peer.as_str(), self.mode);
        let age_secs = self.opened_at.elapsed().as_secs();
        let streams = self.streams_opened.load(Ordering::Relaxed);
        // The level is a runtime choice but `tracing` needs a static callsite,
        // so the three shapes are expanded once per level rather than branched
        // inside a single macro call.
        macro_rules! emit {
            ($level:ident) => {
                match error_text {
                    None => $level!(
                        target: "outline_transport::conn_life",
                        id, peer, mode, age_secs, streams, class,
                        "{mode} connection closed"
                    ),
                    Some(err) if is_expected => $level!(
                        target: "outline_transport::conn_life",
                        id, peer, mode, age_secs, streams, class, error = %err,
                        "{mode} connection closed"
                    ),
                    Some(err) => {
                        $level!(
                            target: "outline_transport::conn_life",
                            id, peer, mode, age_secs, streams, class, error = %err,
                            "{mode} connection closed with error"
                        );
                        error!("{mode} connection error: {err}");
                    },
                }
            };
        }
        match self.level {
            ConnLifeLevel::Shared => emit!(info),
            ConnLifeLevel::Probe => emit!(debug),
        }
        true
    }
}

/// Drop half of the `conn_life` open/close pair.
///
/// Held by the connection itself. The driver task that watches for a
/// protocol-level close is wrapped in an `AbortOnDrop`, so a connection dropped
/// locally — a probe released right after its measurement, a carrier evicted
/// from the cache once its last stream ended — cancels that task before it can
/// log anything. This guard closes that hole and classifies the death honestly
/// as [`CONN_CLASS_LOCAL_DROP`]; it is a no-op when the driver task already
/// reported.
pub(crate) struct ConnLifeGuard(Arc<ConnLife>);

impl ConnLifeGuard {
    pub(crate) fn new(life: Arc<ConnLife>) -> Self {
        Self(life)
    }
}

impl Drop for ConnLifeGuard {
    fn drop(&mut self) {
        self.0.close(None, CONN_CLASS_LOCAL_DROP, true);
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
        Self {
            server_name: Arc::from(server_name),
            server_port,
            fwmark,
        }
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

    /// Read-only lookup: return whatever is currently cached under `key`
    /// (open or stale) without evicting anything. Takes only a read-lock and
    /// has no side effects, so callers that want to *inspect* several entries
    /// — e.g. the H3 slot-picker weighing each carrier's live-stream count —
    /// can do so without churning the map. The caller decides what to do with
    /// a stale entry (`is_open()` == false).
    ///
    /// H3-only: the slot-picker is the sole caller, and it is compiled out
    /// without the `h3` feature — hence the gate, so a non-h3 build does not
    /// carry (and warn about) an unused method.
    #[cfg(feature = "h3")]
    pub(crate) async fn peek(&self, key: &K) -> Option<Arc<V>> {
        let map = self.map.read().await;
        map.get(key).cloned()
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

    /// Remove `key` only if the cached value still satisfies `pred`.
    ///
    /// The reaper decides what to drop from a census taken outside the lock, so
    /// a session can land on a carrier between the decision and the removal.
    /// Re-checking under the write lock keeps that race from evicting a carrier
    /// that just became busy. (Evicting one would not break the session — it
    /// holds its own `Arc` — but it would throw away a connection someone is
    /// using and force the next session to dial.)
    pub(crate) async fn remove_if(&self, key: &K, pred: impl Fn(&V) -> bool) -> bool {
        let mut map = self.map.write().await;
        if map.get(key).is_some_and(|conn| pred(conn)) {
            map.remove(key);
            return true;
        }
        false
    }

    /// Every cached entry with its key, for the reaper: it groups carriers by
    /// logical server, which the key carries and the value does not.
    pub(crate) async fn entries(&self) -> Vec<(K, Arc<V>)> {
        self.map
            .read()
            .await
            .iter()
            .map(|(key, conn)| (key.clone(), Arc::clone(conn)))
            .collect()
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

// ── Idle-carrier reaping ──────────────────────────────────────────────────────

/// One carrier as the reaper sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierIdleState {
    /// Slot this carrier occupies within its logical server.
    pub(crate) slot: u8,
    /// Streams or sessions riding it right now.
    pub(crate) active: u64,
    /// Consecutive maintenance sweeps that found it carrying nothing.
    pub(crate) idle_sweeps: u32,
}

/// Which carriers of one logical server should be closed.
///
/// A pooled carrier is never closed by QUIC itself: keep-alive PINGs (8–12 s)
/// outrun the idle timeout (28–35 s), so a connection opened during a burst
/// holds its UDP socket and its 2.87 MiB receive buffer until the process
/// exits. Measured on two lightly-loaded nodes on 2026-08-22: 3 and 6 carrier
/// flows against 24 live endpoints each, nine of them carrying nothing.
///
/// The policy keeps `min_keep` carriers as a warm floor — dialing costs a QUIC
/// and an HTTP/3 handshake, and a pool that empties itself between bursts pays
/// that on the next session — and closes the rest, oldest idle first. Carriers
/// that have not been idle for `required_sweeps` are left alone, so a brief lull
/// does not cost a connection.
pub(crate) fn carriers_to_reap(
    carriers: &[CarrierIdleState],
    min_keep: u8,
    required_sweeps: u32,
) -> Vec<u8> {
    let busy = carriers.iter().filter(|c| c.active > 0).count();
    // Idle but not yet eligible: still part of the warm floor.
    let young_idle = carriers
        .iter()
        .filter(|c| c.active == 0 && c.idle_sweeps < required_sweeps)
        .count();

    let mut eligible: Vec<&CarrierIdleState> = carriers
        .iter()
        .filter(|c| c.active == 0 && c.idle_sweeps >= required_sweeps)
        .collect();
    if eligible.is_empty() {
        return Vec::new();
    }

    // Longest-idle first, so what survives is the carrier most likely to be
    // wanted again. Ties by slot keep the outcome deterministic.
    eligible.sort_by(|a, b| b.idle_sweeps.cmp(&a.idle_sweeps).then_with(|| a.slot.cmp(&b.slot)));

    let keep = usize::from(min_keep).saturating_sub(busy + young_idle);
    let reap = eligible.len().saturating_sub(keep);
    eligible.iter().take(reap).map(|c| c.slot).collect()
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/shared_cache.rs"]
mod tests;
