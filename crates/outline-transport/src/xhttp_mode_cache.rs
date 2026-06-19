//! Per-host downgrade memory for the XHTTP transport-mode fallback
//! chain (`xhttp_h3 → xhttp_h2 → xhttp_h1`).
//!
//! Sibling of [`crate::ws_mode_cache`] — the WS cache covers the
//! `WsH3 → WsH2 → WsH1` chain, this one covers XHTTP. They are kept
//! separate so a `record_failure` on one chain does not clobber the
//! cap of the other when several uplinks share the same `(host, port)`
//! but use different transports.
//!
//! Like the WS cache, two strategies share this store, selected once at startup
//! by [`crate::init_health_weighting`]: the legacy binary downgrade cap, and the
//! default-on liveness weighting (decaying per-rank penalties; see
//! [`crate::mode_health`]) that picks the start rank probabilistically so a
//! flaky carrier is preferred less but still retried and recovers over time.
//!
//! The cap / penalty is per `(host, port)` and decays by TTL so that a
//! transient outage (server restart, route flap) does not permanently pin the
//! host to `xhttp_h1`.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use url::Url;

use crate::config::TransportMode;
use crate::mode_health::{self, ModePenalty};

/// Default TTL applied when [`init_downgrade_ttl`] has not been
/// called. Matches `ws_mode_cache::DEFAULT_DOWNGRADE_TTL` and the
/// `LoadBalancingConfig::mode_downgrade_duration` default in
/// `outline-uplink`, so a binary that never wires startup config
/// behaves consistently across both caches and the per-uplink
/// soft-window.
const DEFAULT_DOWNGRADE_TTL: Duration = Duration::from_secs(60);

/// Process-wide TTL for the per-host XHTTP downgrade cache. Set once
/// at startup from [`init_downgrade_ttl`] (shared knob with the WS
/// cache); subsequent set attempts are silently ignored. The two
/// caches use independent `OnceLock`s so a future caller could pass
/// asymmetric TTLs without re-plumbing the API.
static DOWNGRADE_TTL: OnceLock<Duration> = OnceLock::new();

fn downgrade_ttl() -> Duration {
    DOWNGRADE_TTL.get().copied().unwrap_or(DEFAULT_DOWNGRADE_TTL)
}

/// Initialise [`downgrade_ttl`]. First call wins; subsequent calls
/// are silently ignored. The bootstrap path passes the same value
/// it hands to [`crate::ws_mode_cache::init_downgrade_ttl`] — the
/// two caches are conceptually one knob, just stored in independent
/// per-family slots so one chain's `record_failure` cannot clobber
/// the other's cap.
pub fn init_downgrade_ttl(ttl: Duration) {
    let _ = DOWNGRADE_TTL.set(ttl);
}

#[derive(Clone, Copy)]
struct Entry {
    /// Legacy binary downgrade cap. Authoritative only when weighting is
    /// disabled; left at the topmost mode (no clamp) when weighting drives
    /// selection.
    max_mode: TransportMode,
    /// Per-rank decaying liveness penalty, indexed by [`rank`] (`0` = XhttpH1,
    /// `1` = XhttpH2, `2` = XhttpH3). Authoritative only when weighting is on.
    penalty: [ModePenalty; 3],
    expires_at: Instant,
}

/// True if `mode` belongs to the XHTTP family this cache governs.
/// Used by [`effective_mode`] / [`record_failure`] to early-return
/// for non-XHTTP modes — the call sites are uniform across the
/// dispatcher, so a non-XHTTP request transparently falls through.
fn is_xhttp(mode: TransportMode) -> bool {
    matches!(mode, TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3)
}

/// Rank inside the XHTTP family. Lower = more downgraded. Used to
/// enforce the "max-mode is a ceiling" semantics of the cache: if
/// the cached cap ranks below the requested mode, clamp; otherwise
/// the requested mode is already at or below the cap and passes
/// through unchanged.
fn rank(mode: TransportMode) -> u8 {
    match mode {
        TransportMode::XhttpH1 => 0,
        TransportMode::XhttpH2 => 1,
        TransportMode::XhttpH3 => 2,
        // Non-XHTTP modes never enter this cache, but `rank` is also
        // called inside `record_success` against a mode that *might*
        // be non-XHTTP (defensive). Topmost rank ensures a cross-family
        // success cannot accidentally clear an XHTTP cap.
        _ => u8::MAX,
    }
}

/// Inverse of [`rank`] for the XHTTP chain: maps a rank back to its mode.
fn mode_for_rank(rank: u8) -> TransportMode {
    match rank {
        0 => TransportMode::XhttpH1,
        1 => TransportMode::XhttpH2,
        _ => TransportMode::XhttpH3,
    }
}

fn host_key(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let port = url.port_or_known_default().unwrap_or(0);
    Some(format!("{host}:{port}"))
}

fn cache() -> &'static RwLock<HashMap<String, Entry>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Resolve the XHTTP mode a dial to `url` should start at, honouring whichever
/// strategy is active. No-op for non-XHTTP modes — the dispatcher can call this
/// unconditionally on every dial.
pub(crate) async fn effective_mode(url: &Url, requested: TransportMode) -> TransportMode {
    if !is_xhttp(requested) {
        return requested;
    }
    let params = mode_health::weighting();
    if !params.enabled {
        return effective_mode_legacy(url, requested).await;
    }
    let req_rank = rank(requested);
    let Some(key) = host_key(url) else { return requested };
    let now = Instant::now();
    let penalties = {
        let map = cache().read().await;
        match map.get(&key) {
            Some(entry) if now < entry.expires_at => entry.penalty,
            _ => return requested,
        }
    };
    let mut rng = rand::rng();
    let chosen = mode_health::descend_start_rank(req_rank, &penalties, now, &params, &mut rng);
    mode_for_rank(chosen)
}

/// Record that `failed` did not work for this host, updating whichever strategy
/// is active. No-op for modes outside the XHTTP fallback chain.
pub(crate) async fn record_failure(url: &Url, failed: TransportMode) {
    let params = mode_health::weighting();
    if !params.enabled {
        return record_failure_legacy(url, failed).await;
    }
    let r = rank(failed);
    // Only H2 / H3 failures matter: H1 is the floor rank, non-XHTTP rank > 2.
    if !(1..=2).contains(&r) {
        return;
    }
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let mut map = cache().write().await;
    let expires_at = now + downgrade_ttl();
    let entry = map.entry(key).or_insert_with(|| Entry {
        max_mode: TransportMode::XhttpH3,
        penalty: <[ModePenalty; 3]>::default(),
        expires_at,
    });
    entry.penalty[r as usize].add(now, &params);
    entry.expires_at = expires_at;
}

/// Note a successful dial at `succeeded`, updating whichever strategy is active.
/// No-op for non-XHTTP modes.
pub(crate) async fn record_success(url: &Url, succeeded: TransportMode) {
    if !is_xhttp(succeeded) {
        return;
    }
    let params = mode_health::weighting();
    if !params.enabled {
        return record_success_legacy(url, succeeded).await;
    }
    let r = rank(succeeded);
    let Some(key) = host_key(url) else { return };
    let mut map = cache().write().await;
    if let Some(entry) = map.get_mut(&key) {
        // Clear only the succeeded rank — a working H2 must not re-arm a broken
        // H3 (same invariant the WS cache documents).
        entry.penalty[r as usize].reset();
    }
}

/// Legacy binary-cap clamp for the XHTTP chain.
async fn effective_mode_legacy(url: &Url, requested: TransportMode) -> TransportMode {
    let Some(key) = host_key(url) else { return requested };
    let map = cache().read().await;
    let Some(entry) = map.get(&key) else { return requested };
    if Instant::now() >= entry.expires_at {
        return requested;
    }
    if rank(entry.max_mode) < rank(requested) {
        entry.max_mode
    } else {
        requested
    }
}

/// Legacy `record_failure`: clamp future dials to the next-lower XHTTP mode for
/// `DOWNGRADE_TTL`.
async fn record_failure_legacy(url: &Url, failed: TransportMode) {
    let new_max = match failed {
        TransportMode::XhttpH3 => TransportMode::XhttpH2,
        TransportMode::XhttpH2 => TransportMode::XhttpH1,
        _ => return,
    };
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let mut map = cache().write().await;
    let expires_at = now + downgrade_ttl();
    map.entry(key)
        .and_modify(|e| {
            // Monotonically downward inside an active window: a later
            // `XhttpH3` failure must not raise an existing `XhttpH1`
            // cap back up to `XhttpH2`. Outside the window the entry
            // is stale — overwrite unconditionally.
            if now >= e.expires_at || rank(new_max) <= rank(e.max_mode) {
                e.max_mode = new_max;
                e.expires_at = expires_at;
            } else {
                // Cap already deeper; just refresh the deadline so
                // the still-deeper window keeps living.
                e.expires_at = expires_at;
            }
        })
        .or_insert(Entry {
            max_mode: new_max,
            penalty: <[ModePenalty; 3]>::default(),
            expires_at,
        });
}

/// Legacy `record_success`: drop the per-host XHTTP cap once a dial succeeded at
/// a mode that meets-or-exceeds the cached cap.
async fn record_success_legacy(url: &Url, succeeded: TransportMode) {
    let Some(key) = host_key(url) else { return };
    let mut map = cache().write().await;
    if let Some(entry) = map.get(&key)
        && rank(succeeded) >= rank(entry.max_mode)
    {
        map.remove(&key);
    }
}

/// Drop expired entries. Called from `gc_shared_connections`
/// alongside the WS cache's `gc()` so both downgrade memories age
/// out on the same cadence.
pub(crate) async fn gc() {
    let now = Instant::now();
    let snapshot: Vec<String> = {
        let map = cache().read().await;
        map.iter()
            .filter(|(_, e)| now >= e.expires_at)
            .map(|(k, _)| k.clone())
            .collect()
    };
    if snapshot.is_empty() {
        return;
    }
    let mut map = cache().write().await;
    for key in snapshot {
        if let Some(e) = map.get(&key)
            && now >= e.expires_at
        {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
#[path = "tests/xhttp_mode_cache.rs"]
mod tests_xhttp_mode_cache;
