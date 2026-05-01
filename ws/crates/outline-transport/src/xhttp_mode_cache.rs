//! Per-host downgrade memory for the XHTTP transport-mode fallback
//! chain (`xhttp_h3 → xhttp_h2 → xhttp_h1`).
//!
//! Sibling of [`crate::ws_mode_cache`] — the WS cache covers the
//! `WsH3 → WsH2 → WsH1` chain, this one covers XHTTP. They are kept
//! separate so a `record_failure` on one chain does not clobber the
//! cap of the other when several uplinks share the same `(host, port)`
//! but use different transports.
//!
//! When a higher-level XHTTP mode fails (e.g. UDP-blocked path drops
//! `xhttp_h3`, or a CDN strips ALPN h2 forcing `xhttp_h2` to fail),
//! the failure is recorded for the target host and clamps subsequent
//! dial requests to the next supported XHTTP mode for `DOWNGRADE_TTL`.
//! Without this, every new VLESS-XHTTP connection to that host would
//! re-pay the cost of the doomed handshake before falling back —
//! exactly the symptom the WS cache solves for the WS chain.
//!
//! The cap is per `(host, port)` and decays by TTL so that a transient
//! outage (server restart, route flap) does not permanently pin the
//! host to `xhttp_h1`. Entries are cleared early by [`record_success`]
//! when the originally-requested mode succeeds, mirroring the WS
//! cache's recovery behaviour.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use url::Url;

use crate::config::TransportMode;

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
    max_mode: TransportMode,
    expires_at: Instant,
}

/// True if `mode` belongs to the XHTTP family this cache governs.
/// Used by [`effective_mode`] / [`record_failure`] to early-return
/// for non-XHTTP modes — the call sites are uniform across the
/// dispatcher, so a non-XHTTP request transparently falls through.
fn is_xhttp(mode: TransportMode) -> bool {
    matches!(
        mode,
        TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3
    )
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

fn host_key(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let port = url.port_or_known_default().unwrap_or(0);
    Some(format!("{host}:{port}"))
}

fn cache() -> &'static RwLock<HashMap<String, Entry>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Entry>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Clamp the requested mode to the cached XHTTP cap for this host.
/// Returns the requested mode unchanged when there is no cap, when
/// the cap has expired, or when the requested mode is already at
/// or below the cap. No-op for non-XHTTP modes — the dispatcher
/// can call this unconditionally on every dial.
pub(crate) async fn effective_mode(url: &Url, requested: TransportMode) -> TransportMode {
    if !is_xhttp(requested) {
        return requested;
    }
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

/// Record that `failed` did not work for this host; future dials
/// are clamped to the next-lower XHTTP mode for `DOWNGRADE_TTL`.
/// No-op for modes outside the XHTTP fallback chain — the WS chain
/// has its own cache in [`crate::ws_mode_cache`] and the two are
/// deliberately independent.
pub(crate) async fn record_failure(url: &Url, failed: TransportMode) {
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
        .or_insert(Entry { max_mode: new_max, expires_at });
}

/// Drop the per-host XHTTP cap once a dial actually succeeded at a
/// mode that meets-or-exceeds the cached cap. Without this the cache
/// would only clear when the entry naturally expires, so concurrent
/// dials hitting the same host during the recovery window keep
/// clamping to the lower mode even though the higher carrier is
/// already healthy again. Non-XHTTP modes pass through silently.
pub(crate) async fn record_success(url: &Url, succeeded: TransportMode) {
    if !is_xhttp(succeeded) {
        return;
    }
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
            .filter_map(|(k, e)| (now >= e.expires_at).then(|| k.clone()))
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
