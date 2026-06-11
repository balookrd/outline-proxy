//! Per-host downgrade memory for the XHTTP **submode** axis
//! (`stream-one → packet-up`).
//!
//! Sibling of [`crate::xhttp_mode_cache`], which governs the orthogonal
//! h-version axis (`xhttp_h3 → xhttp_h2 → xhttp_h1`). The two caches are
//! deliberately independent: a stream-one failure tells us nothing about
//! the h-version reachability of the host, and an h-version downgrade
//! tells us nothing about whether stream-one is viable on the surviving
//! carrier. Each axis decays on its own deadline so a refresh on one
//! does not extend the other.
//!
//! Why this exists: stream-one keeps a single bidirectional request open
//! for the lifetime of the session. Many CDNs / corporate proxies / NATs
//! buffer long-lived POST bodies before forwarding, breaking the data
//! flow even though the request handshake nominally succeeds. Packet-up
//! issues short POSTs with sequence numbers and survives that environment
//! unchanged. When stream-one fails on a host, subsequent dials should
//! skip it for `DOWNGRADE_TTL` and go straight to packet-up — exactly
//! the symptom the h-version cache solves for the carrier axis, applied
//! to the second axis.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use url::Url;

use crate::xhttp::XhttpSubmode;

/// Default TTL applied when [`init_downgrade_ttl`] has not been called.
/// Matches the sibling caches (`ws_mode_cache`, `xhttp_mode_cache`) and
/// the per-uplink soft-window so a binary that never wires startup
/// config behaves consistently across all three.
const DEFAULT_DOWNGRADE_TTL: Duration = Duration::from_secs(60);

/// Process-wide TTL for the per-host XHTTP submode cache. First call
/// to [`init_downgrade_ttl`] wins; subsequent attempts are silently
/// ignored. The slot is independent from the h-version cache so a
/// future caller could pass asymmetric TTLs without re-plumbing the
/// API.
static DOWNGRADE_TTL: OnceLock<Duration> = OnceLock::new();

fn downgrade_ttl() -> Duration {
    DOWNGRADE_TTL.get().copied().unwrap_or(DEFAULT_DOWNGRADE_TTL)
}

/// Initialise [`downgrade_ttl`]. First call wins; subsequent calls are
/// silently ignored. The bootstrap path passes the same value it hands
/// to [`crate::xhttp_mode_cache::init_downgrade_ttl`] and
/// [`crate::ws_mode_cache::init_downgrade_ttl`] — the three caches are
/// conceptually one knob, just stored in independent per-axis slots so
/// failures on one axis cannot clobber the deadline on another.
pub fn init_downgrade_ttl(ttl: Duration) {
    let _ = DOWNGRADE_TTL.set(ttl);
}

#[derive(Clone, Copy)]
struct Entry {
    /// Wall-clock deadline at which the stream-one block lifts.
    expires_at: Instant,
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

/// Clamp the requested submode to packet-up when the cache holds a
/// fresh stream-one block for this host. `PacketUp` requests pass
/// through unconditionally — the cache never affects them. No-op when
/// the URL has no host (data: / file: schemes), when there is no
/// entry, or when the entry has expired.
pub(crate) async fn effective_submode(url: &Url, requested: XhttpSubmode) -> XhttpSubmode {
    if requested == XhttpSubmode::PacketUp {
        return requested;
    }
    let Some(key) = host_key(url) else { return requested };
    let map = cache().read().await;
    let Some(entry) = map.get(&key) else { return requested };
    if Instant::now() >= entry.expires_at {
        return requested;
    }
    XhttpSubmode::PacketUp
}

/// Record that stream-one did not work for this host; future dials
/// are clamped to `PacketUp` for `DOWNGRADE_TTL`. No-op for failures
/// reported on `PacketUp` (the carrier we fall back *to* — recording
/// that as failed would be a logic error at the call site).
pub(crate) async fn record_failure(url: &Url, failed: XhttpSubmode) {
    if failed != XhttpSubmode::StreamOne {
        return;
    }
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let expires_at = now + downgrade_ttl();
    let mut map = cache().write().await;
    map.entry(key)
        .and_modify(|e| {
            // Inside an active window, refresh the deadline so the
            // block keeps living. Outside the window the entry is
            // effectively gone and we re-stamp it from scratch.
            e.expires_at = expires_at;
        })
        .or_insert(Entry { expires_at });
}

/// Drop the per-host stream-one block once a stream-one dial actually
/// succeeded. Without this the cache would only clear when the entry
/// naturally expires, so concurrent dials hitting the same host during
/// the recovery window keep clamping to packet-up even though stream-
/// one is healthy again. Non-stream-one successes pass through silently
/// — a packet-up success proves nothing about stream-one viability.
pub(crate) async fn record_success(url: &Url, succeeded: XhttpSubmode) {
    if succeeded != XhttpSubmode::StreamOne {
        return;
    }
    let Some(key) = host_key(url) else { return };
    let mut map = cache().write().await;
    map.remove(&key);
}

/// Returns the time remaining on the per-host stream-one block, or
/// `None` when there is no entry / the entry has expired. Used by
/// the uplink-snapshot builder to surface the cache state on
/// dashboards without crossing the transport-crate boundary by
/// poking the cache map directly.
pub(crate) async fn stream_one_block_remaining(url: &Url) -> Option<Duration> {
    let key = host_key(url)?;
    let map = cache().read().await;
    let entry = map.get(&key)?;
    let now = Instant::now();
    entry.expires_at.checked_duration_since(now)
}

/// Drop expired entries. Called from `gc_shared_connections` alongside
/// the sibling caches' `gc()` so all downgrade memories age out on the
/// same cadence.
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
#[path = "tests/xhttp_submode_cache.rs"]
mod tests_xhttp_submode_cache;
