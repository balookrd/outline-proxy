//! Per-host downgrade memory for the WebSocket transport-mode fallback chain
//! (`H3 → H2 → H1`).
//!
//! When a higher-level mode fails (e.g. UDP-blocked path drops H3, missing
//! ALPN denies H2 Extended CONNECT), we record the failure for the target
//! host and clamp subsequent dial requests to the next supported mode for
//! `DOWNGRADE_TTL`.  Without this, every new VLESS connection would re-pay
//! the cost of the doomed handshake before falling back.
//!
//! The cap is per `(host, port)` and decays by TTL so that a transient outage
//! (server restart, route flap) does not permanently pin the host to HTTP/1.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use url::Url;

use crate::config::TransportMode;

/// Default TTL applied when [`init_downgrade_ttl`] has not been called.
/// Matches the `LoadBalancingConfig::mode_downgrade_duration` default in
/// `outline-uplink` so a binary that never wires startup config still
/// behaves consistently with the per-uplink soft-window.
const DEFAULT_DOWNGRADE_TTL: Duration = Duration::from_secs(60);

/// Process-wide TTL for the per-host downgrade cache. Set once at
/// startup from the `mode_downgrade_secs` (legacy alias
/// `h3_downgrade_secs`) config knob; subsequent calls are no-ops.
static DOWNGRADE_TTL: OnceLock<Duration> = OnceLock::new();

fn downgrade_ttl() -> Duration {
    DOWNGRADE_TTL.get().copied().unwrap_or(DEFAULT_DOWNGRADE_TTL)
}

/// Initialise [`downgrade_ttl`]. First call wins; subsequent calls are
/// silently ignored. Intended for the `outline-ws-rust` bootstrap: pass
/// the maximum `mode_downgrade_duration` across all uplink groups so the
/// process-global cache holds at least as long as the most conservative
/// group expects (the cache is keyed by `host:port`, not per-group).
pub fn init_downgrade_ttl(ttl: Duration) {
    let _ = DOWNGRADE_TTL.set(ttl);
}

#[derive(Clone, Copy)]
struct Entry {
    max_mode: TransportMode,
    expires_at: Instant,
}

fn rank(m: TransportMode) -> u8 {
    match m {
        TransportMode::WsH1 => 0,
        TransportMode::WsH2 => 1,
        TransportMode::WsH3 => 2,
        // Raw QUIC is not part of the WS fallback chain; treated as topmost
        // so it is never selected by clamping logic here. XHTTP modes share
        // the same property: they ride their own dial path and never get
        // clamped against the WS chain.
        TransportMode::Quic
        | TransportMode::XhttpH1
        | TransportMode::XhttpH2
        | TransportMode::XhttpH3 => 3,
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

/// Clamp the requested mode to the cached max for this host (if any, and not
/// expired).  Returns the requested mode unchanged when there is no cap.
pub(crate) async fn effective_mode(url: &Url, requested: TransportMode) -> TransportMode {
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

/// Record that `failed` did not work for this host; future dials are clamped
/// to the next-lower mode for `DOWNGRADE_TTL`.  No-op for modes outside the
/// H3/H2 fallback chain.
pub(crate) async fn record_failure(url: &Url, failed: TransportMode) {
    let new_max = match failed {
        TransportMode::WsH3 => TransportMode::WsH2,
        TransportMode::WsH2 => TransportMode::WsH1,
        _ => return,
    };
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let mut map = cache().write().await;
    let expires_at = now + downgrade_ttl();
    map.entry(key)
        .and_modify(|e| {
            if rank(new_max) <= rank(e.max_mode) {
                e.max_mode = new_max;
                e.expires_at = expires_at;
            }
        })
        .or_insert(Entry { max_mode: new_max, expires_at });
}

/// Drop the per-host clamp once a dial actually succeeded at a mode
/// that meets-or-exceeds the cached cap. Without this the cache would
/// only clear when the entry naturally expires, so concurrent dials
/// hitting the same host during the recovery window keep clamping to
/// the lower mode even though h3 / h2 is already healthy again.
pub(crate) async fn record_success(url: &Url, succeeded: TransportMode) {
    let Some(key) = host_key(url) else { return };
    let mut map = cache().write().await;
    if let Some(entry) = map.get(&key)
        && rank(succeeded) >= rank(entry.max_mode)
    {
        map.remove(&key);
    }
}

/// Drop expired entries.  Called from `gc_shared_connections`.
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
        if let Some(e) = map.get(&key) {
            if now >= e.expires_at {
                map.remove(&key);
            }
        }
    }
}
