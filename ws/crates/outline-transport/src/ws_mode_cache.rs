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

use crate::config::WsTransportMode;

const DOWNGRADE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
struct Entry {
    max_mode: WsTransportMode,
    expires_at: Instant,
}

fn rank(m: WsTransportMode) -> u8 {
    match m {
        WsTransportMode::Http1 => 0,
        WsTransportMode::H2 => 1,
        WsTransportMode::H3 => 2,
        // Raw QUIC is not part of the WS fallback chain; treated as topmost
        // so it is never selected by clamping logic here.
        WsTransportMode::Quic => 3,
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
pub(crate) async fn effective_mode(url: &Url, requested: WsTransportMode) -> WsTransportMode {
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
pub(crate) async fn record_failure(url: &Url, failed: WsTransportMode) {
    let new_max = match failed {
        WsTransportMode::H3 => WsTransportMode::H2,
        WsTransportMode::H2 => WsTransportMode::Http1,
        _ => return,
    };
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let mut map = cache().write().await;
    let expires_at = now + DOWNGRADE_TTL;
    map.entry(key)
        .and_modify(|e| {
            if rank(new_max) <= rank(e.max_mode) {
                e.max_mode = new_max;
                e.expires_at = expires_at;
            }
        })
        .or_insert(Entry { max_mode: new_max, expires_at });
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
