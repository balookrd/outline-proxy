//! Per-host downgrade memory for the WebSocket transport-mode fallback chain
//! (`H3 → H2 → H1`).
//!
//! Two selection strategies share this cache, chosen once at startup by
//! [`crate::init_health_weighting`]:
//!
//! * **Legacy binary cap** (weighting disabled): when a higher-level mode fails
//!   (e.g. UDP-blocked path drops H3, missing ALPN denies H2 Extended CONNECT),
//!   the failure is recorded and clamps subsequent dials to the next supported
//!   mode for `DOWNGRADE_TTL`. Without this, every new VLESS connection would
//!   re-pay the cost of the doomed handshake before falling back.
//! * **Liveness weighting** (default in production): each rank carries a
//!   decaying penalty and the start rank is chosen probabilistically (see
//!   [`crate::mode_health`]), so a carrier that disconnects often is preferred
//!   less but still retried occasionally and recovers as its penalty decays.
//!
//! Either way the cap / penalty is per `(host, port)` and decays by TTL so that
//! a transient outage (server restart, route flap) does not permanently pin the
//! host to HTTP/1.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use url::Url;

use crate::config::TransportMode;
use crate::mode_health::{self, ModePenalty};

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
    /// Legacy binary downgrade cap. Authoritative only when weighting is
    /// disabled; left at the topmost mode (no clamp) when weighting drives
    /// selection.
    max_mode: TransportMode,
    /// Per-rank decaying liveness penalty, indexed by [`rank`] (`0` = WsH1,
    /// `1` = WsH2, `2` = WsH3). Authoritative only when weighting is enabled.
    penalty: [ModePenalty; 3],
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

/// Inverse of [`rank`] for the WS chain: maps a rank back to its mode.
fn mode_for_rank(rank: u8) -> TransportMode {
    match rank {
        0 => TransportMode::WsH1,
        1 => TransportMode::WsH2,
        _ => TransportMode::WsH3,
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

/// Resolve the mode a dial to `url` should start at, honouring whichever
/// strategy is active. No-op for non-WS modes (raw QUIC / XHTTP) — the
/// dispatcher can call this unconditionally.
pub(crate) async fn effective_mode(url: &Url, requested: TransportMode) -> TransportMode {
    let params = mode_health::weighting();
    if !params.enabled {
        return effective_mode_legacy(url, requested).await;
    }
    let req_rank = rank(requested);
    if req_rank > 2 {
        // Not part of the WS chain — never reranked here.
        return requested;
    }
    let Some(key) = host_key(url) else { return requested };
    let now = Instant::now();
    let penalties = {
        let map = cache().read().await;
        match map.get(&key) {
            Some(entry) if now < entry.expires_at => entry.penalty,
            // No record (or expired) → no penalty → start at the requested top.
            _ => return requested,
        }
    };
    let mut rng = rand::rng();
    let chosen = mode_health::descend_start_rank(req_rank, &penalties, now, &params, &mut rng);
    mode_for_rank(chosen)
}

/// Record that `failed` did not work for this host, updating whichever strategy
/// is active. No-op for modes outside the WS fallback chain.
pub(crate) async fn record_failure(url: &Url, failed: TransportMode) {
    let params = mode_health::weighting();
    if !params.enabled {
        return record_failure_legacy(url, failed).await;
    }
    let r = rank(failed);
    // Only H2 / H3 failures matter: H1 is the floor rank (always acceptable as
    // the last resort), and non-WS modes have rank > 2.
    if !(1..=2).contains(&r) {
        return;
    }
    let Some(key) = host_key(url) else { return };
    let now = Instant::now();
    let mut map = cache().write().await;
    let expires_at = now + downgrade_ttl();
    let entry = map.entry(key).or_insert_with(|| Entry {
        max_mode: TransportMode::WsH3,
        penalty: <[ModePenalty; 3]>::default(),
        expires_at,
    });
    entry.penalty[r as usize].add(now, &params);
    entry.expires_at = expires_at;
}

/// Note a successful dial at `succeeded`, updating whichever strategy is active.
/// No-op for non-WS modes.
pub(crate) async fn record_success(url: &Url, succeeded: TransportMode) {
    let params = mode_health::weighting();
    if !params.enabled {
        return record_success_legacy(url, succeeded).await;
    }
    let r = rank(succeeded);
    if r > 2 {
        return;
    }
    let Some(key) = host_key(url) else { return };
    let mut map = cache().write().await;
    if let Some(entry) = map.get_mut(&key) {
        // Clear only the succeeded rank's penalty. A higher rank's penalty is
        // deliberately preserved — a working H2 must not immediately re-arm a
        // broken H3. This enforces the same invariant the legacy path relied on
        // dial_plan for ("do not record_success(H2) after an H3 failure"), but
        // structurally, in the data model.
        entry.penalty[r as usize].reset();
    }
}

/// Legacy binary-cap clamp. Returns the requested mode unchanged when there is
/// no cap (or it has expired).
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

/// Legacy `record_failure`: clamp future dials to the next-lower mode for
/// `DOWNGRADE_TTL`. No-op for modes outside the H3/H2 fallback chain.
async fn record_failure_legacy(url: &Url, failed: TransportMode) {
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
        .or_insert(Entry {
            max_mode: new_max,
            penalty: <[ModePenalty; 3]>::default(),
            expires_at,
        });
}

/// Legacy `record_success`: drop the per-host clamp once a dial succeeded at a
/// mode that meets-or-exceeds the cached cap.
async fn record_success_legacy(url: &Url, succeeded: TransportMode) {
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
