//! Reverse-tunnel listener (topology A) — the ws side.
//!
//! Accepts QUIC carriers dialed by `ss` peers behind NAT (mTLS, pinned
//! fingerprints), pools them in a [`ReversePeerRegistry`], and serves
//! SOCKS5/TUN traffic routed to the reverse group over a live peer via a
//! `Route::Reverse` branch — kept entirely separate from the index-keyed
//! `UplinkManager` so the forward hot path is untouched.
//!
//! Gated on `h3` (the feature that pulls `outline-transport/quic`), so
//! router builds compile none of this.

use std::sync::Arc;

use crate::config::ReverseListenerConfig;

mod listener;
mod peer_registry;
mod relay;

pub(crate) use peer_registry::{ReversePeer, ReverseRegistry};
pub(crate) use relay::serve_reverse_tcp;

/// Build the reverse-peer registry and spawn the listener task. Returns the
/// registry so the dispatcher can route each reverse group to a live peer.
pub(crate) fn spawn_reverse_listener(
    cfg: &ReverseListenerConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Arc<ReverseRegistry> {
    // One pool per distinct resolved peer group (the listener default is
    // already folded into each peer's `group` at config load).
    let groups = cfg.peers.iter().map(|peer| Arc::clone(&peer.group));
    let registry = ReverseRegistry::new(groups, cfg.max_peers);
    let cfg = cfg.clone();
    let reg = Arc::clone(&registry);
    tokio::spawn(async move {
        if let Err(error) = listener::run_reverse_listener(cfg, reg, shutdown).await {
            tracing::error!(?error, "reverse-tunnel listener failed to start");
        }
    });
    registry
}
