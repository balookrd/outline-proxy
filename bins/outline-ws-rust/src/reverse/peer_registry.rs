//! Runtime-mutable pool of accepted reverse-tunnel peers.
//!
//! A reverse peer is an `ss` server (behind NAT) that dialed this listener;
//! once its mTLS carrier is up it lands here and becomes a live egress for
//! SOCKS5/TUN traffic routed to the reverse group. Peers come and go at
//! runtime, so this lives *outside* the index-keyed `UplinkManager` (whose
//! per-index arrays are fixed at construction) — the reverse path is a
//! separate `Route::Reverse`, not an extra `UplinkCandidate`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;

use outline_transport::quic::SharedQuicConnection;
use shadowsocks_crypto::CipherKind;

/// Liveness of a pooled peer. Abstracted so the pool logic (insert/evict/
/// round-robin) is unit-testable without standing up a real QUIC carrier.
pub(crate) trait Live {
    fn is_live(&self) -> bool;
}

/// One live reverse peer: the accepted QUIC carrier plus the SS credentials
/// this listener uses to frame the SS2022 header on each stream it opens to
/// the peer. `master_key` is pre-derived from the configured `password`.
pub(crate) struct ReversePeer {
    pub(crate) conn: Arc<SharedQuicConnection>,
    pub(crate) cipher: CipherKind,
    pub(crate) master_key: Vec<u8>,
    /// Short, non-reversible label for logs/metrics (never the fingerprint).
    pub(crate) label: Arc<str>,
}

impl Live for ReversePeer {
    fn is_live(&self) -> bool {
        self.conn.is_open()
    }
}

/// Bounded pool of peers for one reverse group. Insert on accept,
/// drop-dead-and-round-robin on pick. Cheap `parking_lot::RwLock<Vec<_>>` —
/// peer churn is rare and the list is tiny.
pub(crate) struct PeerPool<T: Live> {
    group: Arc<str>,
    max_peers: usize,
    peers: RwLock<Vec<Arc<T>>>,
    /// Round-robin cursor so successive sessions spread across live peers.
    cursor: AtomicUsize,
}

/// The concrete reverse-peer pool used by the listener and relay.
pub(crate) type ReversePeerRegistry = PeerPool<ReversePeer>;

impl<T: Live> std::fmt::Debug for PeerPool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerPool")
            .field("group", &self.group)
            .field("max_peers", &self.max_peers)
            .field("live", &self.live_count())
            .finish_non_exhaustive()
    }
}

impl<T: Live> PeerPool<T> {
    pub(crate) fn new(group: Arc<str>, max_peers: usize) -> Arc<Self> {
        Arc::new(Self {
            group,
            max_peers: max_peers.max(1),
            peers: RwLock::new(Vec::new()),
            cursor: AtomicUsize::new(0),
        })
    }

    pub(crate) fn group(&self) -> &str {
        &self.group
    }

    /// Register a freshly-accepted peer. Returns `false` (peer dropped) when
    /// the pool is at capacity — counting only live peers, so a dead slot is
    /// reclaimed first. Bounds the number of concurrent carriers.
    pub(crate) fn try_insert(&self, peer: Arc<T>) -> bool {
        let mut peers = self.peers.write();
        peers.retain(|p| p.is_live());
        if peers.len() >= self.max_peers {
            return false;
        }
        peers.push(peer);
        true
    }

    /// Pick a live peer round-robin, evicting any that have closed. `None`
    /// when no peer is currently connected (caller falls back / fails fast).
    pub(crate) fn pick_live(&self) -> Option<Arc<T>> {
        let mut peers = self.peers.write();
        peers.retain(|p| p.is_live());
        if peers.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % peers.len();
        Some(Arc::clone(&peers[idx]))
    }

    /// Number of currently-live peers (also prunes dead entries).
    pub(crate) fn live_count(&self) -> usize {
        let mut peers = self.peers.write();
        peers.retain(|p| p.is_live());
        peers.len()
    }
}

#[cfg(test)]
#[path = "tests/peer_registry.rs"]
mod tests;
