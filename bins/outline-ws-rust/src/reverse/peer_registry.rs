//! Runtime-mutable pool of accepted reverse-tunnel peers.
//!
//! A reverse peer is an `ss` server (behind NAT) that dialed this listener;
//! once its mTLS carrier is up it lands here and becomes a live egress for
//! SOCKS5/TUN traffic routed to the reverse group. Peers come and go at
//! runtime, so this lives *outside* the index-keyed `UplinkManager` (whose
//! per-index arrays are fixed at construction) — the reverse path is a
//! separate `Route::Reverse`, not an extra `UplinkCandidate`.
//!
//! Items here are nominally `pub` while the `reverse` module itself stays
//! crate-private: the registry leaks through the public
//! `ProxyConfig::reverse` field, and anything narrower trips the
//! `private_interfaces`/`private_bounds` lints. Nothing is nameable
//! outside the crate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;

use outline_transport::quic::SharedQuicConnection;
use shadowsocks_crypto::CipherKind;

/// Liveness of a pooled peer. Abstracted so the pool logic (insert/evict/
/// round-robin) is unit-testable without standing up a real QUIC carrier.
pub trait Live {
    fn is_live(&self) -> bool;
}

/// One live reverse peer: the accepted QUIC carrier plus the protocol-specific
/// credentials this listener uses to frame each stream it opens to the peer.
pub struct ReversePeer {
    pub(crate) conn: Arc<SharedQuicConnection>,
    pub(crate) creds: ReversePeerCreds,
    /// Short, non-reversible label for logs/metrics (never the fingerprint).
    pub(crate) label: Arc<str>,
}

/// Framing credentials for streams opened to a reverse peer, matching the
/// carrier's negotiated protocol (chosen by the dialing `ss`).
#[derive(Clone)]
pub enum ReversePeerCreds {
    /// Raw Shadowsocks: SS2022 framing. `master_key` is pre-derived from the
    /// configured `password`; the password is kept alongside it because the
    /// SS-UDP transport derives its own key from the string
    /// (`UdpWsTransport::from_channel`), whereas the SS-TCP writer takes the
    /// master key directly.
    Ss {
        cipher: CipherKind,
        master_key: Vec<u8>,
        password: Arc<str>,
    },
    /// VLESS: the request header carries this UUID.
    Vless { uuid: [u8; 16] },
}

impl Live for ReversePeer {
    fn is_live(&self) -> bool {
        self.conn.is_open()
    }
}

/// Bounded pool of peers for one reverse group. Insert on accept,
/// drop-dead-and-round-robin on pick. Cheap `parking_lot::RwLock<Vec<_>>` —
/// peer churn is rare and the list is tiny.
pub struct PeerPool<T: Live> {
    group: Arc<str>,
    max_peers: usize,
    peers: RwLock<Vec<Arc<T>>>,
    /// Round-robin cursor so successive sessions spread across live peers.
    cursor: AtomicUsize,
}

/// Runtime registry of reverse peers, partitioned into one [`PeerPool`] per
/// egress group. Groups are fixed at construction from config (a peer's
/// resolved `group`); peers churn within their pool. A peer is steered to a
/// pool by the group its pinned cert maps to, and the dispatcher/UDP path
/// pick a live peer by the route's group name.
///
/// Generic over the peer type (defaulting to [`ReversePeer`]) only so the
/// group routing is unit-testable with a mock peer; production always uses
/// `ReverseRegistry` (i.e. `ReverseRegistry<ReversePeer>`).
pub struct ReverseRegistry<T: Live = ReversePeer> {
    groups: HashMap<Arc<str>, Arc<PeerPool<T>>>,
}

impl<T: Live> std::fmt::Debug for ReverseRegistry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReverseRegistry")
            .field("groups", &self.groups.len())
            .finish_non_exhaustive()
    }
}

impl<T: Live> ReverseRegistry<T> {
    /// Build one pool per distinct group, each bounded by `max_peers`.
    /// Duplicate groups in the iterator collapse to a single pool.
    pub(crate) fn new(groups: impl IntoIterator<Item = Arc<str>>, max_peers: usize) -> Arc<Self> {
        let groups = groups
            .into_iter()
            .map(|group| (Arc::clone(&group), PeerPool::new(group, max_peers)))
            .collect();
        Arc::new(Self { groups })
    }

    /// The pool for `group`, or `None` when `group` is not a reverse group.
    pub(crate) fn pool(&self, group: &str) -> Option<&Arc<PeerPool<T>>> {
        self.groups.get(group)
    }

    /// Pick a live peer for `group` round-robin. `None` when the group is not
    /// a reverse group or has no peer currently connected (caller falls back).
    pub(crate) fn pick_live(&self, group: &str) -> Option<Arc<T>> {
        self.groups.get(group).and_then(|pool| pool.pick_live())
    }

    /// Live peer count per group, for the dashboard topology chip. Order is
    /// unspecified (callers sort if they need stability).
    pub(crate) fn live_counts(&self) -> Vec<(String, usize)> {
        self.groups
            .values()
            .map(|pool| (pool.group().to_string(), pool.live_count()))
            .collect()
    }
}

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
            outline_metrics::set_reverse_peers(&self.group, peers.len());
            return false;
        }
        peers.push(peer);
        outline_metrics::set_reverse_peers(&self.group, peers.len());
        true
    }

    /// Pick a live peer round-robin, evicting any that have closed. `None`
    /// when no peer is currently connected (caller falls back / fails fast).
    pub(crate) fn pick_live(&self) -> Option<Arc<T>> {
        let mut peers = self.peers.write();
        peers.retain(|p| p.is_live());
        outline_metrics::set_reverse_peers(&self.group, peers.len());
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
        outline_metrics::set_reverse_peers(&self.group, peers.len());
        peers.len()
    }
}

#[cfg(test)]
#[path = "tests/peer_registry.rs"]
mod tests;
