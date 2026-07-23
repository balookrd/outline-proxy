//! Short-lived memory of the flows the routing table said to drop, keyed by
//! the flow's `(client, destination)` pair.
//!
//! A dropped flow is the one routing outcome that leaves *no* state behind:
//! there is no flow record, no socket and no task, so nothing tells the client
//! to stop. It keeps sending, and every datagram re-runs the full decision. On
//! the plain path that is a routing lookup; under `[tun] route_by_sni` it is
//! also a complete QUIC Initial decrypt — HKDF-Expand-Label key derivation plus
//! an AES-128-GCM open — per datagram, for a verdict that cannot change until
//! the rules do. A client blocked mid-handshake retransmits its Initial on
//! every PTO, so this is paid repeatedly and precisely on traffic the operator
//! has already decided to discard.
//!
//! The negative entry caches that verdict for a few seconds. It is bounded on
//! both axes ([`DROP_ROUTE_CACHE_CAP`] entries, LRU-evicted; expiring
//! [`DROP_ROUTE_CACHE_TTL`] after the verdict) and tagged with the
//! routing-table version, so a rule reload invalidates every entry at once.
//!
//! Two deliberate differences from the sniffed-SNI memory ([`super::sni_cache`]):
//! the TTL is *absolute*, not idle-based — a hit must not restart the clock, or
//! a client hammering a blocked destination would pin its own entry forever and
//! the engine would never re-consult the table — and it is short, because the
//! verdict also depends on inputs the version stamp cannot see. Two of them:
//! a domain recalled from the sniffed-SNI memory that has since expired, and a
//! 5-tuple whose first datagram carried no ClientHello (so it resolved by
//! literal IP) being reused within seconds by a QUIC connection whose SNI would
//! have routed elsewhere. Neither can change a verdict for longer than the TTL.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::types::UdpFlowKey;

/// Entry cap. An entry is a flow key plus a version and a timestamp — well
/// under a hundred bytes — so this bounds the memory in the low hundreds of KB
/// even when every slot is taken, matching [`super::sni_cache`]'s cap.
pub(super) const DROP_ROUTE_CACHE_CAP: usize = 1024;

/// How long a drop verdict is replayed before the table is consulted again.
/// Long enough to cover a blocked QUIC client's Initial retransmissions (the
/// PTO series that would otherwise each pay a full decrypt), short enough that
/// no verdict outlives a config change by more than a few seconds even in the
/// cases the version stamp cannot see.
pub(super) const DROP_ROUTE_CACHE_TTL: Duration = Duration::from_secs(10);

struct Entry {
    /// [`outline_routing::RoutingTable::version`] snapshot taken when the flow
    /// was dropped. A mismatch means the rules were reloaded underneath this
    /// entry, so the verdict must be re-taken.
    table_version: u64,
    /// When the verdict was taken; drives the (absolute) TTL.
    decided_at: Instant,
}

pub(super) struct DropRouteCache {
    entries: LruCache<UdpFlowKey, Entry>,
    ttl: Duration,
    /// Verdicts served from the cache. Test-only: it exists so a test can prove
    /// the repeat datagram never reached the sniffer, which is the whole point
    /// of the entry.
    #[cfg(test)]
    hits: u64,
}

impl DropRouteCache {
    pub(super) fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(cap).unwrap_or(NonZeroUsize::MIN)),
            ttl,
            #[cfg(test)]
            hits: 0,
        }
    }

    /// Record that `key` resolved to `Drop`. Inserting past the cap evicts the
    /// least-recently-used entry.
    pub(super) fn remember(&mut self, key: &UdpFlowKey, table_version: u64, now: Instant) {
        self.entries
            .put(key.clone(), Entry { table_version, decided_at: now });
    }

    /// Whether `key` is still known to be dropped. Both rejections — a routing
    /// reload and an expired verdict — drop the entry, so a stale key cannot
    /// linger past the moment it stopped being usable.
    pub(super) fn is_dropped(
        &mut self,
        key: &UdpFlowKey,
        table_version: u64,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.entries.get(key) else {
            return false;
        };
        if entry.table_version != table_version
            || now.saturating_duration_since(entry.decided_at) >= self.ttl
        {
            self.entries.pop(key);
            return false;
        }
        #[cfg(test)]
        {
            self.hits += 1;
        }
        true
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn hits(&self) -> u64 {
        self.hits
    }
}

#[cfg(test)]
#[path = "tests/drop_cache.rs"]
mod tests;
