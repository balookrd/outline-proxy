//! Short-lived memory of the domain a UDP flow was sniffed to, keyed by the
//! flow's `(client, destination)` pair.
//!
//! Under `[tun] route_by_sni` a flow's route is decided from the SNI recovered
//! from its **first** datagram, but only a QUIC Initial carries a ClientHello.
//! A flow torn down while the client's QUIC connection is still live (idle
//! eviction, carrier read error, `max_flows` eviction) is recreated by a Short
//! Header datagram with nothing to sniff, and would resolve by literal IP —
//! moving a live connection to a different exit, or dropping it, mid-session.
//! This cache carries the sniffed domain across that teardown so the route
//! follows the *connection* rather than the lifetime of one flow record.
//!
//! Bounded on both axes ([`SNI_ROUTE_CACHE_CAP`] entries, LRU-evicted;
//! [`SNI_ROUTE_CACHE_TTL`] since last use), and tagged with the routing-table
//! version captured at insert: a rule reload invalidates every entry, so no
//! decision is ever made from a pre-reload snapshot.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::types::UdpFlowKey;

/// Entry cap. One entry is a flow key plus a domain — a few hundred bytes at
/// most — so 1024 keeps the worst case in the low hundreds of KB while
/// comfortably covering the live QUIC connections of a real client (mirrors
/// the SOCKS5 per-association route cache's cap).
pub(super) const SNI_ROUTE_CACHE_CAP: usize = 1024;

/// Idle TTL, refreshed on every hit. Sized to outlive the gap a live QUIC
/// connection can leave between flows — the default UDP flow `idle_timeout`
/// (300 s) is the widest of the three teardown paths; a carrier death or a
/// `max_flows` eviction recreates the flow within milliseconds. Past that the
/// client's own QUIC idle timeout has long since closed the connection, so a
/// surviving entry would only pin a route for a destination nobody is talking
/// to any more.
pub(super) const SNI_ROUTE_CACHE_TTL: Duration = Duration::from_secs(300);

struct Entry {
    host: Arc<str>,
    /// [`outline_routing::RoutingTable::version`] snapshot taken when the
    /// domain was sniffed. A mismatch means the rules were reloaded underneath
    /// this entry and it must not steer anything.
    table_version: u64,
    /// Last insert or hit; drives the TTL sweep.
    touched_at: Instant,
}

pub(super) struct SniRouteCache {
    entries: LruCache<UdpFlowKey, Entry>,
    ttl: Duration,
}

impl SniRouteCache {
    pub(super) fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            entries: LruCache::new(NonZeroUsize::new(cap).unwrap_or(NonZeroUsize::MIN)),
            ttl,
        }
    }

    /// Record the domain sniffed from `key`'s first datagram. Inserting past
    /// the cap evicts the least-recently-used entry.
    pub(super) fn remember(
        &mut self,
        key: &UdpFlowKey,
        host: &str,
        table_version: u64,
        now: Instant,
    ) {
        self.entries.put(
            key.clone(),
            Entry {
                host: Arc::from(host),
                table_version,
                touched_at: now,
            },
        );
    }

    /// Domain remembered for `key`, or `None` when there is none, the entry
    /// predates a routing-table reload, or it has gone stale. Both rejections
    /// drop the entry, so a dead flow key cannot outlive its own TTL by being
    /// looked up. A hit refreshes the TTL: a connection that keeps rebuilding
    /// its flow keeps its route.
    pub(super) fn recall(
        &mut self,
        key: &UdpFlowKey,
        table_version: u64,
        now: Instant,
    ) -> Option<Arc<str>> {
        let entry = self.entries.get_mut(key)?;
        if entry.table_version != table_version
            || now.saturating_duration_since(entry.touched_at) >= self.ttl
        {
            self.entries.pop(key);
            return None;
        }
        entry.touched_at = now;
        Some(Arc::clone(&entry.host))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[path = "tests/sni_cache.rs"]
mod tests;
