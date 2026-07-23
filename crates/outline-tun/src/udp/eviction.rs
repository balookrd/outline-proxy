//! Incremental LRU index behind UDP overflow eviction.
//!
//! Picking the least-recently-seen flow used to mean walking the whole flow
//! table and taking every flow's `Mutex` — O(n) awaits, run inline on the shared
//! TUN read-loop *while holding the table write-lock*. Every datagram parks on
//! `flows.read()` for the duration, so a flood of new 5-tuples against a full
//! table degraded into O(n²) head-of-line blocking — exactly what the per-flow
//! pump/reader architecture exists to prevent. The index keeps the LRU order
//! incrementally so selection is O(log n), takes no other flow's lock, and does
//! not await at all.
//!
//! Mirrors `crate::tcp::engine::eviction::FlowEvictionIndex`; it is generic over
//! the key so the tunnelled and direct flow tables can each own one.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Mutex as FlowMutex;

use super::types::FlowStamp;

/// How far a flow's `last_seen` must advance before its index entry is re-keyed.
///
/// `last_seen` moves on every datagram in either direction, but eviction only
/// needs a *coarse* LRU order: a refresh is a `BTreeMap` remove + insert behind
/// one engine-wide mutex shared by the read-loop and every per-flow task, so
/// paying it per datagram would make the index a contention point that grows
/// with the flow count. An entry can therefore lag reality by up to one quantum,
/// which cannot mis-order eviction in practice — the quantum is orders of
/// magnitude below the idle timeout that decides which flows are genuinely
/// stale, so a flow still taking traffic always outranks a quiet one.
const UDP_EVICTION_INDEX_QUANTUM: Duration = Duration::from_secs(1);

/// Whether a flow's advanced `last_seen` is worth re-indexing. The value already
/// published to the index lives next to the flow state, so the decision itself
/// is lock-free.
pub(super) fn eviction_index_needs_refresh(indexed_last_seen: Instant, last_seen: Instant) -> bool {
    last_seen.saturating_duration_since(indexed_last_seen) >= UDP_EVICTION_INDEX_QUANTUM
}

/// LRU order over a UDP flow table: `last_seen` → key, kept incrementally.
pub(super) struct FlowEvictionIndex<K> {
    inner: Mutex<FlowEvictionIndexInner<K>>,
}

struct FlowEvictionIndexInner<K> {
    /// Ordered by `(last_seen, flow_id)`. `flow_id` is a process-wide counter,
    /// so the pair stays unique even for flows stamped in the same instant.
    entries: BTreeMap<(Instant, u64), K>,
    positions: HashMap<K, (Instant, u64)>,
}

impl<K> Default for FlowEvictionIndexInner<K> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            positions: HashMap::new(),
        }
    }
}

impl<K: Clone + Eq + Hash> FlowEvictionIndex<K> {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(FlowEvictionIndexInner::default()),
        }
    }

    /// Publish `key`'s current activity. A stamp from an older flow generation
    /// (a zombie task that lost the race against a replacement) is ignored, so a
    /// late update can never resurrect a superseded flow's position.
    pub(super) fn upsert(&self, key: K, flow_id: u64, last_seen: Instant) {
        let mut inner = self.inner.lock();
        match inner.positions.get(&key).copied() {
            Some((_, previous_id)) if previous_id > flow_id => return,
            Some(previous) => {
                inner.entries.remove(&previous);
            },
            None => {},
        }
        inner.positions.insert(key.clone(), (last_seen, flow_id));
        inner.entries.insert((last_seen, flow_id), key);
    }

    /// Move an *existing* entry to a newer `last_seen`. Unlike [`Self::upsert`]
    /// this never creates one: activity is reported from tasks that hold a
    /// flow's `Arc` without holding the table lock, so the flow may already have
    /// been closed and unindexed — re-adding it there would leak the key back
    /// into the index. Returns whether the entry was moved.
    pub(super) fn refresh(&self, key: &K, flow_id: u64, last_seen: Instant) -> bool {
        let mut inner = self.inner.lock();
        let Some(previous) = inner.positions.get(key).copied() else {
            return false;
        };
        if previous.1 != flow_id {
            return false;
        }
        inner.entries.remove(&previous);
        inner.positions.insert(key.clone(), (last_seen, flow_id));
        inner.entries.insert((last_seen, flow_id), key.clone());
        true
    }

    /// Drop `key`'s entry, but only while it still belongs to generation
    /// `flow_id` — a removal racing a replacement must not unindex the live
    /// flow that took the slot. Returns whether an entry was dropped.
    pub(super) fn remove(&self, key: &K, flow_id: u64) -> bool {
        let mut inner = self.inner.lock();
        let Some(position) = inner.positions.get(key).copied() else {
            return false;
        };
        if position.1 != flow_id {
            return false;
        }
        inner.positions.remove(key);
        inner.entries.remove(&position).is_some()
    }

    /// Take the least-recently-seen entry out of the index.
    pub(super) fn pop_oldest(&self) -> Option<(K, u64)> {
        let mut inner = self.inner.lock();
        let ((_, flow_id), key) = inner.entries.pop_first()?;
        inner.positions.remove(&key);
        Some((key, flow_id))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        let inner = self.inner.lock();
        debug_assert_eq!(inner.entries.len(), inner.positions.len());
        inner.entries.len()
    }
}

/// Remove the least-recently-seen flow from a full table.
///
/// Synchronous and lock-free with respect to the flows themselves: the caller
/// holds the table write-lock, so selection must not await anything — least of
/// all another flow's `Mutex`, which a busy carrier send can hold for as long as
/// the network takes. An index entry whose flow is already gone is stale
/// bookkeeping, so it is discarded and the next candidate tried.
pub(super) fn evict_oldest_flow<K, F>(
    flows: &mut HashMap<K, Arc<FlowMutex<F>>>,
    index: &FlowEvictionIndex<K>,
) -> Option<(K, Arc<FlowMutex<F>>)>
where
    K: Clone + Eq + Hash,
{
    loop {
        let (key, _flow_id) = index.pop_oldest()?;
        if let Some(flow) = flows.remove(&key) {
            return Some((key, flow));
        }
    }
}

/// Refresh a flow's index position after its `last_seen` advanced, skipping the
/// index lock entirely until the advance clears a whole
/// [`UDP_EVICTION_INDEX_QUANTUM`]. Call sites must already hold the flow's own
/// lock (they just bumped `last_seen` through it).
///
/// A flow closed underneath the caller keeps its entry out of the index (see
/// [`FlowEvictionIndex::refresh`]); the local stamp then stays put so a live
/// flow whose entry somehow went missing retries on its next datagram.
pub(super) fn record_flow_activity<K, F>(index: &FlowEvictionIndex<K>, key: &K, flow: &mut F)
where
    K: Clone + Eq + Hash,
    F: FlowStamp,
{
    let last_seen = flow.last_seen();
    if !eviction_index_needs_refresh(flow.eviction_indexed_at(), last_seen) {
        return;
    }
    if index.refresh(key, flow.id(), last_seen) {
        flow.set_eviction_indexed_at(last_seen);
    }
}

#[cfg(test)]
#[path = "tests/eviction.rs"]
mod tests;
