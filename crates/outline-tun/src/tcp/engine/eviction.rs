use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use parking_lot::Mutex;

use super::super::{TCP_EVICTION_INDEX_QUANTUM, TcpFlowKey};

/// Whether a flow's advanced `last_seen` is worth re-indexing for eviction.
///
/// `last_seen` moves on every accepted packet and every downlink chunk, but the
/// index only needs a *coarse* LRU order: re-indexing is a `BTreeSet` remove +
/// insert (two O(log n) node churns) behind a single engine-wide mutex shared by
/// the read-loop and every per-flow reader task, so paying it per packet made the
/// index a contention point that grows with the flow count. Instead we only
/// refresh once the flow has advanced by a whole [`TCP_EVICTION_INDEX_QUANTUM`],
/// and the caller keeps the last indexed value next to the flow state so the
/// decision itself is lock-free.
///
/// The cost is that an active flow's index entry can lag reality by up to one
/// quantum. That cannot mis-order eviction in practice: the quantum is orders of
/// magnitude below the idle timeout that decides which flows are genuinely stale,
/// so a flow still taking traffic always outranks one that has been quiet for
/// seconds.
pub(in crate::tcp::engine) fn eviction_index_needs_refresh(
    indexed_last_seen: Instant,
    last_seen: Instant,
) -> bool {
    last_seen.saturating_duration_since(indexed_last_seen) >= TCP_EVICTION_INDEX_QUANTUM
}

pub(in crate::tcp::engine) struct FlowEvictionIndex {
    inner: Mutex<FlowEvictionIndexInner>,
}

pub(in crate::tcp::engine) struct FlowEvictionCandidate {
    pub(in crate::tcp::engine) key: TcpFlowKey,
    pub(in crate::tcp::engine) flow_id: u64,
}

#[derive(Default)]
struct FlowEvictionIndexInner {
    entries: BTreeSet<FlowEvictionEntry>,
    records_by_key: HashMap<TcpFlowKey, FlowEvictionRecord>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FlowEvictionRecord {
    last_seen: Instant,
    flow_id: u64,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowEvictionEntry {
    last_seen: Instant,
    flow_id: u64,
    key: TcpFlowKey,
}

impl FlowEvictionIndex {
    pub(in crate::tcp::engine) fn new() -> Self {
        Self {
            inner: Mutex::new(FlowEvictionIndexInner::default()),
        }
    }

    pub(in crate::tcp::engine) fn upsert(&self, key: TcpFlowKey, flow_id: u64, last_seen: Instant) {
        let mut inner = self.inner.lock();
        match inner.records_by_key.get(&key).copied() {
            Some(previous) if previous.flow_id > flow_id => return,
            Some(previous) if previous.flow_id == flow_id && previous.last_seen == last_seen => {
                return;
            },
            Some(previous) => {
                inner.entries.remove(&FlowEvictionEntry {
                    last_seen: previous.last_seen,
                    flow_id: previous.flow_id,
                    key: key.clone(),
                });
            },
            None => {},
        }

        inner
            .records_by_key
            .insert(key.clone(), FlowEvictionRecord { last_seen, flow_id });
        inner.entries.insert(FlowEvictionEntry { last_seen, flow_id, key });
    }

    pub(in crate::tcp::engine) fn remove(&self, key: &TcpFlowKey, flow_id: u64) -> bool {
        let mut inner = self.inner.lock();
        let Some(record) = inner.records_by_key.get(key).copied() else {
            return false;
        };
        if record.flow_id != flow_id {
            return false;
        }
        inner.records_by_key.remove(key);

        inner.entries.remove(&FlowEvictionEntry {
            last_seen: record.last_seen,
            flow_id,
            key: key.clone(),
        })
    }

    pub(in crate::tcp::engine) fn pop_oldest(&self) -> Option<FlowEvictionCandidate> {
        let mut inner = self.inner.lock();
        let entry = inner.entries.pop_first()?;
        inner.records_by_key.remove(&entry.key);
        Some(FlowEvictionCandidate { key: entry.key, flow_id: entry.flow_id })
    }
}

#[cfg(test)]
#[path = "tests/eviction.rs"]
mod tests;
