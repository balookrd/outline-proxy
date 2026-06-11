use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use parking_lot::Mutex;

use super::super::TcpFlowKey;

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
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use crate::wire::IpVersion;

    use super::*;

    fn key(client_port: u16) -> TcpFlowKey {
        TcpFlowKey {
            version: IpVersion::V4,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            client_port,
            remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            remote_port: 443,
        }
    }

    #[test]
    fn pop_oldest_follows_activity_updates() {
        let index = FlowEvictionIndex::new();
        let first = key(40000);
        let second = key(40001);
        let now = Instant::now();

        index.upsert(first.clone(), 1, now);
        index.upsert(second.clone(), 2, now + Duration::from_millis(1));
        index.upsert(first.clone(), 1, now + Duration::from_millis(2));

        let evicted = index.pop_oldest().unwrap();
        assert_eq!(evicted.key, second);
        assert_eq!(evicted.flow_id, 2);
        let evicted = index.pop_oldest().unwrap();
        assert_eq!(evicted.key, first);
        assert_eq!(evicted.flow_id, 1);
        assert!(index.pop_oldest().is_none());
    }

    #[test]
    fn remove_drops_entry_from_ordered_index() {
        let index = FlowEvictionIndex::new();
        let first = key(40000);
        let second = key(40001);
        let now = Instant::now();

        index.upsert(first.clone(), 1, now);
        index.upsert(second.clone(), 2, now + Duration::from_millis(1));

        assert!(index.remove(&first, 1));
        assert!(!index.remove(&first, 1));
        let evicted = index.pop_oldest().unwrap();
        assert_eq!(evicted.key, second);
        assert_eq!(evicted.flow_id, 2);
        assert!(index.pop_oldest().is_none());
    }

    #[test]
    fn stale_activity_cannot_replace_newer_flow_generation() {
        let index = FlowEvictionIndex::new();
        let key = key(40000);
        let now = Instant::now();

        index.upsert(key.clone(), 2, now + Duration::from_millis(1));
        index.upsert(key.clone(), 1, now);

        let evicted = index.pop_oldest().unwrap();
        assert_eq!(evicted.key, key);
        assert_eq!(evicted.flow_id, 2);
        assert!(index.pop_oldest().is_none());
    }
}
