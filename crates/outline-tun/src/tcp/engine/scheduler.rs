use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::super::TcpFlowKey;

/// Priority queue of flow maintenance deadlines.
///
/// Flows push entries whenever their next-deadline changes; the maintenance
/// loop pops due entries in order. Stale entries (deadline no longer matches
/// the flow's canonical `next_scheduled_deadline`) are filtered on pop — the
/// heap never shrinks on in-place updates, we just insert a new entry and
/// let the stale one age out. Bounded because each flow holds at most one
/// canonical entry; stale entries are O(number of mutations since last pop).
pub(in crate::tcp) struct FlowScheduler {
    heap: Mutex<BinaryHeap<Reverse<Entry>>>,
    wake: Notify,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    deadline: Instant,
    key: TcpFlowKey,
}

impl FlowScheduler {
    pub(in crate::tcp) fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            wake: Notify::new(),
        }
    }

    /// Enqueue a flow to be inspected at `deadline`. Wakes the loop.
    pub(in crate::tcp) fn schedule(&self, key: TcpFlowKey, deadline: Instant) {
        self.heap.lock().push(Reverse(Entry { deadline, key }));
        self.wake.notify_one();
    }

    /// Peek the earliest scheduled deadline without popping.
    pub(in crate::tcp) fn peek_deadline(&self) -> Option<Instant> {
        self.heap.lock().peek().map(|Reverse(e)| e.deadline)
    }

    /// Pop all entries whose deadline has arrived.
    ///
    /// Returns `(deadline, key)` pairs. Callers are responsible for
    /// verifying each entry against the flow's canonical deadline to
    /// discard stale pushes.
    pub(in crate::tcp) fn drain_due(&self, now: Instant) -> Vec<(Instant, TcpFlowKey)> {
        let mut heap = self.heap.lock();
        let mut out = Vec::new();
        while let Some(Reverse(entry)) = heap.peek() {
            if entry.deadline > now {
                break;
            }
            let Reverse(entry) = heap.pop().expect("peek succeeded");
            out.push((entry.deadline, entry.key));
        }
        out
    }

    pub(in crate::tcp) async fn wait(&self) {
        self.wake.notified().await;
    }

    /// Wake the loop without scheduling — used for tests and forced drains.
    pub(in crate::tcp) fn wake(&self) {
        self.wake.notify_one();
    }
}
