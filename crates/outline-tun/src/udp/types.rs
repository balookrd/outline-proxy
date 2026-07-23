use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, RwLock, mpsc};

use super::eviction::{FlowEvictionIndex, record_flow_activity};
use crate::utils::maybe_shrink_hash_map;
use crate::wire::IpVersion;
use outline_transport::AbortOnDrop;

/// Per-flow bound on client datagrams buffered toward the carrier before the
/// uplink task has drained them. The shared TUN read-loop only ever
/// `try_send`s onto this queue (never awaits it), so a slow/parked carrier
/// send can no longer head-of-line-block the read-loop — the failure mode that
/// froze the whole TUN (every TCP and UDP flow, local services) whenever one
/// UDP flow's carrier back-pressured or was still dialling. On overflow the
/// datagram is dropped, which is the correct connectionless response and keeps
/// the queue (and its memory) bounded per flow.
pub(super) const UDP_OUTBOUND_QUEUE_CAP: usize = 64;

/// Cap on datagrams buffered on the uplink task *while the carrier is still
/// being dialled*. Until the dial completes nothing can be sent, so the uplink
/// task drains the outbound channel into a local buffer instead of letting it
/// fill and drop — otherwise a slow dial (seconds under DPI) would lose the
/// client's QUIC-handshake Initials / PTO retransmits and stall the handshake
/// onto TCP. Generous because a handshake preface is only a handful of
/// datagrams; the dial timeout bounds how long this can grow, and overflow (a
/// flood during a hung dial) drops with a distinct `pending_dial_buffer_full`
/// metric rather than blocking the read-loop.
pub(super) const UDP_PENDING_DIAL_BUFFER_CAP: usize = 256;

/// Minimal view of a flow for table-level helpers: the per-flow `id`
/// (generation counter) used to detect races against replacement, the
/// `last_seen` stamp bumped from reader tasks, and the `last_seen` value that
/// stamp last published to the eviction index.
pub(super) trait FlowStamp {
    fn id(&self) -> u64;
    fn last_seen(&self) -> Instant;
    fn set_last_seen(&mut self, now: Instant);
    fn eviction_indexed_at(&self) -> Instant;
    fn set_eviction_indexed_at(&mut self, at: Instant);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct UdpFlowKey {
    pub(super) version: IpVersion,
    pub(super) local_ip: IpAddr,
    pub(super) local_port: u16,
    pub(super) remote_ip: IpAddr,
    pub(super) remote_port: u16,
}

pub(super) struct UdpFlowState {
    pub(super) id: u64,
    /// Current bound uplink index. `usize::MAX` while the flow's uplink task is
    /// still dialling the carrier (the flow record is inserted before the
    /// connect completes so datagrams buffer instead of parking the read-loop);
    /// the uplink task overwrites it once connected and on every reconnect.
    pub(super) uplink_index: usize,
    /// Uplink name; `"connecting"` until the uplink task finishes the dial.
    pub(super) uplink_name: Arc<str>,
    pub(super) group_name: Arc<str>,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
    /// `last_seen` value currently published to the engine's eviction index.
    /// Kept next to the flow so the per-datagram bump can decide *without* the
    /// index lock whether the advance is worth re-keying — see
    /// [`eviction_index_needs_refresh`](super::eviction::eviction_index_needs_refresh).
    pub(super) eviction_indexed_at: Instant,
    /// Wall-clock stamp of the last ICMP "Frag Needed" / "Packet Too Big"
    /// we synthesised for this flow after a transport oversize drop. Used
    /// to throttle PTB emission per-flow: RFC 4443 §2.4(f) makes ICMPv6
    /// rate-limiting mandatory, and RFC 1812 §4.3.2.8 strongly recommends
    /// it for IPv4 — without throttling a burst of oversize datagrams
    /// (very common during IKE_AUTH retransmits with large certificates)
    /// would generate a matching ICMP storm.
    pub(super) last_ptb_sent: Option<Instant>,
    /// Client→carrier datagram queue. The shared TUN read-loop `try_send`s the
    /// raw client payload here and returns immediately; the per-flow uplink
    /// task drains it, frames each datagram, and awaits the carrier send on its
    /// own task — so carrier back-pressure (or an in-progress dial) parks that
    /// task, never the read-loop. Bounded by [`UDP_OUTBOUND_QUEUE_CAP`]; a full
    /// queue drops the datagram (connectionless-correct) rather than blocking.
    pub(super) outbound_tx: mpsc::Sender<Bytes>,
    /// Per-flow uplink task: the sole owner of this flow's carrier. It dials the
    /// uplink, spawns the downlink reader, drains `outbound_tx` into carrier
    /// sends, and reconnects/fails-over on send error. `AbortOnDrop` ensures
    /// that when the flow is removed from the table (idle eviction, global
    /// switch, error close) the task stops on drop, releasing the transport it
    /// captured so the upstream UDP socket / TCP / QUIC connection closes
    /// promptly — even when the peer went silent and `read_packet` would
    /// otherwise block forever (UDP/quinn have no peer-gone shutdown signal).
    pub(super) _uplink_task: Option<AbortOnDrop>,
}

/// Flow map: `RwLock` on the map itself, `Arc<Mutex<_>>` per flow.
///
/// Hot path (per-packet) takes a short read-lock to clone the `Arc`, then
/// works on the per-flow `Mutex` without blocking other flows. Mirrors the
/// architecture in [`crate::tcp`]. Rare map-level mutations (flow
/// create / remove / idle eviction) take the write-lock.
pub(super) type FlowTable = Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<UdpFlowState>>>>>;

/// State for a direct-routed UDP flow: a plain socket that forwards
/// datagrams to the destination without any tunnel framing.
pub(super) struct DirectUdpFlowState {
    pub(super) id: u64,
    /// Client→destination datagram queue, the direct mirror of
    /// [`UdpFlowState::outbound_tx`]. The shared TUN read-loop `try_send`s here
    /// and returns; the flow's sender task awaits `send_to`. A direct flow has
    /// no carrier to absorb back-pressure — a full `SO_SNDBUF` or a congested
    /// qdisc on a slow egress parks `send_to` for as long as the kernel needs,
    /// which done inline on the read-loop parked *every* flow's packets behind
    /// this one. Bounded by [`UDP_OUTBOUND_QUEUE_CAP`]; a full queue drops the
    /// datagram (connectionless-correct) rather than blocking.
    pub(super) outbound_tx: mpsc::Sender<Bytes>,
    /// Sender task: drains `outbound_tx` into `send_to` on the flow's socket.
    /// `AbortOnDrop`, so removing the flow entry stops it and releases the
    /// captured `Arc<UdpSocket>`.
    pub(super) _sender: AbortOnDrop,
    /// Reader task for inbound datagrams on the same socket. `AbortOnDrop`
    /// cancels it on every removal path of the flow entry (idle
    /// eviction, write-side error, engine teardown); together with the sender
    /// it holds the last references to the socket, so the kernel reclaims the
    /// FD once both are gone.
    pub(super) _reader: AbortOnDrop,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
    /// See [`UdpFlowState::eviction_indexed_at`].
    pub(super) eviction_indexed_at: Instant,
}

pub(super) type DirectFlowTable = Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<DirectUdpFlowState>>>>>;

impl FlowStamp for UdpFlowState {
    fn id(&self) -> u64 {
        self.id
    }
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
    fn set_last_seen(&mut self, now: Instant) {
        self.last_seen = now;
    }
    fn eviction_indexed_at(&self) -> Instant {
        self.eviction_indexed_at
    }
    fn set_eviction_indexed_at(&mut self, at: Instant) {
        self.eviction_indexed_at = at;
    }
}

impl FlowStamp for DirectUdpFlowState {
    fn id(&self) -> u64 {
        self.id
    }
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
    fn set_last_seen(&mut self, now: Instant) {
        self.last_seen = now;
    }
    fn eviction_indexed_at(&self) -> Instant {
        self.eviction_indexed_at
    }
    fn set_eviction_indexed_at(&mut self, at: Instant) {
        self.eviction_indexed_at = at;
    }
}

/// Bump `last_seen` on the flow at `key` — but only if the flow currently
/// in the table still matches `flow_id`. Concurrent replacements (failover
/// re-creation, eviction) would otherwise let a zombie reader update the
/// wrong flow.
///
/// The flow's eviction-index position follows the bump, quantised so the
/// per-datagram path only touches the index lock once per
/// `UDP_EVICTION_INDEX_QUANTUM`.
pub(super) async fn bump_last_seen_if_current<K, F>(
    flows: &RwLock<HashMap<K, Arc<Mutex<F>>>>,
    eviction_index: &FlowEvictionIndex<K>,
    key: &K,
    flow_id: u64,
) where
    K: Clone + Eq + Hash,
    F: FlowStamp,
{
    let handle = flows.read().await.get(key).map(Arc::clone);
    if let Some(handle) = handle {
        let mut flow = handle.lock().await;
        if flow.id() == flow_id {
            flow.set_last_seen(Instant::now());
            record_flow_activity(eviction_index, key, &mut *flow);
        }
    }
}

/// Returns `true` if the flow at `key` exists and its id matches `flow_id`.
/// Used by reader tasks to avoid emitting runtime-failure reports for flows
/// already replaced by a failover.
pub(super) async fn flow_is_current<K, F>(
    flows: &RwLock<HashMap<K, Arc<Mutex<F>>>>,
    key: &K,
    flow_id: u64,
) -> bool
where
    K: Eq + Hash,
    F: FlowStamp,
{
    let handle = flows.read().await.get(key).map(Arc::clone);
    match handle {
        Some(h) => h.lock().await.id() == flow_id,
        None => false,
    }
}

/// Drain flows whose `last_seen` is older than `idle_timeout`, without
/// holding the map write-lock across per-flow lock acquisitions.
///
/// Removal re-checks handle identity under the write-lock, mirroring
/// [`super::lifecycle`]'s `close_flow_if_current`: the candidate scan runs with
/// the map unlocked, so a flow may be torn down and re-created under the same
/// key while it is in progress.
///
/// Returns the removed entries — key and `Arc<Mutex<F>>` handle — so callers can
/// route them through their own close-work pipeline (each flow type has a
/// distinct teardown path) *and* drop their eviction-index entries; an index
/// that kept keys for idle-reaped flows would leak one entry per reaped flow.
pub(super) async fn drain_idle_flows<K, F>(
    flows: &RwLock<HashMap<K, Arc<Mutex<F>>>>,
    idle_timeout: Duration,
    now: Instant,
) -> Vec<(K, Arc<Mutex<F>>)>
where
    K: Eq + Hash + Clone,
    F: FlowStamp,
{
    let handles: Vec<(K, Arc<Mutex<F>>)> = {
        let guard = flows.read().await;
        guard.iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect()
    };
    let mut expired = Vec::new();
    for (key, handle) in handles {
        let idle = {
            let flow = handle.lock().await;
            now.saturating_duration_since(flow.last_seen()) >= idle_timeout
        };
        if idle {
            expired.push((key, handle));
        }
    }
    let mut guard = flows.write().await;
    let mut removed = Vec::with_capacity(expired.len());
    for (key, snapshot) in expired {
        // Re-check under the write-lock: scanning the candidates above runs
        // with the map unlocked and takes a per-flow lock per candidate, so a
        // real teardown (read error, global switch) may have removed this flow
        // and the client re-created it under the same 5-tuple meanwhile.
        // Removing by key alone would evict that brand-new flow as
        // `idle_timeout` at age ~0, dropping its outbound queue and its
        // buffered handshake preface. Comparing handle identity is lock-free
        // and exact — a re-created flow is always a different `Arc`. Returns
        // `(key, flow)` so the caller can also drop the eviction-index entry.
        if guard.get(&key).is_some_and(|current| Arc::ptr_eq(current, &snapshot))
            && let Some(flow) = guard.remove(&key)
        {
            removed.push((key, flow));
        }
    }
    maybe_shrink_hash_map(&mut guard);
    removed
}

#[cfg(test)]
#[path = "tests/types.rs"]
mod tests;
