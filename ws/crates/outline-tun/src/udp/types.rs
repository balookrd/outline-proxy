use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

use outline_transport::{AbortOnDrop, UdpSessionTransport};
use crate::utils::maybe_shrink_hash_map;
use crate::wire::IpVersion;
use outline_uplink::UplinkManager;

/// Minimal view of a flow for table-level helpers: the per-flow `id`
/// (generation counter) used to detect races against replacement, and the
/// `last_seen` stamp bumped from reader tasks.
pub(super) trait FlowStamp {
    fn id(&self) -> u64;
    fn last_seen(&self) -> Instant;
    fn set_last_seen(&mut self, now: Instant);
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
    pub(super) transport: Arc<UdpSessionTransport>,
    pub(super) uplink_index: usize,
    pub(super) uplink_name: Arc<str>,
    pub(super) group_name: Arc<str>,
    /// The group's manager this flow was bound to at creation. All per-flow
    /// operations (failover, strict-active checks, reconciliation) run
    /// against this manager, not the engine's default group.
    pub(super) manager: UplinkManager,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
    /// Reader pump for this flow's upstream-to-client direction.
    /// `AbortOnDrop` ensures that when the flow is removed from the
    /// table (idle eviction, global switch, error close, send failure)
    /// the reader stops on its own drop — the `Arc<UdpSessionTransport>`
    /// it captured is then released, the underlying transport's own
    /// `Drop` runs, and the upstream UDP socket / TCP / QUIC connection
    /// is closed promptly. Without this, the reader would block on
    /// `transport.read_packet().await` indefinitely (UDP/quinn have no
    /// shutdown signal that fires when the peer goes silent), pinning
    /// the socket and tracker buffers for the full transport idle
    /// window — minutes, or never if keepalive is off.
    pub(super) _reader_task: Option<AbortOnDrop>,
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
    pub(super) socket: Arc<UdpSocket>,
    /// Reader task for inbound datagrams on `socket`. `AbortOnDrop`
    /// cancels it on every removal path of the flow entry (idle
    /// eviction, write-side error, engine teardown), releasing the
    /// captured `Arc<UdpSocket>` so the kernel reclaims the FD.
    pub(super) _reader: AbortOnDrop,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
}

pub(super) type DirectFlowTable =
    Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<DirectUdpFlowState>>>>>;

impl FlowStamp for UdpFlowState {
    fn id(&self) -> u64 { self.id }
    fn last_seen(&self) -> Instant { self.last_seen }
    fn set_last_seen(&mut self, now: Instant) { self.last_seen = now; }
}

impl FlowStamp for DirectUdpFlowState {
    fn id(&self) -> u64 { self.id }
    fn last_seen(&self) -> Instant { self.last_seen }
    fn set_last_seen(&mut self, now: Instant) { self.last_seen = now; }
}

/// Bump `last_seen` on the flow at `key` — but only if the flow currently
/// in the table still matches `flow_id`. Concurrent replacements (failover
/// re-creation, eviction) would otherwise let a zombie reader update the
/// wrong flow.
pub(super) async fn bump_last_seen_if_current<K, F>(
    flows: &RwLock<HashMap<K, Arc<Mutex<F>>>>,
    key: &K,
    flow_id: u64,
) where
    K: Eq + Hash,
    F: FlowStamp,
{
    let handle = flows.read().await.get(key).map(Arc::clone);
    if let Some(handle) = handle {
        let mut flow = handle.lock().await;
        if flow.id() == flow_id {
            flow.set_last_seen(Instant::now());
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
/// Returns the removed `Arc<Mutex<F>>` handles so callers can route them
/// through their own close-work pipeline (each flow type has a distinct
/// teardown path).
pub(super) async fn drain_idle_flows<K, F>(
    flows: &RwLock<HashMap<K, Arc<Mutex<F>>>>,
    idle_timeout: Duration,
    now: Instant,
) -> Vec<Arc<Mutex<F>>>
where
    K: Eq + Hash + Clone,
    F: FlowStamp,
{
    let handles: Vec<(K, Arc<Mutex<F>>)> = {
        let guard = flows.read().await;
        guard.iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect()
    };
    let mut expired_keys = Vec::new();
    for (key, handle) in handles {
        let flow = handle.lock().await;
        if now.saturating_duration_since(flow.last_seen()) >= idle_timeout {
            expired_keys.push(key);
        }
    }
    let mut guard = flows.write().await;
    let removed: Vec<_> = expired_keys
        .into_iter()
        .filter_map(|k| guard.remove(&k))
        .collect();
    maybe_shrink_hash_map(&mut guard);
    removed
}
