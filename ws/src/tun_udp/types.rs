use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::transport::UdpWsTransport;
use crate::tun_wire::IpVersion;
use crate::uplink::UplinkManager;

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
    pub(super) transport: Arc<UdpWsTransport>,
    pub(super) uplink_index: usize,
    pub(super) uplink_name: String,
    /// The group's manager this flow was bound to at creation. All per-flow
    /// operations (failover, strict-active checks, reconciliation) run
    /// against this manager, not the engine's default group.
    pub(super) manager: UplinkManager,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
}

/// Flow map: `RwLock` on the map itself, `Arc<Mutex<_>>` per flow.
///
/// Hot path (per-packet) takes a short read-lock to clone the `Arc`, then
/// works on the per-flow `Mutex` without blocking other flows. Mirrors the
/// architecture in [`crate::tun_tcp`]. Rare map-level mutations (flow
/// create / remove / idle eviction) take the write-lock.
pub(super) type FlowTable = Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<UdpFlowState>>>>>;

/// State for a direct-routed UDP flow: a plain socket that forwards
/// datagrams to the destination without any tunnel framing.
pub(super) struct DirectUdpFlowState {
    pub(super) id: u64,
    pub(super) socket: Arc<UdpSocket>,
    pub(super) _reader: JoinHandle<()>,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
}

pub(super) type DirectFlowTable =
    Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<DirectUdpFlowState>>>>>;
