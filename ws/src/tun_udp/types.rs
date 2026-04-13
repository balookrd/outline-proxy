use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::transport::UdpWsTransport;
use crate::tun_wire::IpVersion;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct UdpFlowKey {
    pub(super) version: IpVersion,
    pub(super) local_ip: IpAddr,
    pub(super) local_port: u16,
    pub(super) remote_ip: IpAddr,
    pub(super) remote_port: u16,
}

#[derive(Clone)]
pub(super) struct UdpFlowState {
    pub(super) id: u64,
    pub(super) transport: Arc<UdpWsTransport>,
    pub(super) uplink_index: usize,
    pub(super) uplink_name: String,
    pub(super) created_at: Instant,
    pub(super) last_seen: Instant,
}

pub(super) type FlowTable = Arc<Mutex<HashMap<UdpFlowKey, UdpFlowState>>>;
