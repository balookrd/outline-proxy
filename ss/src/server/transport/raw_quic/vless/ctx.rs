use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use dashmap::DashMap;
use metrics::Counter;
use tokio::net::UdpSocket;

use crate::protocol::vless::VlessUser;

/// Per-QUIC-connection state for raw VLESS: tracks open UDP sessions so the
/// connection-level datagram pump can route incoming datagrams to the right
/// upstream socket.
pub(in crate::server) struct VlessQuicConn {
    pub(super) next_session: AtomicU32,
    pub(super) sessions: DashMap<u32, Arc<VlessUdpSession>>,
    /// Connection-level oversize-record stream, lazy-installed when
    /// either the client opens it (peer accept_bi path) or the server
    /// itself needs to send an oversized response (server-initiated
    /// open). Empty when the negotiated ALPN is the legacy `vless`
    /// (no MTU-aware fallback) or when no oversized packet has flowed
    /// yet on this connection.
    pub(in crate::server) oversize_slot: super::super::OversizeStreamSlot,
}

pub(super) struct VlessUdpSession {
    pub(super) socket: Arc<UdpSocket>,
    /// Pre-resolved client→target byte counter for this session's user.
    /// Holding the resolved [`Counter`] handle lets the per-datagram spawn
    /// task (and the oversize-record router) increment without an
    /// `Arc::clone(&user_label)` or a `counter!()` registry lookup.
    pub(super) udp_in: Counter,
}

impl VlessQuicConn {
    pub(in crate::server) fn new() -> Self {
        Self {
            next_session: AtomicU32::new(1),
            sessions: DashMap::new(),
            oversize_slot: super::super::OversizeStreamSlot::new(),
        }
    }

    pub(super) fn allocate_session(&self) -> u32 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn register(&self, id: u32, session: Arc<VlessUdpSession>) {
        self.sessions.insert(id, session);
    }

    pub(super) fn unregister(&self, id: u32) {
        self.sessions.remove(&id);
    }

    pub(super) fn lookup(&self, id: u32) -> Option<Arc<VlessUdpSession>> {
        self.sessions.get(&id).map(|entry| Arc::clone(entry.value()))
    }
}

pub(super) const MAX_VLESS_HEADER_BUFFER: usize = 512;

pub(in crate::server) struct RawQuicVlessRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}
