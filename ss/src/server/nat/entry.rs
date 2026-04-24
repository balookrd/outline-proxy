use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{crypto::UdpSession, metrics::Protocol};

/// Lookup key for a NAT entry.  Uniquely identifies the (user, routing mark,
/// resolved upstream address) triple.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct NatKey {
    pub user_id: Arc<str>,
    pub fwmark: Option<u32>,
    pub target: SocketAddr,
}

// ── Response sender abstraction ───────────────────────────────────────────────

/// Transport-agnostic outbound path for a client session.
///
/// Implementations live in the transport modules (`server::transport`,
/// `server::shadowsocks`); the NAT layer only sees this trait so it stays
/// independent of WebSocket / HTTP/3 / raw-socket specifics.
pub(crate) trait ResponseSender: Send + Sync {
    /// Returns `false` when the receiving channel has been closed (session gone).
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool>;
    fn protocol(&self) -> Protocol;
}

/// A cloneable handle to the outbound path of the currently active client
/// session.
#[derive(Clone)]
pub(crate) struct UdpResponseSender {
    inner: Arc<dyn ResponseSender>,
}

impl UdpResponseSender {
    pub(crate) fn new(inner: Arc<dyn ResponseSender>) -> Self {
        Self { inner }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    pub(crate) async fn send_bytes(&self, data: Bytes) -> bool {
        self.inner.send_bytes(data).await
    }
}

// ── NAT entry ─────────────────────────────────────────────────────────────────

pub(crate) struct ActiveSession {
    pub(crate) sender: UdpResponseSender,
    pub(crate) session: UdpSession,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct NatEntry {
    socket: Arc<UdpSocket>,
    /// The currently active client session: where to deliver upstream responses
    /// and which `UdpSession` (carrying the live `client_session_id` for SS-2022)
    /// to use when encrypting them. Replaced atomically on every reconnect so
    /// the NAT socket — and therefore the source port and server_session_id —
    /// survives client session changes.
    active: Arc<Mutex<Option<ActiveSession>>>,
    /// Unix timestamp (seconds) of the last datagram in either direction, for idle eviction.
    last_active_secs: Arc<AtomicU64>,
    /// Dropped when the entry is evicted, which aborts the background reader task.
    _reader: AbortOnDrop,
}

impl NatEntry {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        active: Arc<Mutex<Option<ActiveSession>>>,
        last_active_secs: Arc<AtomicU64>,
        reader: tokio::task::JoinHandle<()>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            active,
            last_active_secs,
            _reader: AbortOnDrop(reader),
        })
    }

    /// Set the active client session that should receive upstream responses,
    /// along with the `UdpSession` used to encrypt them. The previous session
    /// (if any) is replaced; its channel may be closed.
    pub(crate) async fn register_session(
        &self,
        sender: UdpResponseSender,
        session: UdpSession,
    ) {
        *self.active.lock().await = Some(ActiveSession { sender, session });
    }

    /// Reset the idle-eviction timer.  Call after every successful outbound send.
    pub(crate) fn touch(&self) {
        self.last_active_secs.store(current_unix_secs(), Ordering::Relaxed);
    }

    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub(crate) fn last_active_secs(&self) -> &AtomicU64 {
        &self.last_active_secs
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn random_session_id() -> Result<[u8; 8]> {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut session_id = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut session_id)
        .map_err(|error| anyhow::anyhow!("failed to generate UDP session id: {error:?}"))?;
    Ok(session_id)
}
