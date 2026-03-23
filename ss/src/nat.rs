//! Process-wide UDP NAT table for sharing socket state across client sessions.
//!
//! Instead of creating a new ephemeral UDP socket per incoming datagram, the NAT
//! table maintains a persistent socket per `(user_id, fwmark, target_addr)` triple.
//! This gives:
//!
//! - A stable source port for the lifetime of the NAT entry, which is required by
//!   stateful UDP protocols (QUIC, DTLS, some game protocols).
//! - Delivery of unsolicited upstream responses (server-initiated pushes) to the
//!   currently active client session.
//! - Transparent reconnect: a new client session for the same user immediately
//!   receives responses from the existing upstream socket without re-establishing
//!   the upstream association.
//!
//! Entries are evicted after `idle_timeout` with no outbound traffic.  A background
//! cleanup task calls [`NatTable::evict_idle`] on a regular interval.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::extract::ws::Message;
use bytes::Bytes;
use sockudo_ws::Message as H3Message;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
};
use tracing::{debug, warn};

use crate::{
    crypto::{UdpSession, UserKey, encrypt_udp_packet_for_response},
    fwmark::apply_fwmark_if_needed,
    metrics::{Metrics, Protocol},
    protocol::TargetAddr,
};

const UDP_NAT_RECV_BUF_SIZE: usize = 65_535;
const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;

// ── NAT key ──────────────────────────────────────────────────────────────────

/// Lookup key for a NAT entry.  Uniquely identifies the (user, routing mark,
/// resolved upstream address) triple.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct NatKey {
    pub user_id: String,
    pub fwmark: Option<u32>,
    pub target: SocketAddr,
    pub udp_client_session_id: Option<[u8; 8]>,
}

// ── Response sender abstraction ───────────────────────────────────────────────

/// A cloneable handle to the outbound path of the currently active client
/// session. Wraps both WebSocket transports and plain UDP sockets so the NAT
/// reader task can deliver upstream responses without knowing the transport
/// layer.
#[derive(Clone)]
pub(crate) struct UdpResponseSender {
    inner: UdpResponseSenderInner,
    protocol: Protocol,
}

#[derive(Clone)]
enum UdpResponseSenderInner {
    Ws(mpsc::Sender<Message>),
    H3(mpsc::Sender<H3Message>),
    Datagram {
        socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
    },
}

impl UdpResponseSender {
    pub(crate) fn ws(tx: mpsc::Sender<Message>, protocol: Protocol) -> Self {
        Self {
            inner: UdpResponseSenderInner::Ws(tx),
            protocol,
        }
    }

    pub(crate) fn h3(tx: mpsc::Sender<H3Message>) -> Self {
        Self {
            inner: UdpResponseSenderInner::H3(tx),
            protocol: Protocol::Http3,
        }
    }

    pub(crate) fn datagram(socket: Arc<UdpSocket>, client_addr: SocketAddr) -> Self {
        Self {
            inner: UdpResponseSenderInner::Datagram {
                socket,
                client_addr,
            },
            protocol: Protocol::Socket,
        }
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns `false` when the receiving channel has been closed (session gone).
    async fn send_bytes(&self, data: Bytes) -> bool {
        match &self.inner {
            UdpResponseSenderInner::Ws(tx) => tx.send(Message::Binary(data)).await.is_ok(),
            UdpResponseSenderInner::H3(tx) => tx.send(H3Message::Binary(data)).await.is_ok(),
            UdpResponseSenderInner::Datagram {
                socket,
                client_addr,
            } => socket.send_to(&data, *client_addr).await.is_ok(),
        }
    }
}

// ── NAT entry ─────────────────────────────────────────────────────────────────

pub(crate) struct NatEntry {
    socket: Arc<UdpSocket>,
    /// The outbound path for the currently active client session.
    /// Updated every time a new outbound datagram arrives so responses are
    /// delivered to the right session even after a reconnect.
    session_tx: Arc<Mutex<Option<UdpResponseSender>>>,
    /// Unix timestamp (seconds) of the last outbound datagram, for idle eviction.
    last_active_secs: Arc<AtomicU64>,
    /// Dropped when the entry is evicted, which aborts the background reader task.
    _reader: AbortOnDrop,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl NatEntry {
    /// Set the active client session that should receive upstream responses.
    /// The previous session (if any) is replaced; its channel may be closed.
    pub(crate) async fn register_session(&self, sender: UdpResponseSender) {
        *self.session_tx.lock().await = Some(sender);
    }

    /// Reset the idle-eviction timer.  Call after every successful outbound send.
    pub(crate) fn touch(&self) {
        self.last_active_secs
            .store(unix_secs_now(), Ordering::Relaxed);
    }

    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

// ── NAT table ─────────────────────────────────────────────────────────────────

/// Process-wide NAT table.  Shared via `Arc` in `AppState`.
pub(crate) struct NatTable {
    entries: Mutex<HashMap<NatKey, Arc<NatEntry>>>,
    idle_timeout: Duration,
}

impl NatTable {
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            idle_timeout,
        })
    }

    /// Returns the existing NAT entry for `key`, or creates a new one: binds a
    /// UDP socket, applies `fwmark` if set, and starts a background reader task
    /// that delivers upstream responses to the registered client session.
    pub(crate) async fn get_or_create(
        &self,
        key: NatKey,
        user: &UserKey,
        udp_session: UdpSession,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<NatEntry>> {
        if let Some(entry) = {
            let entries = self.entries.lock().await;
            entries.get(&key).cloned()
        } {
            return Ok(entry);
        }

        let bind_addr: &str = if key.target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind NAT UDP socket for {}", key.target))?;
        apply_fwmark_if_needed(&socket, key.fwmark)
            .with_context(|| format!("failed to apply fwmark {:?} to NAT socket", key.fwmark))?;
        let socket = Arc::new(socket);

        let session_tx: Arc<Mutex<Option<UdpResponseSender>>> = Arc::new(Mutex::new(None));
        let last_active_secs = Arc::new(AtomicU64::new(unix_secs_now()));
        let next_packet_id = Arc::new(AtomicU64::new(0));
        let server_session_id = match udp_session {
            UdpSession::Legacy => None,
            UdpSession::Aes2022 { .. } | UdpSession::Chacha2022 { .. } => {
                Some(random_session_id()?)
            }
        };

        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get(&key).cloned() {
            return Ok(entry);
        }

        let reader_task = tokio::spawn(nat_reader_task(
            Arc::clone(&socket),
            Arc::clone(&session_tx),
            user.clone(),
            key.target,
            udp_session.clone(),
            server_session_id,
            Arc::clone(&metrics),
            Arc::clone(&last_active_secs),
            Arc::clone(&next_packet_id),
        ));

        let entry = Arc::new(NatEntry {
            socket,
            session_tx,
            last_active_secs,
            _reader: AbortOnDrop(reader_task),
        });
        debug!(
            user = %key.user_id,
            target = %key.target,
            "created UDP NAT entry"
        );
        metrics.record_udp_nat_entry_created();
        entries.insert(key, Arc::clone(&entry));
        Ok(entry)
    }

    /// Remove entries that have had no outbound traffic for longer than
    /// `self.idle_timeout`.  The reader task for each evicted entry is aborted
    /// when the `Arc<NatEntry>` refcount reaches zero.
    pub(crate) async fn evict_idle(&self, metrics: &Metrics) {
        let threshold = unix_secs_now().saturating_sub(self.idle_timeout.as_secs());
        let mut entries = self.entries.lock().await;
        let before = entries.len();
        entries.retain(|_, entry| entry.last_active_secs.load(Ordering::Relaxed) >= threshold);
        let evicted = before - entries.len();
        if evicted > 0 {
            metrics.record_udp_nat_entries_evicted(evicted);
            debug!(
                evicted,
                remaining = entries.len(),
                "evicted idle UDP NAT entries"
            );
        }
    }

    /// Current number of active NAT entries (informational).
    #[allow(dead_code)]
    pub(crate) async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }
}

// ── Background reader task ────────────────────────────────────────────────────

async fn nat_reader_task(
    socket: Arc<UdpSocket>,
    session_tx: Arc<Mutex<Option<UdpResponseSender>>>,
    user: UserKey,
    target: SocketAddr,
    udp_session: UdpSession,
    server_session_id: Option<[u8; 8]>,
    metrics: Arc<Metrics>,
    last_active: Arc<AtomicU64>,
    next_packet_id: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; UDP_NAT_RECV_BUF_SIZE];
    loop {
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(error) => {
                warn!(%target, %error, "UDP NAT socket recv error, closing reader");
                break;
            }
        };

        last_active.store(unix_secs_now(), Ordering::Relaxed);

        let packet_id = next_packet_id.fetch_add(1, Ordering::Relaxed);
        let ciphertext = match encrypt_udp_packet_for_response(
            &user,
            &TargetAddr::Socket(source),
            &buf[..n],
            &udp_session,
            server_session_id,
            packet_id,
        ) {
            Ok(v) => v,
            Err(error) => {
                warn!(%source, %error, "failed to encrypt NAT UDP response");
                continue;
            }
        };

        let sender = { session_tx.lock().await.clone() };
        if matches!(
            sender.as_ref().map(UdpResponseSender::protocol),
            Some(Protocol::Socket)
        ) && ciphertext.len() > MAX_UDP_PAYLOAD_SIZE
        {
            metrics.record_udp_oversized_datagram_dropped(
                user.id_arc(),
                Protocol::Socket,
                "target_to_client",
            );
            warn!(
                user = user.id(),
                %source,
                encrypted_bytes = ciphertext.len(),
                max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
                "dropping oversized socket udp response datagram"
            );
            continue;
        }

        // Deliver to the currently registered client session.
        if let Some(sender) = sender {
            let protocol = sender.protocol();
            let user_id = user.id_arc();
            metrics.record_udp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", n);
            metrics.record_udp_response_datagrams(user_id, protocol, 1);
            if !sender.send_bytes(Bytes::from(ciphertext)).await {
                debug!(%target, "NAT response dropped: client session disconnected");
            }
        } else {
            metrics.record_udp_nat_response_dropped();
            debug!(%target, "NAT response dropped: no active client session");
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn random_session_id() -> Result<[u8; 8]> {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut session_id = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut session_id)
        .map_err(|error| anyhow::anyhow!("failed to generate UDP session id: {error:?}"))?;
    Ok(session_id)
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
