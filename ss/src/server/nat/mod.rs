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
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::future::BoxFuture;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, OnceCell},
};
use tracing::{debug, warn};

use crate::{
    crypto::{UdpSession, UserKey, encrypt_udp_packet_for_response},
    fwmark::apply_fwmark_if_needed,
    metrics::{Metrics, Protocol},
    outbound::{OutboundIpv6, set_ipv6_freebind},
    protocol::TargetAddr,
};

// RFC 768: max UDP payload over IPv4 = 65 535 − 20 (IP) − 8 (UDP)
const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;

// ── NAT key ──────────────────────────────────────────────────────────────────

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
/// session. Thin wrapper around a `dyn ResponseSender` so `NatEntry` can hold
/// and replace the sender without caring about the concrete transport.
#[derive(Clone)]
pub(crate) struct UdpResponseSender {
    inner: Arc<dyn ResponseSender>,
}

impl UdpResponseSender {
    pub(crate) fn new(inner: Arc<dyn ResponseSender>) -> Self {
        Self { inner }
    }

    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    async fn send_bytes(&self, data: Bytes) -> bool {
        self.inner.send_bytes(data).await
    }
}

// ── NAT entry ─────────────────────────────────────────────────────────────────

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

struct ActiveSession {
    sender: UdpResponseSender,
    session: UdpSession,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl NatEntry {
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
}

// ── NAT table ─────────────────────────────────────────────────────────────────

/// Process-wide NAT table.  Shared via `Arc` in `AppState`.
pub(crate) struct NatTable {
    entries: DashMap<NatKey, Arc<OnceCell<Arc<NatEntry>>>>,
    idle_timeout: Duration,
    outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

impl NatTable {
    #[cfg(test)]
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        Self::with_outbound_ipv6(idle_timeout, None)
    }

    pub(crate) fn with_outbound_ipv6(
        idle_timeout: Duration,
        outbound_ipv6: Option<Arc<OutboundIpv6>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            idle_timeout,
            outbound_ipv6,
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
        // DashMap shard lock is held only for the insert/lookup, then dropped
        // before any `.await` — the OnceCell deduplicates concurrent creation.
        let cell = Arc::clone(
            self.entries
                .entry(key.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .value(),
        );

        // On error the cell stays uninitialised; evict_idle drops such cells
        // without counting them as evictions (they never incremented the
        // active-entries metric), so no second lock is needed to clean up.
        let create_user = user.clone();
        let outbound = self.outbound_ipv6.clone();
        cell.get_or_try_init(|| async move {
            Self::create_entry(&key, create_user, udp_session, metrics, outbound).await
        })
        .await
        .map(Arc::clone)
    }

    async fn create_entry(
        key: &NatKey,
        user: UserKey,
        udp_session: UdpSession,
        metrics: Arc<Metrics>,
        outbound_ipv6: Option<Arc<OutboundIpv6>>,
    ) -> Result<Arc<NatEntry>> {
        let socket = bind_nat_udp_socket(key.target, outbound_ipv6.as_deref())
            .with_context(|| format!("failed to bind NAT UDP socket for {}", key.target))?;
        apply_fwmark_if_needed(&socket, key.fwmark)
            .with_context(|| format!("failed to apply fwmark {:?} to NAT socket", key.fwmark))?;
        let socket = Arc::new(socket);

        let active: Arc<Mutex<Option<ActiveSession>>> = Arc::new(Mutex::new(None));
        let last_active_secs = Arc::new(AtomicU64::new(current_unix_secs()));
        let next_packet_id = Arc::new(AtomicU64::new(0));
        let server_session_id = match udp_session {
            UdpSession::Legacy => None,
            UdpSession::Aes2022 { .. } | UdpSession::Chacha2022 { .. } => {
                Some(random_session_id()?)
            },
        };

        let reader_task = tokio::spawn(nat_reader_task(
            Arc::clone(&socket),
            Arc::clone(&active),
            user.clone(),
            key.target,
            server_session_id,
            Arc::clone(&metrics),
            Arc::clone(&last_active_secs),
            Arc::clone(&next_packet_id),
        ));

        let entry = Arc::new(NatEntry {
            socket,
            active,
            last_active_secs,
            _reader: AbortOnDrop(reader_task),
        });
        debug!(
            user = %key.user_id,
            target = %key.target,
            "created UDP NAT entry"
        );
        metrics.record_udp_nat_entry_created();
        Ok(entry)
    }

    /// Remove entries that have had no outbound traffic for longer than
    /// `self.idle_timeout`.  The reader task for each evicted entry is aborted
    /// when the `Arc<NatEntry>` refcount reaches zero.
    /// Current number of active NAT entries (informational).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|r| r.value().get().is_some())
            .count()
    }

    pub(crate) fn evict_idle(&self, metrics: &Metrics) {
        let threshold = current_unix_secs().saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        self.entries.retain(|_, cell| match cell.get() {
            Some(entry) => {
                let keep = entry.last_active_secs.load(Ordering::Relaxed) >= threshold;
                if !keep {
                    evicted += 1;
                }
                keep
            },
            None => false,
        });
        if evicted > 0 {
            metrics.record_udp_nat_entries_evicted(evicted);
            debug!(
                evicted,
                remaining = self.entries.len(),
                "evicted idle UDP NAT entries"
            );
        }
    }
}

// ── Socket helpers ────────────────────────────────────────────────────────────

/// Create the NAT upstream UDP socket. When `outbound_ipv6` is configured and
/// the target is IPv6, the socket is bound to a random address from the pool
/// (with `IPV6_FREEBIND` to allow non-local bind); otherwise it falls back to
/// the kernel default wildcard bind, matching legacy behaviour. Interface
/// mode may return no usable address (e.g. interface not up yet) — in that
/// case we also fall back to the wildcard bind rather than fail the datagram.
fn bind_nat_udp_socket(
    target: SocketAddr,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    use socket2::{Domain, SockAddr, Socket, Type};

    let source = if target.is_ipv6() {
        match outbound_ipv6 {
            Some(src) => {
                let picked = src
                    .random_addr()
                    .context("failed to generate random outbound IPv6 address")?;
                if picked.is_none() {
                    debug!(
                        %target,
                        source = %src,
                        "outbound IPv6 pool is empty; NAT UDP socket falling back to wildcard bind",
                    );
                }
                picked
            },
            None => None,
        }
    } else {
        None
    };

    if source.is_none() {
        let bind_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let std_socket = std::net::UdpSocket::bind(bind_addr)
            .with_context(|| format!("failed to bind NAT UDP socket on {bind_addr}"))?;
        std_socket
            .set_nonblocking(true)
            .context("failed to set NAT UDP socket nonblocking")?;
        return UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket");
    }

    // IPv6 with random source.
    let source = source.expect("checked above");
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create NAT UDP socket")?;
    set_ipv6_freebind(&socket)
        .context("failed to set IPV6_FREEBIND on NAT UDP socket")?;
    let bind_addr = SocketAddr::V6(std::net::SocketAddrV6::new(source, 0, 0, 0));
    socket
        .bind(&SockAddr::from(bind_addr))
        .with_context(|| format!("failed to bind NAT UDP socket {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .context("failed to set NAT UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket")
}

// ── Background reader task ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn nat_reader_task(
    socket: Arc<UdpSocket>,
    active: Arc<Mutex<Option<ActiveSession>>>,
    user: UserKey,
    target: SocketAddr,
    server_session_id: Option<[u8; 8]>,
    metrics: Arc<Metrics>,
    last_active: Arc<AtomicU64>,
    next_packet_id: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD_SIZE];
    loop {
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(error) => {
                warn!(%target, %error, "UDP NAT socket recv error, closing reader");
                break;
            },
        };

        // Snapshot the active session so encryption picks up the latest
        // client_session_id after a reconnect.
        let (sender, session) = match active.lock().await.as_ref() {
            Some(a) => (a.sender.clone(), a.session.clone()),
            None => {
                // Intentionally do NOT touch last_active here: otherwise a
                // chatty upstream keeps the entry (and its socket + reader
                // task) alive forever after the client has gone away.
                metrics.record_udp_nat_response_dropped();
                debug!(%target, "NAT response dropped: no active client session");
                continue;
            },
        };

        let packet_id = next_packet_id.fetch_add(1, Ordering::Relaxed);
        let ciphertext = match encrypt_udp_packet_for_response(
            &user,
            &TargetAddr::Socket(source),
            &buf[..n],
            &session,
            server_session_id,
            packet_id,
        ) {
            Ok(v) => v,
            Err(error) => {
                warn!(%source, %error, "failed to encrypt NAT UDP response");
                continue;
            },
        };

        if record_oversized_socket_response_drop(
            Some(&sender),
            metrics.as_ref(),
            &user,
            source,
            ciphertext.len(),
        ) {
            continue;
        }

        let protocol = sender.protocol();
        let user_id = user.id_arc();
        metrics.record_udp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", n);
        metrics.record_udp_response_datagrams(user_id, protocol, 1);
        if sender.send_bytes(Bytes::from(ciphertext)).await {
            // Only a delivered response resets the idle timer. Otherwise a
            // chatty upstream pointed at a dead client would hold the NAT
            // entry (and its socket + reader task) alive indefinitely.
            last_active.store(current_unix_secs(), Ordering::Relaxed);
        } else {
            debug!(%target, "NAT response dropped: client session disconnected");
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

/// Returns the current Unix timestamp in whole seconds, saturating at zero on clock skew.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn record_oversized_socket_response_drop(
    sender: Option<&UdpResponseSender>,
    metrics: &Metrics,
    user: &UserKey,
    source: SocketAddr,
    ciphertext_len: usize,
) -> bool {
    if !matches!(sender.map(UdpResponseSender::protocol), Some(Protocol::Socket))
        || ciphertext_len <= MAX_UDP_PAYLOAD_SIZE
    {
        return false;
    }

    metrics.record_udp_oversized_datagram_dropped(
        user.id_arc(),
        Protocol::Socket,
        "target_to_client",
    );
    warn!(
        user = user.id(),
        %source,
        encrypted_bytes = ciphertext_len,
        max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
        "dropping oversized socket udp response datagram"
    );
    true
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use anyhow::Result;
    use bytes::Bytes;
    use futures_util::future::BoxFuture;

    use super::{
        MAX_UDP_PAYLOAD_SIZE, NatKey, NatTable, ResponseSender, UdpResponseSender,
        record_oversized_socket_response_drop,
    };
    use crate::{
        config::{CipherKind, Config},
        crypto::{UdpSession, UserKey},
        metrics::{Metrics, Protocol},
    };

    /// Minimal `ResponseSender` double used to exercise the NAT layer without
    /// pulling in the WebSocket/H3 transport crates.
    struct TestResponseSender {
        protocol: Protocol,
    }

    impl ResponseSender for TestResponseSender {
        fn send_bytes(&self, _data: Bytes) -> BoxFuture<'_, bool> {
            Box::pin(async { true })
        }

        fn protocol(&self) -> Protocol {
            self.protocol
        }
    }

    fn test_sender(protocol: Protocol) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(TestResponseSender { protocol }))
    }

    #[tokio::test]
    async fn drops_oversized_socket_udp_response_and_records_metric() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let sender = test_sender(Protocol::Socket);

        assert!(record_oversized_socket_response_drop(
            Some(&sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
            MAX_UDP_PAYLOAD_SIZE + 1,
        ));

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains(
            "outline_ss_udp_oversized_datagrams_dropped_total{user=\"bob\",protocol=\"socket\",direction=\"target_to_client\"} 1"
        ));
        Ok(())
    }

    #[test]
    fn ignores_non_socket_or_in_range_udp_response_sizes() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let ws_sender = test_sender(Protocol::Http2);

        assert!(!record_oversized_socket_response_drop(
            Some(&ws_sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            MAX_UDP_PAYLOAD_SIZE + 1,
        ));
        assert!(!record_oversized_socket_response_drop(
            Some(&ws_sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            MAX_UDP_PAYLOAD_SIZE,
        ));
        Ok(())
    }

    #[tokio::test]
    async fn deduplicates_concurrent_nat_entry_creation() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(Duration::from_secs(300));
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let key = NatKey {
            user_id: user.id_arc(),
            fwmark: None,
            target: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        };

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let nat_table = Arc::clone(&nat_table);
            let user = user.clone();
            let key = key.clone();
            let metrics = Arc::clone(&metrics);
            tasks.push(tokio::spawn(async move {
                nat_table.get_or_create(key, &user, UdpSession::Legacy, metrics).await
            }));
        }

        let mut entries = Vec::new();
        for task in tasks {
            entries.push(task.await??);
        }

        assert_eq!(nat_table.len(), 1);
        for entry in entries.iter().skip(1) {
            assert!(Arc::ptr_eq(&entries[0], entry));
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("outline_ss_udp_nat_entries_created_total 1"));
        assert!(rendered.contains("outline_ss_udp_nat_active_entries 1"));
        Ok(())
    }
}
