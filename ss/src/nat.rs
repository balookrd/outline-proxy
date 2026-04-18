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
use bytes::Bytes;
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
    pub udp_client_session_id: Option<[u8; 8]>,
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
    /// The outbound path for the currently active client session.
    /// Updated every time a new outbound datagram arrives so responses are
    /// delivered to the right session even after a reconnect.
    session_tx: Arc<Mutex<Option<UdpResponseSender>>>,
    /// Unix timestamp (seconds) of the last datagram in either direction, for idle eviction.
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
        self.last_active_secs.store(unix_secs_now(), Ordering::Relaxed);
    }

    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

// ── NAT table ─────────────────────────────────────────────────────────────────

/// Process-wide NAT table.  Shared via `Arc` in `AppState`.
pub(crate) struct NatTable {
    entries: Mutex<HashMap<NatKey, Arc<OnceCell<Arc<NatEntry>>>>>,
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
        let cell = {
            let mut entries = self.entries.lock().await;
            Arc::clone(
                entries
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new())),
            )
        };

        // On error the cell stays uninitialised. evict_idle already removes
        // cells whose get() is None, so no second lock is needed to clean up.
        let create_user = user.clone();
        cell.get_or_try_init(|| async move {
            Self::create_entry(&key, create_user, udp_session, metrics).await
        })
        .await
        .map(Arc::clone)
    }

    async fn create_entry(
        key: &NatKey,
        user: UserKey,
        udp_session: UdpSession,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<NatEntry>> {
        let bind_addr: &str = if key.target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
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
            },
        };

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
        Ok(entry)
    }

    /// Remove entries that have had no outbound traffic for longer than
    /// `self.idle_timeout`.  The reader task for each evicted entry is aborted
    /// when the `Arc<NatEntry>` refcount reaches zero.
    /// Current number of active NAT entries (informational).
    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize {
        self.entries
            .lock()
            .await
            .values()
            .filter(|cell| cell.get().is_some())
            .count()
    }

    pub(crate) async fn evict_idle(&self, metrics: &Metrics) {
        let threshold = unix_secs_now().saturating_sub(self.idle_timeout.as_secs());
        let mut entries = self.entries.lock().await;
        let before = entries.len();
        entries.retain(|_, cell| {
            cell.get()
                .is_none_or(|entry| entry.last_active_secs.load(Ordering::Relaxed) >= threshold)
        });
        let evicted = before - entries.len();
        if evicted > 0 {
            metrics.record_udp_nat_entries_evicted(evicted);
            debug!(evicted, remaining = entries.len(), "evicted idle UDP NAT entries");
        }
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
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD_SIZE];
    loop {
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(error) => {
                warn!(%target, %error, "UDP NAT socket recv error, closing reader");
                break;
            },
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
            },
        };

        let sender = { session_tx.lock().await.clone() };
        if record_oversized_socket_response_drop(
            sender.as_ref(),
            metrics.as_ref(),
            &user,
            source,
            ciphertext.len(),
        ) {
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

/// Returns the current Unix timestamp in whole seconds, saturating at zero on clock skew.
fn unix_secs_now() -> u64 {
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
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
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
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
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
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
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
            udp_client_session_id: None,
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

        assert_eq!(nat_table.len().await, 1);
        for entry in entries.iter().skip(1) {
            assert!(Arc::ptr_eq(&entries[0], entry));
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("outline_ss_udp_nat_entries_created_total 1"));
        assert!(rendered.contains("outline_ss_udp_nat_active_entries 1"));
        Ok(())
    }
}
