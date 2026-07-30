use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::server::abort::AbortOnDrop;
use crate::{
    clock,
    crypto::{UdpCipherMode, UserKey},
    metrics::{AppProtocol, PerUserCounters, Protocol},
};

/// Lookup key for a NAT entry.  Identifies the (user, routing mark, resolved
/// upstream address) triple, optionally narrowed to a single resumable session
/// by [`scope`](Self::scope).
///
/// The `scope` discriminator is what keeps two *concurrent* SS-UDP-over-WS
/// carriers for the same (user, target) from sharing one entry — and therefore
/// one last-writer-wins response slot. It is the session identity the entry was
/// pinned to (the client's issued/resume id), so it stays stable across a
/// reconnect/resume (the resuming carrier adopts the parked scope) yet differs
/// between two independent sessions. `None` on the plain shadowsocks UDP
/// listener and whenever session resumption is disabled — those paths keep the
/// historical shared-entry behaviour.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct NatKey {
    pub user_id: Arc<str>,
    pub fwmark: Option<u32>,
    pub target: SocketAddr,
    pub scope: Option<NatScope>,
}

/// Session discriminator embedded in a [`NatKey`]. The raw 16 bytes of the
/// session's issued/resume id — kept as a plain array so the NAT layer stays
/// independent of the resumption module's `SessionId` type.
pub(crate) type NatScope = [u8; 16];

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
    /// Application-layer protocol carried by this responder. Lets the
    /// shared NAT reader tag per-datagram metrics by `app_protocol`
    /// without needing to know which transport module created the entry.
    fn app_protocol(&self) -> AppProtocol;
}

/// How a NAT entry's reader must encode an upstream response before handing it
/// to the active session's sender.
///
/// It is a property of the *attachment*, not of the entry, because one NAT
/// socket outlives the carriers that address it and those carriers do not all
/// terminate the client's crypto:
///
/// - A client-terminating carrier — the direct SS-UDP listeners, and a mesh
///   *edge* — seals the response itself, so it hands over the user key and
///   the live [`UdpCipherMode`] the client's own datagram carried.
/// - A **mesh home** cannot: the seal needs the client session id that rides
///   inside a datagram the edge decrypted and this node never saw. It therefore
///   emits the SOCKS5-wrapped plaintext (`TargetAddr(source) || payload`) that
///   is exactly the body the sealed arm would have encrypted, and the edge seals
///   it under the client's key.
///
/// Keeping the [`UserKey`] here rather than on the entry is what lets the same
/// NAT socket serve both: a session parked by a relayed carrier and resumed by a
/// direct one (or the reverse) re-points the slot and the coding together.
#[derive(Clone)]
pub(crate) enum UdpResponseCoding {
    /// Shadowsocks AEAD, sealed for `user` under the client's `session`.
    Ss { user: UserKey, session: UdpCipherMode },
    /// SOCKS5-wrapped plaintext, sealed downstream by a cluster edge.
    Plaintext,
}

impl UdpResponseCoding {
    /// Whether the carrier behind this attachment terminates the client's
    /// session — and therefore owns its per-user byte and request accounting.
    ///
    /// Per-user accounting belongs to exactly one node: the one the client's
    /// crypto ends on. `Ss` is that node by construction (it holds the key);
    /// `Plaintext` is a v5 mesh home, whose edge already counted these same
    /// bytes against the same user under the client's real protocol. Counting
    /// them here too would double every relayed user's
    /// `outline_ss_udp_payload_bytes_total`, `outline_ss_udp_requests_total` and
    /// `outline_ss_udp_response_datagrams_total`, and would do it under
    /// `protocol="http3"` — the mesh's protocol — where the duplicate is
    /// indistinguishable from genuine direct H3 traffic on the same node and so
    /// cannot even be subtracted back out. The home's share of relayed traffic
    /// is on its `role="home"` mesh counters instead, which is the same split
    /// `splice_plaintext_tcp` makes by dropping `ParkedTcp::user_counters`.
    ///
    /// Node-local facts stay unconditional either way: a drop the home decided
    /// on (oversized datagram, relay concurrency limit) happened *here* and is
    /// counted nowhere else.
    pub(crate) fn terminates_client_session(&self) -> bool {
        matches!(self, Self::Ss { .. })
    }
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

    pub(crate) fn app_protocol(&self) -> AppProtocol {
        self.inner.app_protocol()
    }

    pub(crate) async fn send_bytes(&self, data: Bytes) -> bool {
        self.inner.send_bytes(data).await
    }
}

// ── NAT entry ─────────────────────────────────────────────────────────────────

pub(crate) struct ActiveSession {
    pub(crate) sender: UdpResponseSender,
    /// How this attachment needs upstream responses encoded; see
    /// [`UdpResponseCoding`].
    pub(crate) coding: UdpResponseCoding,
    /// Identifies the registering WS-stream so a resumption-driven
    /// `detach_session_for_stream` only clears the slot when we are
    /// still the registered owner — not when a newer stream has
    /// already taken over (e.g. concurrent reconnect by the same
    /// user). Allocated by the relay code once per stream lifetime.
    pub(crate) stream_id: u64,
}

pub(crate) struct NatEntry {
    socket: Arc<UdpSocket>,
    /// The currently active client session: where to deliver upstream responses
    /// and how to encode them ([`UdpResponseCoding`] — for a client-terminating
    /// carrier the user key plus the live `client_session_id`, for a v5 relayed
    /// one plaintext). Replaced atomically on every reconnect so the NAT socket
    /// — and therefore the source port and server_session_id — survives client
    /// session changes.
    active: Arc<Mutex<Option<ActiveSession>>>,
    /// Pre-resolved per-user metrics counters, shared with the reader task.
    /// Lets the per-datagram client→upstream and upstream→client paths skip the
    /// `counter!()` registry lookup and the per-call `Arc<str>` clone.
    user_counters: Arc<PerUserCounters>,
    /// Unix timestamp (seconds) of the last datagram in either direction, for idle eviction.
    last_active_secs: Arc<AtomicU64>,
    /// Dropped when the entry is evicted, which aborts the background reader task.
    _reader: AbortOnDrop<()>,
}

impl NatEntry {
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        active: Arc<Mutex<Option<ActiveSession>>>,
        user_counters: Arc<PerUserCounters>,
        last_active_secs: Arc<AtomicU64>,
        reader: tokio::task::JoinHandle<()>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            active,
            user_counters,
            last_active_secs,
            _reader: AbortOnDrop::new(reader),
        })
    }

    pub(crate) fn user_counters(&self) -> &PerUserCounters {
        &self.user_counters
    }

    /// Set the active client session that should receive upstream responses,
    /// along with the [`UdpResponseCoding`] its carrier needs them encoded in.
    /// The previous session (if any) is replaced; its channel may be closed.
    ///
    /// `stream_id` identifies the registering WS-stream (or
    /// shadowsocks plain-UDP session). It is matched by
    /// [`Self::detach_session_for_stream`] so a stream's park-on-drop
    /// only clears the slot when we are still the registered owner.
    pub(crate) fn register_session(
        &self,
        sender: UdpResponseSender,
        coding: UdpResponseCoding,
        stream_id: u64,
    ) {
        *self.active.lock() = Some(ActiveSession { sender, coding, stream_id });
    }

    /// Atomically clears the active session slot iff its `stream_id`
    /// matches `expected`. Returns `true` on detach. Used by the
    /// SS-UDP-over-WS park path to release the entry's response sender
    /// without disrupting other streams that may have taken over
    /// in the meantime.
    pub(crate) fn detach_session_for_stream(&self, expected: u64) -> bool {
        let mut guard = self.active.lock();
        match guard.as_ref() {
            Some(active) if active.stream_id == expected => {
                *guard = None;
                true
            },
            _ => false,
        }
    }

    /// Reset the idle-eviction timer.  Call after every successful outbound send.
    pub(crate) fn touch(&self) {
        self.last_active_secs
            .store(clock::current_unix_secs(), Ordering::Relaxed);
    }

    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub(crate) fn last_active_secs(&self) -> &AtomicU64 {
        &self.last_active_secs
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn random_session_id() -> Result<[u8; 8]> {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut session_id = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut session_id)
        .map_err(|error| anyhow::anyhow!("failed to generate UDP session id: {error:?}"))?;
    Ok(session_id)
}
