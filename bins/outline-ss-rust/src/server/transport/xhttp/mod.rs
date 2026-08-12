//! Server-side XHTTP packet-up transport for VLESS.
//!
//! Multiplexes a VLESS session over a single long-lived GET
//! (downlink) plus many short POSTs (uplink) sharing a path. The
//! pair is glued by an opaque session id carried as the last URL
//! segment, so a CDN that key-shards by full URL routes both halves
//! to the same origin. The id is opaque to the server: the client
//! picks it, we just key the registry by it.
//!
//! Why packet-up only: `stream-up` requires a long-lived chunked
//! POST body which Cloudflare and similar CDNs buffer end-to-end,
//! defeating the very point of XHTTP; `stream-one` is functionally
//! equivalent to our existing RFC 9220 ws-over-h3, no new ground.
//!
//! Lifetimes:
//! * Either POST or GET may arrive first. The first call creates
//!   the registry entry; the second attaches.
//! * GET may be terminated mid-flight (CDN ~100 s cut-off). The
//!   downlink ring is preserved; the next GET on the same id
//!   resumes from where the previous one stopped.
//! * POST is one packet per request, sequenced by `X-Xhttp-Seq`.
//!   Out-of-order POSTs are stashed until the missing seq arrives —
//!   needed because HTTP/2 stream scheduling and CDN distribution
//!   can reorder concurrent requests.

use std::{
    collections::{BTreeMap, VecDeque},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::resume_headers::ResumeResponseEcho;
use crate::server::resumption::SessionId;

mod duplex;
mod h3;
pub(in crate::server) mod handlers;
mod padding;

#[cfg(test)]
mod tests;

pub(in crate::server) use duplex::XhttpDuplex;
pub(in crate::server) use generate_anonymous_session_id as generate_anonymous_xhttp_session_id;
pub(in crate::server) use h3::{XhttpH3Ctx, handle_xhttp_h3_request};
pub(in crate::server) use handlers::{
    XhttpAppProtocol, XhttpAxumState, XhttpRoute, xhttp_handler, xhttp_handler_no_session,
    xhttp_handler_with_path_seq,
};
pub(in crate::server) use padding::{generate_padding_header, masquerade_response_headers};

// XHTTP wire vocabulary (header names, `?mode=` submode selector) is
// shared with the client and lives in `outline_wire::xhttp`.
pub(in crate::server) use outline_wire::xhttp::{
    FIN_HEADER, PADDING_HEADER, SEQ_HEADER, UDP_RECORDS_ENABLED, UDP_RECORDS_HEADER, XhttpSubmode,
};

/// Soft cap on the bytes the per-session downlink ring may hold.
/// The relay's `push_downlink` parks (awaits) once the ring sits
/// at or above this watermark, propagating the GET consumer's
/// throughput back to the upstream reader through the natural TCP
/// receive window. Sized to a few hundred TCP segments — large
/// enough to absorb burstiness on a healthy connection, small
/// enough that a stuck consumer doesn't pin tens of MiB per idle
/// session. Resumption-safe: the ring keeps holding bytes across
/// a GET reattach, the cap just stops the writer from racing past
/// the reader between attaches.
const DOWNLINK_BUFFER_BYTES_CAP: usize = 256 * 1024;
/// Cap on bytes parked in the uplink reorder buffer. POSTs whose
/// seq is too far ahead of the expected one push us past this cap
/// and are rejected (HTTP 503).
const UPLINK_REORDER_BUFFER_BYTES_CAP: usize = 256 * 1024;
/// Maximum gap between the highest seen seq and the next expected
/// seq before we give up. Bounds memory and prevents a malicious
/// client from forcing unbounded buffering by skipping seq numbers.
const UPLINK_REORDER_MAX_GAP: u64 = 64;
/// Soft cap on the bytes the per-session in-order uplink queue
/// (`UplinkState::ready`) may hold. The downlink half already parks
/// its writer on [`DOWNLINK_BUFFER_BYTES_CAP`] and the reorder buffer
/// is bounded by [`UPLINK_REORDER_BUFFER_BYTES_CAP`]; without this the
/// in-order queue was the one unbounded producer path — a valid client
/// on a slow/stuck upstream keeps the relay from draining `ready`
/// while it POSTs (packet-up) or the stream-up pump keeps vacuuming
/// the h2/h3 flow-control window into it, growing `ready` until OOM
/// (fatal under `panic = abort`). At the cap the producer is throttled
/// so the carrier's own flow control brakes the client: the stream-up
/// pump parks (see [`XhttpSession::ingest_uplink_inorder`]), and a
/// packet-up POST is rejected with HTTP 503 ([`UplinkIngestError::ReadyFull`],
/// idempotent — the seq is not consumed, the client retries). Sized to
/// match the downlink and reorder caps: total resident uplink memory
/// per session stays under `ready` + `reorder` = 512 KiB. Modeled on
/// the byte-budget in `outline_transport::carrier_queue`.
const UPLINK_READY_BYTES_CAP: usize = 256 * 1024;
/// Time a session may sit idle before the registry janitor evicts it (see
/// [`XhttpSession::is_evictable`] for the two ways a session counts as idle).
/// Must stay comfortably above the relay's keepalive cadence
/// (`WS_TCP_KEEPALIVE_PING_INTERVAL_SECS`, 60 s): on an idle-but-live UDP
/// datagram channel the relay's keepalive tick `touch_keepalive()`s the session
/// every 60 s (see `XhttpDuplex::send`), so the eviction window has to tolerate
/// a missed keepalive or two before declaring a live relay dead — otherwise the
/// janitor races the keepalive and tears down quiet-but-healthy UDP sessions
/// (DNS between lookups, an idle QUIC connection), surfacing as a spurious `ws
/// closed` on the client. 180 s = 3× keepalive mirrors the
/// `WS_PONG_DEADLINE_MULTIPLIER` budget while still being generous enough that a
/// CDN reconnect (10–20 s gap while the client picks a new edge) is not yet
/// eviction-eligible. The same window also bounds how long a downlink-stalled
/// session lingers before the `progress`-clock check reaps it despite ongoing
/// keepalives.
pub(in crate::server) const SESSION_IDLE_EVICTION: Duration = Duration::from_secs(180);

/// Process-wide caps for [`XhttpRegistry`]. Sourced from `[tuning]`
/// (`xhttp_max_sessions` / `xhttp_max_sessions_per_ip` /
/// `xhttp_max_concurrent_relay_tasks`); `0` on any field disables that cap.
#[derive(Clone, Copy, Debug)]
pub(in crate::server) struct XhttpRegistryLimits {
    /// Max concurrent sessions the registry may hold; `0` = unbounded.
    pub(in crate::server) max_sessions: usize,
    /// Max concurrent sessions a single source IP may hold, on top of
    /// `max_sessions`; `0` = unbounded (global cap only).
    pub(in crate::server) max_sessions_per_ip: usize,
    /// Max concurrent relay tasks (global semaphore permits); `0` = unbounded.
    pub(in crate::server) max_relay_tasks: usize,
}

impl XhttpRegistryLimits {
    /// No caps — used by tests that do not exercise the bounds.
    #[cfg(test)]
    pub(in crate::server) fn unbounded() -> Self {
        Self {
            max_sessions: 0,
            max_sessions_per_ip: 0,
            max_relay_tasks: 0,
        }
    }
}

/// Outcome of reserving a global relay-task slot before `spawn_relay` spawns
/// the per-session relay task. Mirrors the UDP relay's `relay_semaphore`.
pub(in crate::server) enum RelayPermit {
    /// A slot was reserved. Holds the owned permit (`None` when no global cap
    /// is configured); the caller must keep it alive for the relay task's
    /// lifetime so the semaphore reflects in-flight work.
    Acquired(Option<OwnedSemaphorePermit>),
    /// The global relay-task ceiling is reached; the caller must not spawn.
    AtCapacity,
}

/// Live per-source-IP session count, held by value on the map so the guard
/// released when the last `Arc<XhttpSession>` drops can decrement it without
/// the registry threading the count onto every teardown path.
type PerIpCounts = DashMap<IpAddr, usize>;

/// RAII slot against the per-source-IP session cap. Reserved in
/// [`XhttpRegistry::get_or_create`] and moved into the [`XhttpSession`] it
/// admits, so the count follows the session's own lifetime: dropping the last
/// `Arc<XhttpSession>` (relay-task exit, idle eviction, a seq-gap `close`, any
/// in-flight handler — whichever is last) releases the slot exactly once. This
/// is why the per-IP counter needs no manual decrement on the individual
/// teardown paths.
struct PerIpGuard {
    counts: Arc<PerIpCounts>,
    ip: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        // Decrement under the shard lock, then release it before removing the
        // now-zero entry: `remove_if` re-locks the same shard, so holding the
        // `get_mut` guard across it would deadlock. Removing at zero keeps the
        // map from growing one entry per source IP ever seen.
        let now_zero = match self.counts.get_mut(&self.ip) {
            Some(mut slot) => {
                *slot = slot.saturating_sub(1);
                *slot == 0
            },
            None => false,
        };
        if now_zero {
            self.counts.remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

/// Outcome of [`XhttpRegistry::get_or_create`]: either a session to serve
/// (with `created` telling the caller whether to spawn the relay) or a
/// rejection carrying the low-cardinality metric reason the caller records
/// before answering 503.
pub(in crate::server) enum SessionSlot {
    /// Serve this session; `created` is true for the caller that must spawn the
    /// relay task.
    Ready {
        session: Arc<XhttpSession>,
        created: bool,
    },
    /// A new session was refused by a process-wide cap. Holds the static
    /// `reason` label for `record_xhttp_session_rejected`
    /// (`"max_sessions"` or `"max_sessions_per_ip"`).
    Rejected(&'static str),
}

/// Process-wide store of live XHTTP sessions, keyed by client-
/// chosen opaque id. Cheap to clone (`Arc`).
pub(in crate::server) struct XhttpRegistry {
    sessions: DashMap<Arc<str>, Arc<XhttpSession>>,
    /// Ceiling on concurrent sessions; `0` = unbounded. Enforced only on
    /// creation of a *new* session — an existing id is always served.
    max_sessions: usize,
    /// Per-source-IP ceiling on concurrent sessions; `0` = unbounded. Enforced
    /// on creation only, on top of `max_sessions`.
    max_sessions_per_ip: usize,
    /// Live session count per source IP; empty and unused when the per-IP cap
    /// is disabled. Kept in a separate map from `sessions` so its shard locks
    /// never nest with the session shard locks.
    per_ip: Arc<PerIpCounts>,
    /// Global relay-task semaphore; `None` = unbounded. Reserved in
    /// `spawn_relay` and held for the relay task's lifetime.
    relay_semaphore: Option<Arc<Semaphore>>,
}

impl XhttpRegistry {
    pub(in crate::server) fn with_limits(limits: XhttpRegistryLimits) -> Arc<Self> {
        let relay_semaphore =
            (limits.max_relay_tasks > 0).then(|| Arc::new(Semaphore::new(limits.max_relay_tasks)));
        Arc::new(Self {
            sessions: DashMap::new(),
            max_sessions: limits.max_sessions,
            max_sessions_per_ip: limits.max_sessions_per_ip,
            per_ip: Arc::new(DashMap::new()),
            relay_semaphore,
        })
    }

    /// Reserves a slot against the per-source-IP cap, returning `None` when the
    /// source is already at its share. `Some(None)` means the cap is disabled
    /// (no accounting); `Some(Some(guard))` reserved a slot the caller must
    /// keep alive for the session's lifetime.
    fn reserve_source_slot(&self, ip: IpAddr) -> Option<Option<PerIpGuard>> {
        if self.max_sessions_per_ip == 0 {
            return Some(None);
        }
        // `entry` takes the shard write-lock once; increment in place only when
        // still under the cap. A refused reservation leaves the existing
        // (non-zero) entry untouched — no leak, and the entry is reclaimed by
        // `PerIpGuard::drop` when the source's live sessions reach zero.
        let mut slot = self.per_ip.entry(ip).or_insert(0);
        if *slot >= self.max_sessions_per_ip {
            return None;
        }
        *slot += 1;
        drop(slot);
        Some(Some(PerIpGuard { counts: Arc::clone(&self.per_ip), ip }))
    }

    /// Returns [`SessionSlot::Ready`] with the session and a `created` flag —
    /// the flag tells the caller whether they are the side that should spawn
    /// the relay task. Atomic: two concurrent requests with the same id race
    /// once, the loser sees `created = false` and just attaches.
    ///
    /// Returns [`SessionSlot::Rejected`] when a *new* session is refused by the
    /// global `max_sessions` cap (`"max_sessions"`) or the per-source-IP cap
    /// (`"max_sessions_per_ip"`): the caller rejects with HTTP 503 without
    /// inserting an entry or spawning a task, recording the carried reason. An
    /// already-live id (resume / repeat request) is served regardless of either
    /// cap — the caps gate creation only.
    ///
    /// `source_ip` is the transport peer address, charged against the per-IP
    /// cap for the session's whole lifetime via a guard moved onto the session.
    ///
    /// `issued_resume_id` and `relayed_echo` are the edge decision this request
    /// committed to; both are recorded on the session and read back by every
    /// later request on the same id, which is what keeps an attaching request's
    /// answer identical to the creating one's (see
    /// [`XhttpSession::relayed_echo`]). Both are ignored when the id is already
    /// live — that session's own creator settled them.
    pub(in crate::server) fn get_or_create(
        &self,
        session_id: &str,
        source_ip: IpAddr,
        issued_resume_id: Option<SessionId>,
        relayed_echo: Option<ResumeResponseEcho>,
    ) -> SessionSlot {
        let key: Arc<str> = Arc::from(session_id);
        // Fast path: an existing session is always served, never rejected by
        // the caps. The read guard is released before the `len()` check below.
        if let Some(existing) = self.sessions.get(&key) {
            return SessionSlot::Ready {
                session: Arc::clone(existing.value()),
                created: false,
            };
        }
        // New session: enforce the global cap before taking the shard
        // write-lock in `entry()`. `len()` acquires per-shard read locks, so
        // reading it while holding a shard write-lock could deadlock a
        // concurrent `len()` (mirrors `ReplayStore`). The check/insert race is
        // benign for a soft bound — at most a few racing callers slip past the
        // cap.
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            return SessionSlot::Rejected("max_sessions");
        }
        // Reserve the per-source-IP slot before inserting. Held in `ip_guard`
        // and moved into the session by `or_insert_with` on the creating call;
        // if this call loses the create race, the guard is never taken and
        // dropping it here returns the slot.
        let mut ip_guard = match self.reserve_source_slot(source_ip) {
            Some(guard) => guard,
            None => return SessionSlot::Rejected("max_sessions_per_ip"),
        };
        let mut created = false;
        let session = self
            .sessions
            .entry(Arc::clone(&key))
            .or_insert_with(|| {
                created = true;
                Arc::new(XhttpSession::new(
                    Arc::clone(&key),
                    issued_resume_id,
                    relayed_echo,
                    ip_guard.take(),
                ))
            })
            .value()
            .clone();
        SessionSlot::Ready { session, created }
    }

    /// Reserve a slot against the global relay-task ceiling. `AtCapacity` means
    /// the caller must not spawn a relay (and should reject with 503).
    pub(in crate::server) fn try_acquire_relay_permit(&self) -> RelayPermit {
        match &self.relay_semaphore {
            Some(sem) => match Arc::clone(sem).try_acquire_owned() {
                Ok(permit) => RelayPermit::Acquired(Some(permit)),
                Err(_) => RelayPermit::AtCapacity,
            },
            None => RelayPermit::Acquired(None),
        }
    }

    pub(in crate::server) fn get(&self, session_id: &str) -> Option<Arc<XhttpSession>> {
        let key: Arc<str> = Arc::from(session_id);
        self.sessions.get(&key).map(|entry| Arc::clone(entry.value()))
    }

    pub(in crate::server) fn remove(&self, session_id: &str) {
        let key: Arc<str> = Arc::from(session_id);
        self.sessions.remove(&key);
    }

    /// Sweep idle/closed entries. Cheap to call on a 30 s tick.
    /// Closing on idle (rather than just unmapping) is what wakes
    /// any `push_downlink` waiter that was parked on a full ring
    /// without a GET consumer attached, so the relay task can
    /// finish instead of holding the upstream open indefinitely.
    pub(in crate::server) fn evict_idle(&self) {
        let cutoff = Instant::now() - SESSION_IDLE_EVICTION;
        self.sessions.retain(|_, session| {
            if session.is_closed() {
                return false;
            }
            if session.is_evictable(cutoff) {
                session.close();
                return false;
            }
            true
        });
    }

    /// Returns any one live session in the registry. Tests use this
    /// to reach into a session whose id was randomly chosen by the
    /// client crate (no `X-Xhttp-Fin` plumbing on that side yet) so
    /// they can drive a graceful close via `close_uplink` without
    /// guessing the path id.
    #[cfg(test)]
    pub(in crate::server) fn first_session(&self) -> Option<Arc<XhttpSession>> {
        self.sessions.iter().next().map(|entry| Arc::clone(entry.value()))
    }
}

/// Per-session duplex state. POST/GET handlers and the relay task
/// share an `Arc<XhttpSession>`.
pub(in crate::server) struct XhttpSession {
    pub(in crate::server) id: Arc<str>,
    pub(in crate::server) uplink: Mutex<UplinkState>,
    pub(in crate::server) uplink_notify: Notify,
    /// Wakes any [`ingest_uplink_inorder`](XhttpSession::ingest_uplink_inorder)
    /// task parked because `ready` is at or above [`UPLINK_READY_BYTES_CAP`].
    /// Fired by [`pop_uplink_ready`](XhttpSession::pop_uplink_ready) after the
    /// relay pulls a chunk out of `ready`, and by [`close`](XhttpSession::close)
    /// so a parked producer wakes and observes the closed state. Mirrors
    /// `downlink_drain_notify` for the opposite direction.
    pub(in crate::server) uplink_drain_notify: Notify,
    pub(in crate::server) downlink: Mutex<DownlinkState>,
    pub(in crate::server) downlink_notify: Notify,
    /// Wakes any [`push_downlink`](XhttpSession::push_downlink) task
    /// that is parked because the ring is at or above
    /// [`DOWNLINK_BUFFER_BYTES_CAP`]. Fired by `drain_downlink`
    /// after it pulls bytes out of the ring, and by
    /// [`close`](XhttpSession::close) so a parked writer wakes up
    /// and observes the closed state.
    pub(in crate::server) downlink_drain_notify: Notify,
    closed: AtomicBool,
    /// Last real data movement (uplink ingested/drained, downlink pushed/drained),
    /// as nanos since `created_at`. Bumped by [`Self::touch_progress`] only — the
    /// relay's keepalive tick deliberately does *not* touch it, so a session that
    /// is being kept warm by keepalives while its downlink is stuck (a GET
    /// consumer that never reads) still ages out through `progress`.
    last_progress_nanos: AtomicI64,
    /// Last keepalive tick from the relay ([`Self::touch_keepalive`]), as nanos
    /// since `created_at`. Proves the carrier/relay is alive on an otherwise
    /// quiet channel, but — unlike `progress` — does not by itself spare a
    /// downlink-stalled session from eviction (see [`Self::is_evictable`]).
    last_keepalive_nanos: AtomicI64,
    created_at: Instant,
    /// Charges this session against the per-source-IP cap for its whole
    /// lifetime; the slot is released when the last `Arc<XhttpSession>` drops.
    /// `None` when the per-IP cap is disabled. Never read — only its `Drop`
    /// matters.
    _source_ip_guard: Option<PerIpGuard>,
    /// Server-issued cross-transport resumption id, minted on the
    /// first request that creates the session (when the client
    /// advertised `X-Outline-Resume-Capable` or supplied
    /// `X-Outline-Resume`). Surfaced back to the client in every
    /// GET/POST response on this session, so a reconnect-attach
    /// can pick it up too. `None` when resumption is disabled at
    /// the server or the client did not opt in. Held by value
    /// because `SessionId` is `Copy`.
    pub(in crate::server) issued_resume_id: Option<SessionId>,
    /// The response echo of the mesh relay this session was created over, or
    /// `None` when it is served locally.
    ///
    /// Recorded once, by the request that created the session, because the echo
    /// describes the *session* and not the request that happens to be answering.
    /// A later request on the same id has no relay to ask — `xhttp_edge`
    /// short-circuits on an id that is already live — so re-deriving the echo
    /// from that request's own headers would answer with this node's local
    /// resumption policy. That answer is wrong in one way that breaks the
    /// client: it confirms v2 Symmetric Downlink Replay, which no relayed
    /// session can honour (the home's replay suffix crosses the mesh as
    /// undelimited plaintext, so there is no `ORDR` frame to hand on), and a
    /// client that latches v2 parses the suffix as a frame header and drops the
    /// session. Held by value — [`ResumeResponseEcho`] is `Copy`.
    pub(in crate::server) relayed_echo: Option<ResumeResponseEcho>,
    /// Datagram record framing negotiated for this session (see
    /// [`outline_wire::udp_records`]). Latched by whichever request first
    /// arrives on an SS-UDP path carrying `X-Outline-Udp-Records: 1` — GET and
    /// POST can arrive in either order, so it is not fixed at creation — then
    /// read back by every handler to echo the capability and by `spawn_relay`
    /// to build the duplex. Never set on a TCP / VLESS path, so those wires
    /// stay byte-for-byte as they were.
    udp_records: AtomicBool,
}

pub(in crate::server) struct UplinkState {
    pub(in crate::server) expected_seq: u64,
    pub(in crate::server) ready: VecDeque<Bytes>,
    /// Bytes currently resident in `ready`, kept in step with pushes and
    /// [`pop_uplink_ready`](XhttpSession::pop_uplink_ready) so the byte cap
    /// ([`UPLINK_READY_BYTES_CAP`]) can be enforced without walking the deque.
    pub(in crate::server) ready_bytes: usize,
    pub(in crate::server) reorder: BTreeMap<u64, Bytes>,
    pub(in crate::server) reorder_bytes: usize,
    pub(in crate::server) closed: bool,
}

pub(in crate::server) struct DownlinkState {
    pub(in crate::server) pending: VecDeque<Bytes>,
    pub(in crate::server) pending_bytes: usize,
    pub(in crate::server) closed: bool,
    pub(in crate::server) get_attached: bool,
}

impl XhttpSession {
    fn new(
        id: Arc<str>,
        issued_resume_id: Option<SessionId>,
        relayed_echo: Option<ResumeResponseEcho>,
        source_ip_guard: Option<PerIpGuard>,
    ) -> Self {
        Self {
            id,
            uplink: Mutex::new(UplinkState {
                expected_seq: 0,
                ready: VecDeque::new(),
                ready_bytes: 0,
                reorder: BTreeMap::new(),
                reorder_bytes: 0,
                closed: false,
            }),
            uplink_notify: Notify::new(),
            uplink_drain_notify: Notify::new(),
            downlink: Mutex::new(DownlinkState {
                pending: VecDeque::new(),
                pending_bytes: 0,
                closed: false,
                get_attached: false,
            }),
            downlink_notify: Notify::new(),
            downlink_drain_notify: Notify::new(),
            closed: AtomicBool::new(false),
            last_progress_nanos: AtomicI64::new(0),
            last_keepalive_nanos: AtomicI64::new(0),
            created_at: Instant::now(),
            _source_ip_guard: source_ip_guard,
            issued_resume_id,
            relayed_echo,
            udp_records: AtomicBool::new(false),
        }
    }

    /// Latches datagram record framing for this session. Called by the request
    /// handlers when an SS-UDP path sees the client capability header; the
    /// relay reads it back through [`Self::udp_records`]. Idempotent, and only
    /// ever moves `false → true` — a later request that omits the header does
    /// not un-negotiate a session already framing its wire.
    pub(in crate::server) fn enable_udp_records(&self) {
        self.udp_records.store(true, Ordering::Release);
    }

    /// Whether this session frames datagrams as length-prefixed records.
    pub(in crate::server) fn udp_records(&self) -> bool {
        self.udp_records.load(Ordering::Acquire)
    }

    /// Records real data movement — uplink ingested/drained, downlink
    /// pushed/drained. This is the clock the idle-eviction backstop ages a
    /// stalled session against; the keepalive tick must *not* call it.
    fn touch_progress(&self) {
        self.stamp(&self.last_progress_nanos);
    }

    /// Records a relay keepalive tick. Keeps a genuinely quiet-but-live session
    /// (an idle UDP datagram channel, a quiet QUIC connection) off the eviction
    /// backstop, without refreshing the `progress` clock — so a downlink-stalled
    /// session that only *looks* alive through keepalives still ages out.
    pub(in crate::server) fn touch_keepalive(&self) {
        self.stamp(&self.last_keepalive_nanos);
    }

    fn stamp(&self, field: &AtomicI64) {
        let elapsed = self.created_at.elapsed().as_nanos();
        let stamp = i64::try_from(elapsed).unwrap_or(i64::MAX);
        field.store(stamp, Ordering::Relaxed);
    }

    fn instant_of(&self, field: &AtomicI64) -> Instant {
        let elapsed = field.load(Ordering::Relaxed).max(0) as u64;
        self.created_at + Duration::from_nanos(elapsed)
    }

    fn downlink_pending_bytes(&self) -> usize {
        self.downlink.lock().pending_bytes
    }

    /// Whether the registry janitor should evict this session at `cutoff`
    /// (= `now - SESSION_IDLE_EVICTION`).
    ///
    /// Two independent reasons, either sufficient:
    /// * **Downlink-stalled.** Bytes are queued for a GET consumer that has not
    ///   drained any within the window (`progress` older than `cutoff`). This
    ///   fires even while the relay's keepalive keeps ticking — the whole point,
    ///   since a stuck downlink (a client that attaches a GET but never reads)
    ///   otherwise looks alive forever through keepalives and pins its ring
    ///   until the process dies.
    /// * **Fully idle.** Neither real progress nor a keepalive landed within the
    ///   window. This preserves the historical behaviour for an abandoned,
    ///   empty session; a healthy quiet session stays alive because its
    ///   keepalive keeps `keepalive` fresh and it has nothing pending.
    pub(in crate::server) fn is_evictable(&self, cutoff: Instant) -> bool {
        let progress = self.instant_of(&self.last_progress_nanos);
        if self.downlink_pending_bytes() > 0 && progress < cutoff {
            return true;
        }
        let keepalive = self.instant_of(&self.last_keepalive_nanos);
        progress.max(keepalive) < cutoff
    }

    /// Marks the session torn down. Idempotent. Wakes every notifier
    /// so any pending POST/GET handler, the relay task, and any parked
    /// `push_downlink` / `ingest_uplink_inorder` waiter observe the
    /// close and exit.
    pub(in crate::server) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.uplink.lock().closed = true;
            self.downlink.lock().closed = true;
            self.uplink_notify.notify_waiters();
            self.uplink_drain_notify.notify_waiters();
            self.downlink_notify.notify_waiters();
            self.downlink_drain_notify.notify_waiters();
        }
    }

    pub(in crate::server) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// POST handler: enqueue an inbound packet at `seq`. Idempotent
    /// against replays of already-consumed seqs (CDNs occasionally
    /// retry POSTs on transport errors).
    pub(in crate::server) fn ingest_uplink(
        &self,
        seq: u64,
        data: Bytes,
    ) -> Result<(), UplinkIngestError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.uplink.lock();
        if state.closed {
            return Err(UplinkIngestError::Closed);
        }
        if seq < state.expected_seq {
            return Ok(());
        }
        if seq == state.expected_seq {
            // Refuse to grow `ready` past its byte cap: a stuck relay that
            // stopped draining must not let a client keep enqueuing in-order
            // packets unbounded. Rejecting is idempotent — `expected_seq` is
            // not advanced, so the client retries the same seq once the relay
            // frees room (HTTP 503, mirroring the reorder `BufferFull` path).
            // The very first frame is always admitted (`ready` empty) so a
            // frame larger than the whole cap cannot wedge the session.
            if !state.ready.is_empty()
                && state.ready_bytes.saturating_add(data.len()) > UPLINK_READY_BYTES_CAP
            {
                return Err(UplinkIngestError::ReadyFull);
            }
            state.ready_bytes = state.ready_bytes.saturating_add(data.len());
            state.ready.push_back(data);
            state.expected_seq = state.expected_seq.saturating_add(1);
            loop {
                let key = state.expected_seq;
                // Peek the next in-order frame's length before removing it: only
                // promote it into `ready` if there is room. Otherwise leave it
                // parked in `reorder` (separately bounded) so the in-order queue
                // stays under its byte cap.
                let Some(next_len) = state.reorder.get(&key).map(Bytes::len) else { break };
                if state.ready_bytes.saturating_add(next_len) > UPLINK_READY_BYTES_CAP {
                    break;
                }
                let next = state.reorder.remove(&key).expect("checked present above");
                state.reorder_bytes = state.reorder_bytes.saturating_sub(next_len);
                state.ready_bytes = state.ready_bytes.saturating_add(next_len);
                state.ready.push_back(next);
                state.expected_seq = state.expected_seq.saturating_add(1);
            }
            drop(state);
            self.uplink_notify.notify_waiters();
            self.touch_progress();
            return Ok(());
        }
        let gap = seq - state.expected_seq;
        if gap > UPLINK_REORDER_MAX_GAP {
            return Err(UplinkIngestError::GapTooLarge { expected: state.expected_seq, got: seq });
        }
        if state.reorder_bytes.saturating_add(data.len()) > UPLINK_REORDER_BUFFER_BYTES_CAP {
            return Err(UplinkIngestError::BufferFull);
        }
        let len = data.len();
        if state.reorder.insert(seq, data).is_none() {
            state.reorder_bytes = state.reorder_bytes.saturating_add(len);
        }
        drop(state);
        self.touch_progress();
        Ok(())
    }

    /// Marks the uplink half closed (e.g. client sent FIN). Relay
    /// sees `uplink_eof()` once the in-order queue drains.
    pub(in crate::server) fn close_uplink(&self) {
        self.uplink.lock().closed = true;
        self.uplink_notify.notify_waiters();
    }

    /// Stream-one / stream-up variant of [`Self::ingest_uplink`]: the
    /// carrier is a single long-lived request, so chunks are already in
    /// order and never need the seq/reorder dance — push them straight
    /// into the ready queue. Used by the server-side stream-one / stream-up
    /// pump (`handlers`/`h3`), which vacuums the request body frame by frame.
    ///
    /// Awaits when `ready` is at or above [`UPLINK_READY_BYTES_CAP`] until
    /// either (a) [`Self::pop_uplink_ready`] frees room, or (b) the session
    /// closes (returns `Closed`). Parking the pump here is the whole point:
    /// it stops the pump from reading further body frames, so the h2/h3
    /// flow-control window stops draining and the client is throttled at the
    /// carrier instead of `ready` growing without bound. Mirrors
    /// [`Self::push_downlink`] for the opposite direction. The first frame is
    /// always admitted (`ready` empty) so a frame larger than the whole cap
    /// cannot wedge the session.
    pub(in crate::server) async fn ingest_uplink_inorder(
        &self,
        data: Bytes,
    ) -> Result<(), UplinkIngestError> {
        if data.is_empty() {
            return Ok(());
        }
        let len = data.len();
        let mut data = Some(data);
        loop {
            // Subscribe before checking so a drain between the room-check and
            // the await cannot lose its wake-up (same guard as `push_downlink`).
            let notified = self.uplink_drain_notify.notified();
            {
                let mut state = self.uplink.lock();
                if state.closed {
                    return Err(UplinkIngestError::Closed);
                }
                if state.ready.is_empty()
                    || state.ready_bytes.saturating_add(len) <= UPLINK_READY_BYTES_CAP
                {
                    let bytes = data.take().expect("ingest_uplink_inorder: data taken twice");
                    state.ready_bytes = state.ready_bytes.saturating_add(len);
                    state.ready.push_back(bytes);
                    // expected_seq stays 0 forever — packet-up reorder is not
                    // exercised on this carrier, but keeping the field around
                    // means a session that was created in stream-one mode does
                    // not reject seq=0 packets if anything ever bridges across.
                    drop(state);
                    self.uplink_notify.notify_waiters();
                    self.touch_progress();
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    pub(in crate::server) fn pop_uplink_ready(&self) -> Option<Bytes> {
        let mut state = self.uplink.lock();
        let chunk = state.ready.pop_front()?;
        state.ready_bytes = state.ready_bytes.saturating_sub(chunk.len());
        drop(state);
        // The relay is the only reader, so one permit suffices; `notify_one`
        // stores a permit when no producer is parked yet, so a push that
        // arrives between drain and its own subscribe still wakes up.
        self.uplink_drain_notify.notify_one();
        Some(chunk)
    }

    pub(in crate::server) fn uplink_eof(&self) -> bool {
        let state = self.uplink.lock();
        state.closed && state.ready.is_empty()
    }

    /// Atomically claims the GET slot. Returns `false` if another
    /// GET is already attached or the session is torn down — the
    /// caller should respond 409 in the first case, 410 in the
    /// second. The two situations rarely matter to clients in
    /// practice, but the distinction keeps debugging sane.
    pub(in crate::server) fn try_attach_get(&self) -> AttachOutcome {
        let mut state = self.downlink.lock();
        if state.closed {
            return AttachOutcome::Gone;
        }
        if state.get_attached {
            return AttachOutcome::Conflict;
        }
        state.get_attached = true;
        AttachOutcome::Ok
    }

    pub(in crate::server) fn detach_get(&self) {
        self.downlink.lock().get_attached = false;
    }

    /// Drains all pending downlink chunks into `dst`. Returns
    /// `true` once the session is closed (so the GET handler ends
    /// the response body after writing). Wakes any `push_downlink`
    /// waiter that was parked on the ring being full so it can
    /// retry now that bytes have been freed.
    pub(in crate::server) fn drain_downlink(&self, dst: &mut Vec<Bytes>) -> bool {
        let mut state = self.downlink.lock();
        let drained_any = !state.pending.is_empty();
        while let Some(chunk) = state.pending.pop_front() {
            state.pending_bytes = state.pending_bytes.saturating_sub(chunk.len());
            dst.push(chunk);
        }
        let closed = state.closed;
        drop(state);
        if !dst.is_empty() {
            self.touch_progress();
        }
        if drained_any {
            // The relay is the only writer (one VLESS pipe per XHTTP
            // session, even when VLESS-mux multiplexes sub-conns above
            // it), so a single permit is sufficient. `notify_one`
            // stores a permit if no waiter is parked yet, so a push
            // that arrives between drain and its own subscribe still
            // wakes up.
            self.downlink_drain_notify.notify_one();
        }
        closed
    }

    /// Relay-side enqueue. Awaits if the ring is at or above the
    /// soft cap until either (a) `drain_downlink` pulls bytes out
    /// and frees room, or (b) the session is closed. Returns
    /// `Closed` only on case (b); the caller can treat any other
    /// outcome as a successful enqueue.
    ///
    /// Blocking the relay here is intentional: it lets the GET
    /// consumer's pace propagate back through the upstream TCP
    /// receive window instead of pinning ever more pending bytes
    /// in memory. VLESS-mux sub-conns share one ring, so a slow
    /// downlink does throttle the whole pipe — that is strictly
    /// better than the previous behaviour of severing the session
    /// (which killed every sub-conn at once).
    pub(in crate::server) async fn push_downlink(
        &self,
        data: Bytes,
    ) -> Result<(), DownlinkPushError> {
        if data.is_empty() {
            return Ok(());
        }
        let len = data.len();
        let mut data = Some(data);
        loop {
            // Subscribe before checking so a drain that happens between
            // the room-check and the await cannot lose its wake-up.
            let notified = self.downlink_drain_notify.notified();
            {
                let mut state = self.downlink.lock();
                if state.closed {
                    return Err(DownlinkPushError::Closed);
                }
                if state.pending_bytes.saturating_add(len) <= DOWNLINK_BUFFER_BYTES_CAP {
                    let bytes = data.take().expect("push_downlink: data taken twice");
                    state.pending.push_back(bytes);
                    state.pending_bytes = state.pending_bytes.saturating_add(len);
                    drop(state);
                    self.downlink_notify.notify_one();
                    self.touch_progress();
                    return Ok(());
                }
            }
            notified.await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum AttachOutcome {
    /// The GET slot is now claimed by the caller.
    Ok,
    /// Another GET is already streaming the downlink for this id.
    Conflict,
    /// The session has already been torn down.
    Gone,
}

#[derive(Debug)]
pub(in crate::server) enum UplinkIngestError {
    Closed,
    GapTooLarge {
        expected: u64,
        got: u64,
    },
    /// The reorder buffer is full (a too-far-ahead seq would push it past
    /// [`UPLINK_REORDER_BUFFER_BYTES_CAP`]).
    BufferFull,
    /// The in-order `ready` queue is full (an in-order packet would push it
    /// past [`UPLINK_READY_BYTES_CAP`]): the relay is not draining fast enough.
    /// Non-fatal and idempotent — the seq is not consumed, so the client
    /// retries once room frees. Answered with HTTP 503, like [`Self::BufferFull`].
    ReadyFull,
}

#[derive(Debug)]
pub(in crate::server) enum DownlinkPushError {
    Closed,
}

/// URL-captured `{id}` sanity check shared between the axum
/// (h1/h2) and h3 entry points. Path captures already reject
/// `/`, `?`, `#`; the shared rule further bounds the length and
/// restricts to URL-safe alphanumeric so that a hostile blob cannot
/// evade log redaction. The id is opaque to the server otherwise.
pub(in crate::server) use outline_wire::xhttp::is_valid_session_id;

/// 16-byte URL-safe alphanumeric session id, generated server-side
/// for xray-style stream-one carriers that hit `<base>` (or
/// `<base>/`) without a client-supplied id. Each stream-one POST is
/// its own self-contained session — there is no second request that
/// needs to attach to the same registry slot — so a fresh random id
/// per request is exactly what the registry expects. Length is the
/// same order as the client-supplied ids, so log redaction patterns
/// keep working uniformly.
pub(in crate::server) fn generate_anonymous_session_id() -> String {
    use outline_wire::xhttp::SESSION_ID_ALPHABET as ALPHABET;
    use ring::rand::{SecureRandom, SystemRandom};
    let mut raw = [0_u8; 16];
    // Best-effort RNG: if the platform RNG fails (extremely unlikely
    // outside of test mocks) we still need a non-empty, unique-ish
    // id. Salt the timestamp into the alphabet so two callers in the
    // same nanosecond don't necessarily collide.
    if SystemRandom::new().fill(&mut raw).is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = (now >> (i * 4)) as u8;
        }
    }
    raw.iter()
        .map(|b| char::from(ALPHABET[(*b as usize) % ALPHABET.len()]))
        .collect()
}
