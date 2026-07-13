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
    FIN_HEADER, PADDING_HEADER, SEQ_HEADER, XhttpSubmode,
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
/// Time a session may sit with no I/O before the registry janitor
/// evicts it. Must stay comfortably above the relay's keepalive
/// cadence (`WS_TCP_KEEPALIVE_PING_INTERVAL_SECS`, 60 s): on an
/// idle-but-live UDP datagram channel the relay's keepalive tick
/// `touch()`es the session every 60 s (see `XhttpDuplex::send`), so
/// the eviction window has to tolerate a missed keepalive or two
/// before declaring a live relay dead — otherwise the janitor races
/// the keepalive and tears down quiet-but-healthy UDP sessions (DNS
/// between lookups, an idle QUIC connection), surfacing as a
/// spurious `ws closed` on the client. 180 s = 3× keepalive mirrors
/// the `WS_PONG_DEADLINE_MULTIPLIER` budget while still being
/// generous enough that a CDN reconnect (10–20 s gap while the
/// client picks a new edge) is not yet eviction-eligible.
pub(in crate::server) const SESSION_IDLE_EVICTION: Duration = Duration::from_secs(180);

/// Process-wide caps for [`XhttpRegistry`]. Sourced from `[tuning]`
/// (`xhttp_max_sessions` / `xhttp_max_concurrent_relay_tasks`); `0` on either
/// field disables that cap.
#[derive(Clone, Copy, Debug)]
pub(in crate::server) struct XhttpRegistryLimits {
    /// Max concurrent sessions the registry may hold; `0` = unbounded.
    pub(in crate::server) max_sessions: usize,
    /// Max concurrent relay tasks (global semaphore permits); `0` = unbounded.
    pub(in crate::server) max_relay_tasks: usize,
}

impl XhttpRegistryLimits {
    /// No caps — used by tests that do not exercise the bounds.
    #[cfg(test)]
    pub(in crate::server) fn unbounded() -> Self {
        Self { max_sessions: 0, max_relay_tasks: 0 }
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

/// Process-wide store of live XHTTP sessions, keyed by client-
/// chosen opaque id. Cheap to clone (`Arc`).
///
// TODO(bounded): add an optional per-source-IP session cap so a single peer
// cannot consume the whole `max_sessions` budget. Deferred because a session's
// source IP would have to be threaded onto `XhttpSession` and the per-IP
// counter decremented on *every* teardown path (relay-task exit, idle
// eviction's `retain`, the seq-gap `close`), which is easy to leak; the global
// `max_sessions` cap plus the relay-task semaphore already bound the aggregate
// footprint, so per-IP fairness is a separate, self-contained follow-up.
pub(in crate::server) struct XhttpRegistry {
    sessions: DashMap<Arc<str>, Arc<XhttpSession>>,
    /// Ceiling on concurrent sessions; `0` = unbounded. Enforced only on
    /// creation of a *new* session — an existing id is always served.
    max_sessions: usize,
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
            relay_semaphore,
        })
    }

    /// Returns `Some((session, created))` — the bool tells the caller
    /// whether they are the side that should spawn the relay task.
    /// Atomic: two concurrent requests with the same id race once,
    /// the loser sees `created = false` and just attaches.
    ///
    /// Returns `None` when the registry is at `max_sessions` and the id is not
    /// already live: the caller rejects with HTTP 503 without inserting an
    /// entry or spawning a task. An already-live id (resume / repeat request)
    /// is served regardless of the cap — the cap gates creation only.
    pub(in crate::server) fn get_or_create(
        &self,
        session_id: &str,
        issued_resume_id: Option<SessionId>,
    ) -> Option<(Arc<XhttpSession>, bool)> {
        let key: Arc<str> = Arc::from(session_id);
        // Fast path: an existing session is always served, never rejected by
        // the cap. The read guard is released before the `len()` check below.
        if let Some(existing) = self.sessions.get(&key) {
            return Some((Arc::clone(existing.value()), false));
        }
        // New session: enforce the cap before taking the shard write-lock in
        // `entry()`. `len()` acquires per-shard read locks, so reading it while
        // holding a shard write-lock could deadlock a concurrent `len()`
        // (mirrors `ReplayStore`). The check/insert race is benign for a soft
        // bound — at most a few racing callers slip past the cap.
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            return None;
        }
        let mut created = false;
        let session = self
            .sessions
            .entry(Arc::clone(&key))
            .or_insert_with(|| {
                created = true;
                Arc::new(XhttpSession::new(Arc::clone(&key), issued_resume_id))
            })
            .value()
            .clone();
        Some((session, created))
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
            if session.is_idle_since(cutoff) {
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
    last_activity_nanos: AtomicI64,
    created_at: Instant,
    /// Server-issued cross-transport resumption id, minted on the
    /// first request that creates the session (when the client
    /// advertised `X-Outline-Resume-Capable` or supplied
    /// `X-Outline-Resume`). Surfaced back to the client in every
    /// GET/POST response on this session, so a reconnect-attach
    /// can pick it up too. `None` when resumption is disabled at
    /// the server or the client did not opt in. Held by value
    /// because `SessionId` is `Copy`.
    pub(in crate::server) issued_resume_id: Option<SessionId>,
}

pub(in crate::server) struct UplinkState {
    pub(in crate::server) expected_seq: u64,
    pub(in crate::server) ready: VecDeque<Bytes>,
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
    fn new(id: Arc<str>, issued_resume_id: Option<SessionId>) -> Self {
        Self {
            id,
            uplink: Mutex::new(UplinkState {
                expected_seq: 0,
                ready: VecDeque::new(),
                reorder: BTreeMap::new(),
                reorder_bytes: 0,
                closed: false,
            }),
            uplink_notify: Notify::new(),
            downlink: Mutex::new(DownlinkState {
                pending: VecDeque::new(),
                pending_bytes: 0,
                closed: false,
                get_attached: false,
            }),
            downlink_notify: Notify::new(),
            downlink_drain_notify: Notify::new(),
            closed: AtomicBool::new(false),
            last_activity_nanos: AtomicI64::new(0),
            created_at: Instant::now(),
            issued_resume_id,
        }
    }

    pub(in crate::server) fn touch(&self) {
        let elapsed = self.created_at.elapsed().as_nanos();
        let stamp = i64::try_from(elapsed).unwrap_or(i64::MAX);
        self.last_activity_nanos.store(stamp, Ordering::Relaxed);
    }

    pub(in crate::server) fn is_idle_since(&self, cutoff: Instant) -> bool {
        let elapsed = self.last_activity_nanos.load(Ordering::Relaxed).max(0) as u64;
        let last = self.created_at + Duration::from_nanos(elapsed);
        last < cutoff
    }

    /// Marks the session torn down. Idempotent. Wakes every notifier
    /// so any pending POST/GET handler, the relay task, and any
    /// `push_downlink` waiter observe the close and exit.
    pub(in crate::server) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.uplink.lock().closed = true;
            self.downlink.lock().closed = true;
            self.uplink_notify.notify_waiters();
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
            state.ready.push_back(data);
            state.expected_seq = state.expected_seq.saturating_add(1);
            loop {
                let key = state.expected_seq;
                let Some(next) = state.reorder.remove(&key) else { break };
                state.reorder_bytes = state.reorder_bytes.saturating_sub(next.len());
                state.ready.push_back(next);
                state.expected_seq = state.expected_seq.saturating_add(1);
            }
            drop(state);
            self.uplink_notify.notify_waiters();
            self.touch();
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
        self.touch();
        Ok(())
    }

    /// Marks the uplink half closed (e.g. client sent FIN). Relay
    /// sees `uplink_eof()` once the in-order queue drains.
    pub(in crate::server) fn close_uplink(&self) {
        self.uplink.lock().closed = true;
        self.uplink_notify.notify_waiters();
    }

    /// Stream-one variant of [`Self::ingest_uplink`]: the carrier
    /// is a single bidirectional request, so chunks are already in
    /// order and never need the seq/reorder dance — push them
    /// straight into the ready queue. Used by the server-side
    /// stream-one handler (selected by `?mode=stream-one`).
    pub(in crate::server) fn ingest_uplink_inorder(
        &self,
        data: Bytes,
    ) -> Result<(), UplinkIngestError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.uplink.lock();
        if state.closed {
            return Err(UplinkIngestError::Closed);
        }
        state.ready.push_back(data);
        // expected_seq stays 0 forever — packet-up reorder is not
        // exercised on this carrier, but keeping the field around
        // means a session that was created in stream-one mode does
        // not reject seq=0 packets if anything ever bridges across.
        drop(state);
        self.uplink_notify.notify_waiters();
        self.touch();
        Ok(())
    }

    pub(in crate::server) fn pop_uplink_ready(&self) -> Option<Bytes> {
        self.uplink.lock().ready.pop_front()
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
            self.touch();
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
                    self.touch();
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
    GapTooLarge { expected: u64, got: u64 },
    BufferFull,
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
