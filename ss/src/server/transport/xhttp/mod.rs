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
use tokio::sync::Notify;

use crate::server::resumption::SessionId;

mod duplex;
mod h3;
pub(in crate::server) mod handlers;
mod padding;

pub(in crate::server) use duplex::XhttpDuplex;
pub(in crate::server) use h3::handle_xhttp_h3_request;
pub(in crate::server) use handlers::{
    XhttpAxumState, xhttp_handler, xhttp_handler_no_session, xhttp_handler_with_path_seq,
};
pub(in crate::server) use generate_anonymous_session_id as generate_anonymous_xhttp_session_id;
pub(in crate::server) use padding::{generate_padding_header, masquerade_response_headers};

/// HTTP request header carrying the in-order seq number for an
/// uplink POST. Lower-cased to match hyper's normalised headers.
pub(in crate::server) const SEQ_HEADER: &str = "x-xhttp-seq";

/// Submode selector. Picked from the request URL's query string
/// via `?mode=...`. Absent / unknown values fall back to packet-up,
/// keeping pre-existing clients on the working path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum XhttpSubmode {
    /// Default. Long-lived GET (downlink) + sequenced POSTs (uplink).
    PacketUp,
    /// Single bidirectional request: request body = uplink, response
    /// body = downlink. Requires h2 or h3 (h1 cannot full-duplex).
    StreamOne,
}

impl XhttpSubmode {
    /// Parses `?mode=...` out of the URL query string. Accepts both
    /// dashed (`stream-one`) and underscored (`stream_one`) spellings
    /// because xray uses the dashed form on the wire while sing-box
    /// configs sometimes carry the underscored one.
    pub(in crate::server) fn parse(query: Option<&str>) -> Self {
        let Some(q) = query else {
            return Self::PacketUp;
        };
        for pair in q.split('&') {
            if let Some(value) = pair.strip_prefix("mode=") {
                return match value {
                    "stream-one" | "stream_one" => Self::StreamOne,
                    _ => Self::PacketUp,
                };
            }
        }
        Self::PacketUp
    }
}
/// HTTP request/response header for a `Sec-WebSocket-Key`-style
/// random padding. Server emits one with each response, server
/// accepts and ignores any client-emitted value.
pub(in crate::server) const PADDING_HEADER: &str = "x-padding";
/// Hint header sent on the final POST of a session so the server
/// can collapse the uplink without waiting for an idle timeout.
/// Optional — its absence does not change correctness.
pub(in crate::server) const FIN_HEADER: &str = "x-xhttp-fin";

/// Cap on the bytes the per-session downlink ring may hold while
/// no GET consumer is attached. Sized so a couple of hundred TCP
/// segments fit (BDP for a typical mobile link) without making
/// each idle session expensive. When exceeded the relay sees a
/// backpressure error and tears the session down — the alternative
/// (blocking the relay) would let one stuck client stall the
/// whole connection.
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
/// evicts it. Generous enough that a CDN reconnect (10–20 s gap
/// while the client picks a new edge) is not yet eviction-eligible.
pub(in crate::server) const SESSION_IDLE_EVICTION: Duration = Duration::from_secs(60);

/// Process-wide store of live XHTTP sessions, keyed by client-
/// chosen opaque id. Cheap to clone (`Arc`).
#[derive(Default)]
pub(in crate::server) struct XhttpRegistry {
    sessions: DashMap<Arc<str>, Arc<XhttpSession>>,
}

impl XhttpRegistry {
    pub(in crate::server) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns `(session, created)` — the bool tells the caller
    /// whether they are the side that should spawn the relay task.
    /// Atomic: two concurrent requests with the same id race once,
    /// the loser sees `created = false` and just attaches.
    pub(in crate::server) fn get_or_create(
        &self,
        session_id: &str,
        data_channel_capacity: usize,
        issued_resume_id: Option<SessionId>,
    ) -> (Arc<XhttpSession>, bool) {
        let key: Arc<str> = Arc::from(session_id);
        let mut created = false;
        let session = self
            .sessions
            .entry(Arc::clone(&key))
            .or_insert_with(|| {
                created = true;
                Arc::new(XhttpSession::new(
                    Arc::clone(&key),
                    data_channel_capacity,
                    issued_resume_id,
                ))
            })
            .value()
            .clone();
        (session, created)
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
    pub(in crate::server) fn evict_idle(&self) {
        let cutoff = Instant::now() - SESSION_IDLE_EVICTION;
        self.sessions.retain(|_, session| {
            if session.is_closed() {
                return false;
            }
            !session.is_idle_since(cutoff)
        });
    }

    #[cfg(test)]
    pub(in crate::server) fn len(&self) -> usize {
        self.sessions.len()
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
    closed: AtomicBool,
    last_activity_nanos: AtomicI64,
    created_at: Instant,
    pub(in crate::server) data_channel_capacity: usize,
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
    fn new(
        id: Arc<str>,
        data_channel_capacity: usize,
        issued_resume_id: Option<SessionId>,
    ) -> Self {
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
            closed: AtomicBool::new(false),
            last_activity_nanos: AtomicI64::new(0),
            created_at: Instant::now(),
            data_channel_capacity,
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

    /// Marks the session torn down. Idempotent. Wakes both notifiers
    /// so any pending POST/GET handler and the relay task observe
    /// the close and exit.
    pub(in crate::server) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.uplink.lock().closed = true;
            self.downlink.lock().closed = true;
            self.uplink_notify.notify_waiters();
            self.downlink_notify.notify_waiters();
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
            return Err(UplinkIngestError::GapTooLarge {
                expected: state.expected_seq,
                got: seq,
            });
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
    /// the response body after writing). The caller must release
    /// the held lock by virtue of this method returning, and is
    /// expected to follow up with an HTTP write.
    pub(in crate::server) fn drain_downlink(&self, dst: &mut Vec<Bytes>) -> bool {
        let mut state = self.downlink.lock();
        while let Some(chunk) = state.pending.pop_front() {
            state.pending_bytes = state.pending_bytes.saturating_sub(chunk.len());
            dst.push(chunk);
        }
        let closed = state.closed;
        drop(state);
        if !dst.is_empty() {
            self.touch();
        }
        closed
    }

    /// Relay-side enqueue. Returns `Backpressure` when the ring is
    /// over budget — the caller (relay) should treat this as a
    /// fatal error for the session, since blocking the relay would
    /// stall every other multiplexed VLESS sub-conn on the same
    /// session.
    pub(in crate::server) fn push_downlink(&self, data: Bytes) -> Result<(), DownlinkPushError> {
        if data.is_empty() {
            return Ok(());
        }
        let len = data.len();
        let mut state = self.downlink.lock();
        if state.closed {
            return Err(DownlinkPushError::Closed);
        }
        if state.pending_bytes.saturating_add(len) > DOWNLINK_BUFFER_BYTES_CAP {
            return Err(DownlinkPushError::Backpressure);
        }
        state.pending.push_back(data);
        state.pending_bytes = state.pending_bytes.saturating_add(len);
        drop(state);
        self.downlink_notify.notify_one();
        self.touch();
        Ok(())
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
    Backpressure,
}

/// URL-captured `{id}` sanity check shared between the axum
/// (h1/h2) and h3 entry points. Path captures already reject
/// `/`, `?`, `#`; we further bound the length and restrict to
/// URL-safe alphanumeric so that a hostile blob cannot evade
/// log redaction. The id is opaque to the server otherwise.
pub(in crate::server) fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// 16-byte URL-safe alphanumeric session id, generated server-side
/// for xray-style stream-one carriers that hit `<base>` (or
/// `<base>/`) without a client-supplied id. Each stream-one POST is
/// its own self-contained session — there is no second request that
/// needs to attach to the same registry slot — so a fresh random id
/// per request is exactly what the registry expects. Length is the
/// same order as the client-supplied ids, so log redaction patterns
/// keep working uniformly.
pub(in crate::server) fn generate_anonymous_session_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    const ALPHABET: &[u8; 62] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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
    raw.iter().map(|b| char::from(ALPHABET[(*b as usize) % ALPHABET.len()])).collect()
}

