//! Cross-transport session resumption — client side.
//!
//! Mirrors the server-side spec at `docs/SESSION-RESUMPTION.md` in the
//! outline-ss-rust repository. The client mints nothing on its own —
//! Session IDs are **server-issued**: the server returns one in the
//! `X-Outline-Session` response header on a successful WebSocket
//! Upgrade, the client stores it, and on the next reconnect (possibly
//! over a different transport) presents it back via `X-Outline-Resume`.
//! On a hit the upstream `TcpStream` is reattached without reopening
//! the connection to the destination.
//!
//! This module is intentionally kept small: only the `SessionId`
//! newtype and the wire constants. Higher-level plumbing (per-uplink
//! cache, retry semantics) lives in `outline-uplink`.
//!
//! See also the lifecycle table in the server spec — this client only
//! ever surfaces `Resume-Capable: 1` (no ID yet) or
//! `Resume: <hex>` (resume request); negotiation of the response side
//! is read straight off the upgrade response.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::OnceLock;

use parking_lot::Mutex;

/// Server-minted opaque token identifying a resumable session.
///
/// Emitted by the server in the `X-Outline-Session` response header
/// (and, eventually, in the VLESS Addons `SESSION_ID` opcode for the
/// raw-QUIC path). The client treats it as an opaque 16-byte value;
/// any ordering or structure is the server's concern. Kept `Copy` so
/// callers can stash it in `Arc<Mutex<Option<SessionId>>>` without
/// fighting borrow checker over clones.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Length, in characters, of [`Self::to_hex`] output.
    pub const HEX_LEN: usize = 32;

    /// Constructs a [`SessionId`] from a raw 16-byte value. The bytes
    /// are not validated — the only invariant is the length, which is
    /// statically guaranteed by the array type.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase 32-hex-char representation suitable for HTTP headers.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(Self::HEX_LEN);
        for byte in &self.0 {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }

    /// Parses a 32-character hex value (case-insensitive). Returns
    /// `None` for any other length or non-hex input — including the
    /// empty string, so a missing header trivially folds into `None`.
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != Self::HEX_LEN {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 16];
        for i in 0..16 {
            let hi = hex_value(bytes[2 * i])?;
            let lo = hex_value(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncate so logs stay readable; the full ID is a bearer
        // token and we deliberately avoid logging it in full.
        let hex = self.to_hex();
        write!(f, "SessionId({}…)", &hex[..8])
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lower-cased name of the request header carrying the Session ID a
/// client wishes to resume.
pub const RESUME_REQUEST_HEADER: &str = "x-outline-resume";

/// Lower-cased name of the request header advertising client support
/// for session resumption. Sent on every connect for as long as the
/// client wishes to receive future Session IDs.
pub const RESUME_CAPABLE_HEADER: &str = "x-outline-resume-capable";

/// Lower-cased name of the response header carrying the Session ID
/// the server has assigned to the just-established session.
pub const SESSION_RESPONSE_HEADER: &str = "x-outline-session";

/// Lower-cased name of the request **and** response header used to
/// negotiate the Ack-Prefix Protocol (v1).
///
/// Client sets `1` on the upgrade request to advertise it understands
/// the on-resume-hit control frame; server echoes `1` in the response
/// to confirm support. When **both** sides set the header AND the
/// resume hits AND owner-check passes, the server emits a 14-byte
/// plaintext control frame ahead of the upstream→client relay.
///
/// See `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1) for the
/// wire format and full negotiation rules.
pub const ACK_PREFIX_HEADER: &str = "x-outline-resume-ack-prefix";

/// Lower-cased name of the request **and** response header used to
/// negotiate the v2 Symmetric Downlink Replay capability (`1` to
/// advertise / confirm). Per spec the server MUST suppress this
/// echo when the client did not also advertise [`ACK_PREFIX_HEADER`]
/// or when the server's own ring is disabled (`downlink_buffer_bytes
/// == 0`). See `docs/SESSION-RESUMPTION.md` § Symmetric Downlink
/// Replay (v2) for the wire format and gating rules.
pub const SYMMETRIC_REPLAY_HEADER: &str = "x-outline-resume-symmetric-replay";

/// Lower-cased name of the request-only header carrying the client's
/// last-acked downstream offset on a v2 resume request. Decimal
/// `u64`, max value `2^63 − 1`. Sent only on retry redials that
/// also carry [`ACK_PREFIX_HEADER`] AND [`SYMMETRIC_REPLAY_HEADER`].
pub const DOWN_ACKED_HEADER: &str = "x-outline-resume-down-acked";

/// Writes the request-side resume negotiation headers. One
/// implementation shared by the h1 upgrade, h2 CONNECT and h3 Extended
/// CONNECT dial paths so the header set cannot drift between carriers:
/// `Resume-Capable` is always advertised; the Session ID, v1/v2
/// capability bits and the v2 down-acked offset follow the gating the
/// orchestrator already applied to
/// [`DialResumeOptions`](crate::dial_plan::DialResumeOptions).
pub(crate) fn apply_resume_request_headers(
    resume: &crate::dial_plan::DialResumeOptions,
    headers: &mut http::HeaderMap,
) {
    headers.insert(RESUME_CAPABLE_HEADER, http::HeaderValue::from_static("1"));
    if let Some(id) = resume.resume_request {
        headers.insert(
            RESUME_REQUEST_HEADER,
            id.to_hex().parse().expect("hex Session ID is a valid header value"),
        );
    }
    if resume.ack_prefix_requested {
        // Capability advertise for Ack-Prefix Protocol v1. The server
        // only emits the 14-byte control frame when it sees this header
        // AND the resume hits; old servers ignore it.
        headers.insert(ACK_PREFIX_HEADER, http::HeaderValue::from_static("1"));
    }
    if resume.symmetric_replay_requested {
        // v2 Symmetric Downlink Replay capability advertise. Spec gates
        // v2 on v1; the orchestrator enforces that invariant before the
        // options reach a dial path.
        headers.insert(SYMMETRIC_REPLAY_HEADER, http::HeaderValue::from_static("1"));
    }
    // v2 client-reported downstream-acked offset. Sent only on retry
    // redials that also advertise v2 AND when the offset is non-zero
    // (a fresh session has no prior bytes to claim).
    if resume.symmetric_replay_requested && resume.client_acked_offset > 0 {
        headers.insert(
            DOWN_ACKED_HEADER,
            resume
                .client_acked_offset
                .to_string()
                .parse()
                .expect("decimal u64 is a valid header value"),
        );
    }
}

/// Server's response-side echo of the resume negotiation, parsed with
/// identical gating on every dial path.
pub(crate) struct NegotiatedResume {
    /// Session ID the server minted for this session, if any.
    pub(crate) issued_session_id: Option<SessionId>,
    /// v1 negotiation result: we advertised AND the server echoed `1`.
    /// A spurious echo without a matching request is reported as
    /// `false` so the receiver never looks for a control frame the
    /// spec forbids the server from sending.
    pub(crate) ack_prefix_advertised_by_server: bool,
    /// v2 negotiation result: requested, echoed, AND v1 also came back
    /// on — the v2-on-v1 invariant is enforced locally even if a buggy
    /// server echoes v2 alone.
    pub(crate) symmetric_replay_advertised_by_server: bool,
}

/// Parses the `X-Outline-*` response headers against what the request
/// advertised.
pub(crate) fn parse_resume_response_echo(
    resume: &crate::dial_plan::DialResumeOptions,
    headers: &http::HeaderMap,
) -> NegotiatedResume {
    let issued_session_id = headers
        .get(SESSION_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex);
    let ack_prefix_advertised_by_server = resume.ack_prefix_requested
        && headers.get(ACK_PREFIX_HEADER).and_then(|v| v.to_str().ok()) == Some("1");
    let symmetric_replay_advertised_by_server = resume.symmetric_replay_requested
        && ack_prefix_advertised_by_server
        && headers.get(SYMMETRIC_REPLAY_HEADER).and_then(|v| v.to_str().ok()) == Some("1");
    NegotiatedResume {
        issued_session_id,
        ack_prefix_advertised_by_server,
        symmetric_replay_advertised_by_server,
    }
}

/// Process-wide cache of the last server-issued [`SessionId`] for each
/// logical uplink. Callers (the warm-standby refill, fresh dials in
/// `connect_tcp_ws_fresh`, the probe path that wants to opt-in) read
/// the cached ID before dialing and write the new ID returned in the
/// upgrade response.
///
/// The cache is intentionally last-write-wins per key. Multiple
/// concurrent dials to the same uplink will overwrite each other's
/// entries; on a parking-storm, only the most recently dialed session
/// is reachable by ID, the others are simply un-resumable. This is an
/// acceptable simplification for the motivating scenario (intermittent
/// QUIC↔TCP path flap on a small number of uplinks); a more
/// fine-grained scheme (per-stream, per-route) can layer on top later
/// without breaking this API.
#[derive(Default)]
pub struct ResumeCache {
    inner: Mutex<ResumeCacheInner>,
}

/// Hard cap on cached resume entries. Keys are `<uplink>#<transport>`,
/// so the live population is two entries per configured uplink — far
/// below this cap in practice. The cap is a safety valve keeping the
/// process-wide cache bounded if keys ever become more dynamic; on
/// overflow the oldest-inserted entry is evicted (resume is
/// best-effort, so an evicted entry only costs a missed resume).
const RESUME_CACHE_CAPACITY: usize = 1_024;

/// Live entries plus their first-insertion order. The two collections
/// always hold the same key set (`forget` removes from both), so
/// eviction can pop the queue front without staleness checks.
#[derive(Default)]
struct ResumeCacheInner {
    entries: HashMap<String, SessionId>,
    insertion_order: VecDeque<String>,
}

impl ResumeCache {
    pub fn new_uninit() -> Self {
        Self {
            inner: Mutex::new(ResumeCacheInner::default()),
        }
    }

    /// Returns the last cached Session ID for `key`, if any.
    pub fn get(&self, key: &str) -> Option<SessionId> {
        self.inner.lock().entries.get(key).copied()
    }

    /// Stores `id` under `key`. Overwrites any previous value. At
    /// capacity, the oldest-inserted key is evicted to make room.
    pub fn store(&self, key: impl Into<String>, id: SessionId) {
        let key = key.into();
        let inner = &mut *self.inner.lock();
        if !inner.entries.contains_key(&key) {
            while inner.entries.len() >= RESUME_CACHE_CAPACITY {
                let Some(oldest) = inner.insertion_order.pop_front() else {
                    break;
                };
                inner.entries.remove(&oldest);
            }
            inner.insertion_order.push_back(key.clone());
        }
        inner.entries.insert(key, id);
    }

    /// Convenience: stores the issued ID when present, no-op otherwise.
    /// Returned by the WebSocket transports as `Option<SessionId>`.
    pub fn store_if_issued(&self, key: impl Into<String>, issued: Option<SessionId>) {
        if let Some(id) = issued {
            self.store(key, id);
        }
    }

    /// Removes the cached ID for `key`. Useful when the caller learns
    /// the parked session is gone (e.g. server returned a fresh ID
    /// after we presented a now-expired one).
    pub fn forget(&self, key: &str) {
        let inner = &mut *self.inner.lock();
        if inner.entries.remove(key).is_some() {
            inner.insertion_order.retain(|k| k != key);
        }
    }

    /// Test/diagnostic accessor. Companion to [`Self::len`].
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Test/diagnostic accessor. Returns the number of cached entries.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

/// Returns the process-wide [`ResumeCache`]. Initialised on first
/// access. All callers sharing the same `outline-transport` crate
/// instance see the same cache.
pub fn global_resume_cache() -> &'static ResumeCache {
    static CACHE: OnceLock<ResumeCache> = OnceLock::new();
    CACHE.get_or_init(ResumeCache::default)
}

const fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/resumption.rs"]
mod tests;
