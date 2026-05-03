//! Client-side XHTTP packet-up transport.
//!
//! Mirror image of the server's `outline-ss-rust` module of the same
//! name. Multiplexes a long-lived GET (downlink) and a sequence of
//! short POSTs (uplink) over a single shared HTTP/2 connection. The
//! GET and POST share the same URL `<base>/<session-id>`, where
//! `session-id` is a random per-connection token chosen by us.
//!
//! Why h2 only in this MVP:
//! * h2 mux'es every request into the same TCP+TLS connection, so a
//!   long-lived GET and a stream of POSTs cost one TCP socket and
//!   one TLS handshake.
//! * h3 (raw QUIC) needs a separate dial path through `quinn` and
//!   manual h3 client setup; we add it once h2 is proven.
//!
//! Why pipelined POSTs (not strictly serial):
//! * Forcing one-at-a-time uplink would halve effective TX bandwidth
//!   and make every `Sink::start_send` await an HTTP round-trip.
//! * The server's reorder buffer already absorbs out-of-order seqs,
//!   so we can fire the next POST before the previous one returns.
//!
//! Failure modes:
//! * GET drop: driver completes the `incoming` channel; the stream
//!   surfaces as `None`. Callers retry by dialing a new session.
//! * POST 4xx/5xx: driver records it on a flag; the next outbound
//!   send sees a closed channel and `Sink::poll_ready` returns the
//!   recorded error. We do not attempt cross-session retry — that
//!   belongs at the uplink-manager layer.

use anyhow::{Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use rand::RngCore;
use std::convert::Infallible;
use url::Url;

use crate::config::TransportMode;
use crate::dns_cache::DnsCache;
use crate::resumption::SessionId;

mod h1;
mod h2;
#[cfg(feature = "h3")]
mod h3;
mod stream;

#[cfg(test)]
#[path = "tests/packet_up.rs"]
mod tests_packet_up;

#[cfg(test)]
#[path = "tests/packet_up_h1.rs"]
mod tests_packet_up_h1;

#[cfg(test)]
#[path = "tests/sink_backpressure.rs"]
mod tests_sink_backpressure;

// Re-exports kept at the previous `super::*` paths so sibling carrier
// modules (`h1`, `h2`, `h3`) and the rest of the crate keep working
// after the file split — h1 still does `use super::{XhttpStream, …}`.
pub(crate) use stream::XhttpStream;

/// Cross-transport session resumption: client → server. Mirrors the
/// header used by the WS-upgrade path so a single token works for
/// any resumption-aware client/server pair.
pub(super) const RESUME_REQUEST_HEADER: &str = "x-outline-resume";

/// Cross-transport session resumption: client capability flag. The
/// server only mints a fresh token when this is `1` (or when
/// `RESUME_REQUEST_HEADER` is present), so non-resumption clients
/// pay nothing.
pub(super) const RESUME_CAPABLE_HEADER: &str = "x-outline-resume-capable";

/// Cross-transport session resumption: server → client.
pub(super) const SESSION_RESPONSE_HEADER: &str = "x-outline-session";

/// Submode selector. Picked from the dial URL's query string
/// (`?mode=stream-one` selects stream-one; anything else, including
/// no query, means packet-up). The mode is not threaded through
/// the dial-dispatcher signature — instead `connect_xhttp` reads it
/// off the URL each call, which keeps the caller config minimal:
/// you write the URL you want and the carrier follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpSubmode {
    #[default]
    PacketUp,
    StreamOne,
}

impl std::fmt::Display for XhttpSubmode {
    /// Renders the dashed spelling the server's `?mode=` query
    /// expects, so the same string can be echoed back on dashboards
    /// and logs without re-mapping. Stable wire shape, do not change.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PacketUp => "packet-up",
            Self::StreamOne => "stream-one",
        })
    }
}

impl XhttpSubmode {
    /// Extracts the submode from a `?mode=...` query parameter on
    /// the dial URL. Accepts both dashed (`stream-one`) and
    /// underscored (`stream_one`) spellings to match what the server
    /// accepts. Anything else (or absence) → packet-up.
    pub fn from_url(url: &Url) -> Self {
        let Some(query) = url.query() else {
            return Self::PacketUp;
        };
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("mode=") {
                return match value {
                    "stream-one" | "stream_one" => Self::StreamOne,
                    _ => Self::PacketUp,
                };
            }
        }
        Self::PacketUp
    }

    fn append_to_query(&self, base: &str) -> String {
        match self {
            Self::PacketUp => base.to_owned(),
            Self::StreamOne => {
                if base.contains('?') {
                    format!("{base}&mode=stream-one")
                } else {
                    format!("{base}?mode=stream-one")
                }
            },
        }
    }
}

/// Pick the submode the dialer will actually use for a given carrier.
/// Two clamps stack on top of the URL-derived value:
///   1. The h1 carrier supports packet-up only (it cannot multiplex a
///      streaming GET against a streaming POST on a single keep-alive
///      socket), so callers asking for stream-one over h1 are silently
///      coerced. Without the clamp the inner `connect_xhttp_h1` bails,
///      which would propagate as a hard dial failure even though
///      packet-up is a safe substitute.
///   2. The per-host stream-one block — see [`crate::xhttp_submode_cache`] —
///      clamps stream-one to packet-up for `DOWNGRADE_TTL` after a
///      recent stream-one failure on this `host:port`. This avoids
///      re-paying the doomed handshake on every dial when the network
///      path between the client and server cannot carry stream-one
///      (CDN buffering, middlebox idle-timeout, etc.).
pub(super) async fn resolve_effective_submode(url: &Url, mode: TransportMode) -> XhttpSubmode {
    let mut submode = XhttpSubmode::from_url(url);
    if matches!(mode, TransportMode::XhttpH1) {
        submode = XhttpSubmode::PacketUp;
    }
    crate::xhttp_submode_cache::effective_submode(url, submode).await
}

/// Boxed body type used by every XHTTP request the client issues.
/// Hyper's `SendRequest<B>` is monomorphic in `B`, so we pick a
/// single `BoxBody` shape that fits the empty-GET / Full-POST /
/// streaming-POST cases all at once.
pub(super) type RequestBody = BoxBody<Bytes, Infallible>;

pub(super) fn empty_request_body() -> RequestBody {
    Empty::<Bytes>::new().boxed()
}

pub(super) fn full_request_body(payload: Bytes) -> RequestBody {
    Full::new(payload).boxed()
}

/// Bounds for the random session id used in `<base>/<id>`. The id is
/// opaque to the server; we just need it to be wide enough to avoid
/// per-session collision and narrow enough to fit inside one URL
/// path segment without bloating logs.
const SESSION_ID_BYTES: usize = 16;

/// Cap for the per-session inbound (downlink) channel. Frames in
/// flight are already capped by h2 flow control on the wire; this
/// in-memory buffer smooths the gap between the driver task drain
/// and `Stream::poll_next`. Sized for ~4 MB inflight at the 16 KB
/// SS2022 chunk size — enough to cover BDP on a 1 Gbps × 30 ms link
/// without forcing the reader to round-trip after every chunk.
/// `pub(super)` so the h3 sibling module reuses the same sizing.
pub(super) const INBOUND_CHANNEL_CAPACITY: usize = 256;

/// Cap for the per-session outbound (uplink) channel. Same sizing
/// rationale as the inbound cap. With the `PollSender`-based Sink
/// the channel applies real back-pressure to bulk uploads, so the
/// larger window only widens the burst tolerance — it does not
/// cause unbounded memory growth.
pub(super) const OUTBOUND_CHANNEL_CAPACITY: usize = 256;

/// Dials an XHTTP session against `url`. The host and port come from
/// `url`; the **path component** of `url` is the XHTTP base — the
/// server registers `<base>/<id>` and we generate `<id>` randomly.
/// This is the dispatcher: each `TransportMode::Xhttp*` arm hands
/// off to the corresponding carrier submodule.
pub(crate) async fn connect_xhttp(
    cache: &DnsCache,
    url: &Url,
    mode: TransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    resume_request: Option<SessionId>,
) -> Result<(XhttpStream, Option<SessionId>)> {
    match mode {
        TransportMode::XhttpH2 => {
            h2::connect_xhttp_h2(cache, url, mode, fwmark, ipv6_first, resume_request).await
        },
        TransportMode::XhttpH1 => {
            let submode = resolve_effective_submode(url, mode).await;
            h1::connect_xhttp_h1(cache, url, submode, fwmark, ipv6_first, resume_request).await
        },
        #[cfg(feature = "h3")]
        TransportMode::XhttpH3 => {
            let submode = resolve_effective_submode(url, mode).await;
            h3::connect_xhttp_h3(cache, url, submode, fwmark, ipv6_first, resume_request).await
        },
        #[cfg(not(feature = "h3"))]
        TransportMode::XhttpH3 => {
            bail!("xhttp_h3 requires the `h3` feature at build time");
        },
        other => bail!("connect_xhttp called with non-xhttp mode {other}"),
    }
}

pub(super) fn parse_session_response(headers: &http::HeaderMap) -> Option<SessionId> {
    headers
        .get(SESSION_RESPONSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex)
}

pub(super) fn default_port_for(use_tls: bool) -> u16 {
    if use_tls { 443 } else { 80 }
}

pub(super) struct XhttpTarget {
    pub(super) scheme: String,
    pub(super) authority: String,
    pub(super) base_path: String,
    pub(super) session_id: String,
}

impl XhttpTarget {
    pub(super) fn full_uri(&self) -> String {
        format!(
            "{}://{}{}/{}",
            self.scheme, self.authority, self.base_path, self.session_id,
        )
    }

    /// Packet-up uplink POST URL: appends the per-packet `seq` to
    /// the path, matching xray / sing-box's `PlacementPath` default
    /// (`<base>/<session>/<seq>`). The server still accepts the
    /// older header-based form (`X-Xhttp-Seq`) for backward
    /// compatibility, but this client now emits the path form so
    /// the wire shape is identical to what xray-family clients
    /// produce — the same byte stream in either ecosystem.
    pub(super) fn full_uri_with_seq(&self, seq: u64) -> String {
        format!(
            "{}://{}{}/{}/{seq}",
            self.scheme, self.authority, self.base_path, self.session_id,
        )
    }

    /// Same as [`Self::full_uri`] but with a `?mode=...` selector
    /// appended for the stream-one carrier. Packet-up sessions use
    /// the bare URI (the server defaults to packet-up when the
    /// query is absent or unrecognised).
    pub(super) fn full_uri_with_submode(&self, submode: XhttpSubmode) -> String {
        submode.append_to_query(&self.full_uri())
    }
}

pub(super) fn generate_session_id() -> Result<String> {
    let mut raw = [0_u8; SESSION_ID_BYTES];
    rand::thread_rng().fill_bytes(&mut raw);
    // URL-safe alphanumeric. Bias from `% 62` is negligible at
    // these lengths and gives a strict subset of `is_valid_session_id`
    // on the server side.
    const ALPHABET: &[u8; 62] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let id: String = raw
        .iter()
        .map(|byte| char::from(ALPHABET[(*byte as usize) % ALPHABET.len()]))
        .collect();
    Ok(id)
}
