//! XHTTP wire vocabulary shared by the server and the client.
//!
//! Owns the request-header names, the `?mode=` submode selector and the
//! session-id alphabet/validation rules of the XHTTP packet-up /
//! stream-one transport, so the two sides (and the xray / sing-box
//! ecosystem shapes the server accepts) stay on one definition.

use std::fmt;

/// HTTP request header carrying the in-order seq number for an uplink
/// POST. Lower-cased to match hyper's normalised headers. Our client
/// puts the seq into the URL path (`<base>/<id>/<seq>`, the xray /
/// sing-box default); the header form is the fallback shape the server
/// also accepts.
pub const SEQ_HEADER: &str = "x-xhttp-seq";

/// HTTP request/response header for a `Sec-WebSocket-Key`-style random
/// padding. The server emits one with each response and accepts (and
/// ignores) any client-emitted value.
pub const PADDING_HEADER: &str = "x-padding";

/// Hint header sent on the final POST of a session so the server can
/// collapse the uplink without waiting for an idle timeout. Optional —
/// its absence does not change correctness.
pub const FIN_HEADER: &str = "x-xhttp-fin";

/// XHTTP submode selector, negotiated through the dial URL's `?mode=`
/// query parameter. Absent / unknown values fall back to packet-up,
/// keeping pre-existing clients on the working path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpSubmode {
    /// Default. Long-lived GET (downlink) + sequenced POSTs (uplink).
    #[default]
    PacketUp,
    /// Single bidirectional request: request body = uplink, response
    /// body = downlink. Requires h2 or h3 (h1 cannot full-duplex).
    StreamOne,
}

impl XhttpSubmode {
    /// Parses `?mode=...` out of a URL query string. Accepts both
    /// dashed (`stream-one`) and underscored (`stream_one`) spellings
    /// because xray uses the dashed form on the wire while sing-box
    /// configs sometimes carry the underscored one. Anything else (or
    /// absence) → packet-up.
    pub fn parse_query(query: Option<&str>) -> Self {
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

    /// The dashed spelling the `?mode=` query expects on the wire.
    /// Stable wire shape, do not change.
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::PacketUp => "packet-up",
            Self::StreamOne => "stream-one",
        }
    }
}

impl fmt::Display for XhttpSubmode {
    /// Renders [`Self::as_wire_str`] so the same string can be echoed
    /// on dashboards and logs without re-mapping.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire_str())
    }
}

/// URL-safe alphabet both sides draw random session ids from. A strict
/// subset of what [`is_valid_session_id`] accepts, so generated ids
/// always validate.
pub const SESSION_ID_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Validates a client-supplied session id from the URL path: non-empty,
/// at most 128 bytes, ASCII alphanumerics plus `-` / `_` / `.`. The
/// server applies this to every `<base>/<id>` request; client-side
/// generators must stay within this contract.
pub fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Hidden TCP-vs-UDP discriminator for the optional *combined* path mode,
/// where Shadowsocks TCP and UDP share one base path instead of the default
/// split (`xhttp_path_ss` / `xhttp_path_ss_udp` and `ws_path_tcp` /
/// `ws_path_udp`). The bit rides the parity of the index of the session-id /
/// WS token's first character in [`SESSION_ID_ALPHABET`]: even → TCP, odd →
/// UDP. The first character stays a uniform alphanumeric (31 of the 62
/// choices per parity), so the token is statistically indistinguishable from
/// an ordinary random id and still satisfies [`is_valid_session_id`].
///
/// The client always knows whether it is dialing TCP or UDP, so it always
/// encodes the bit; the server only *reads* it on a combined path. On the
/// default split paths the path itself is the discriminator and the bit is
/// ignored, which keeps split-path and third-party (xray) clients working
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsPathKind {
    /// Shadowsocks TCP relay (stream). Encoded as even first-char parity.
    Tcp,
    /// Shadowsocks UDP relay (datagrams). Encoded as odd first-char parity.
    Udp,
}

impl SsPathKind {
    /// The parity bit this kind occupies in the token's first character.
    const fn bit(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }

    /// Short label for logs / metrics. Not a wire form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Maps one random byte to a [`SESSION_ID_ALPHABET`] character whose index
/// has the parity of `kind`, preserving uniformity across the 31 characters
/// of that parity. Callers supply the randomness (this crate carries no rng
/// dependency); the remaining session-id characters are generated the usual
/// way (`SESSION_ID_ALPHABET[byte % 62]`).
pub fn encode_kind_first_byte(rand_byte: u8, kind: SsPathKind) -> u8 {
    let half = (rand_byte as usize) % 31;
    SESSION_ID_ALPHABET[half * 2 + kind.bit()]
}

/// Recovers the [`SsPathKind`] a token encodes, from the parity of its first
/// character's index in [`SESSION_ID_ALPHABET`]. A first character outside
/// the alphabet (or an empty token) defaults to [`SsPathKind::Tcp`] — the
/// safe default for the combined path.
pub fn decode_kind(token: &str) -> SsPathKind {
    match token
        .as_bytes()
        .first()
        .and_then(|first| SESSION_ID_ALPHABET.iter().position(|c| c == first))
    {
        Some(index) if index % 2 == 1 => SsPathKind::Udp,
        _ => SsPathKind::Tcp,
    }
}

#[cfg(test)]
#[path = "tests/xhttp.rs"]
mod tests;
