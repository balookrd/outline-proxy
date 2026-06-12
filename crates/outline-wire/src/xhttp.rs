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

#[cfg(test)]
#[path = "tests/xhttp.rs"]
mod tests;
