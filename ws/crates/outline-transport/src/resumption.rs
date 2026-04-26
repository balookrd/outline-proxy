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

use std::fmt;

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
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let id = SessionId::from_bytes([0xAB; 16]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), SessionId::HEX_LEN);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let parsed = SessionId::parse_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn parse_hex_rejects_invalid_length() {
        assert!(SessionId::parse_hex("").is_none());
        assert!(SessionId::parse_hex(&"a".repeat(31)).is_none());
        assert!(SessionId::parse_hex(&"a".repeat(33)).is_none());
    }

    #[test]
    fn parse_hex_accepts_uppercase_and_normalises_to_lowercase() {
        let id = SessionId::parse_hex("0123456789ABCDEFFEDCBA9876543210").unwrap();
        assert_eq!(id.to_hex(), "0123456789abcdeffedcba9876543210");
    }

    #[test]
    fn debug_output_does_not_leak_full_token() {
        let id = SessionId::from_bytes([0xAB; 16]);
        let debug = format!("{id:?}");
        assert!(debug.starts_with("SessionId("));
        assert!(debug.contains("abababab"));
        assert!(!debug.contains(&id.to_hex()));
    }
}
