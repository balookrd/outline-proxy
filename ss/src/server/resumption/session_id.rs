//! Opaque 16-byte server-issued identifier for a resumable session.
//!
//! See `docs/SESSION-RESUMPTION.md` for the wire format and the trust model.

use std::fmt;

use ring::rand::{SecureRandom, SystemRandom};

/// Server-minted opaque token identifying a resumable session.
///
/// Carried by the client across reconnects in the `X-Outline-Resume`
/// HTTP header (for WebSocket transports) or in the VLESS Addons
/// `RESUME_ID` opcode (for raw QUIC). The token is meaningless to the
/// client beyond echoing it back; ownership is enforced server-side
/// against the authenticated user (see [`super::registry::OrphanRegistry`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId([u8; 16]);

impl SessionId {
    /// Length, in characters, of [`Self::to_hex`] output.
    pub(crate) const HEX_LEN: usize = 32;

    /// Draws a fresh identifier from the supplied CSPRNG.
    pub(crate) fn random(rng: &SystemRandom) -> std::io::Result<Self> {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes)
            .map_err(|_| std::io::Error::other("csprng failure minting session id"))?;
        Ok(Self(bytes))
    }

    /// Constructs from raw bytes. Used by Addons-decoding paths.
    #[allow(dead_code)]
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase 32-hex-char representation suitable for HTTP headers.
    pub(crate) fn to_hex(self) -> String {
        let mut out = String::with_capacity(Self::HEX_LEN);
        for byte in &self.0 {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }

    /// Parses a 32-character hex value (case-insensitive). Returns `None`
    /// for any other length or non-hex input.
    pub(crate) fn parse_hex(s: &str) -> Option<Self> {
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
        // Truncate so logs stay readable; the full ID is a bearer token
        // and we deliberately avoid logging it in full.
        let hex = self.to_hex();
        write!(f, "SessionId({}…)", &hex[..8])
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
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
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let rng = SystemRandom::new();
        let id = SessionId::random(&rng).unwrap();
        let hex = id.to_hex();
        assert_eq!(hex.len(), SessionId::HEX_LEN);
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
    fn parse_hex_rejects_non_hex() {
        assert!(SessionId::parse_hex(&"g".repeat(32)).is_none());
        let mut almost = "a".repeat(31);
        almost.push('z');
        assert!(SessionId::parse_hex(&almost).is_none());
    }

    #[test]
    fn parses_uppercase_and_normalises_to_lowercase_on_format() {
        let id = SessionId::parse_hex("0123456789ABCDEFFEDCBA9876543210").unwrap();
        assert_eq!(id.to_hex(), "0123456789abcdeffedcba9876543210");
    }

    #[test]
    fn debug_output_is_truncated() {
        let id = SessionId::from_bytes([0xAB; 16]);
        let debug = format!("{id:?}");
        assert!(debug.starts_with("SessionId("));
        assert!(debug.contains("abababab"));
        // Do not expose the full ID in Debug output.
        assert!(!debug.contains(&id.to_hex()));
    }

    #[test]
    fn random_ids_differ() {
        let rng = SystemRandom::new();
        let a = SessionId::random(&rng).unwrap();
        let b = SessionId::random(&rng).unwrap();
        assert_ne!(a, b, "two consecutive random session IDs must differ");
    }
}
