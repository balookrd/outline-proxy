//! Opaque 16-byte server-issued identifier for a resumable session.
//!
//! See `docs/SESSION-RESUMPTION.md` for the wire format and the trust model.

use std::fmt;

use outline_wire::cluster::{ObfuscationKey, ShardId, decode_shard, encode_session_id};
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

    /// Draws a fresh identifier that carries the cluster `shard` (this home
    /// server's id), obfuscated under `key` so the token stays wire-random.
    /// Used instead of [`Self::random`] when the server runs in a cluster; a
    /// resuming client's edge decodes the shard back with [`Self::shard`] to
    /// route to this home. See `docs/CLUSTER.md`.
    pub(crate) fn random_with_shard(
        rng: &SystemRandom,
        key: &ObfuscationKey,
        shard: ShardId,
    ) -> std::io::Result<Self> {
        let mut entropy = [0u8; 16];
        rng.fill(&mut entropy)
            .map_err(|_| std::io::Error::other("csprng failure minting session id"))?;
        Ok(Self(encode_session_id(key, shard, &entropy)))
    }

    /// Decodes the cluster shard embedded in this id under `key`. Total: any
    /// id yields some shard, so an unknown/forged id simply routes to a shard
    /// that resume-misses. Only meaningful when the cluster is configured.
    pub(crate) fn shard(&self, key: &ObfuscationKey) -> ShardId {
        decode_shard(key, &self.0)
    }

    /// Constructs from raw bytes. Used by Addons-decoding paths.
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

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
#[path = "tests/session_id.rs"]
mod tests;
