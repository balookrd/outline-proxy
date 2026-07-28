//! Datagram record framing for UDP carried over a *streaming* carrier.
//!
//! The datagram transports (SS-UDP, VLESS-UDP) assume the carrier preserves
//! packet boundaries: one send is one packet, one receive is one packet. A
//! WebSocket carrier honours that — a `Binary` frame is a real frame — but an
//! XHTTP carrier does not: its payload is an HTTP body, and h1/h2/h3 hand the
//! reader whatever slice of that byte stream happens to be available. Two
//! datagrams coalesce into one chunk, or one datagram arrives split across
//! two, and a per-packet AEAD decrypt then fails ("decryption failed" on a
//! coalesced pair, "packet too short" on a split one).
//!
//! This module restores the boundaries explicitly. Each datagram goes on the
//! wire as
//!
//! ```text
//! record := len:u16 (big endian) || payload[len]
//! ```
//!
//! and the receiver reassembles records from the stream regardless of how it
//! was sliced. The shape mirrors the `len || payload` records VLESS-UDP
//! already writes, so the two datagram protocols frame alike.
//!
//! Framing sits *outside* carrier padding: the padded frame (or the bare
//! encrypted packet when padding is off) is the record payload, so the two
//! features compose in either combination.
//!
//! Unlike padding, gating is **negotiated on the wire**, not config-
//! synchronised: the client advertises [`crate::xhttp::UDP_RECORDS_HEADER`] on
//! its XHTTP requests and the server echoes it back on the SS-UDP paths it
//! will frame. A peer that does not know the header never frames and never
//! decodes, so a half-rolled-out pair keeps the pre-existing (unframed) wire
//! instead of talking past each other.

use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;

/// Bytes of fixed header in front of every record: `len:u16`, big endian.
pub const UDP_RECORD_HEADER_LEN: usize = 2;

/// Largest datagram a single record can carry (the `u16` length ceiling).
/// Comfortably above any real UDP payload — a datagram past this is dropped
/// by the caller rather than fragmented, exactly like the VLESS-UDP ceiling.
pub const MAX_UDP_RECORD_PAYLOAD: usize = u16::MAX as usize;

/// Framing error. Only the encoder can fail, and only on a payload that
/// overflows the length field; the decoder reads nothing but lengths the
/// encoder wrote, so it is infallible by construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UdpRecordError {
    #[error("udp record payload too large: {0} bytes (max {MAX_UDP_RECORD_PAYLOAD})")]
    PayloadTooLarge(usize),
}

/// Appends `payload` to `out` as one length-prefixed record. Leaves `out`
/// untouched when the payload cannot be expressed.
pub fn encode_record_into(payload: &[u8], out: &mut Vec<u8>) -> Result<(), UdpRecordError> {
    let len =
        u16::try_from(payload.len()).map_err(|_| UdpRecordError::PayloadTooLarge(payload.len()))?;
    out.reserve(UDP_RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Streaming reassembler: feed it carrier chunks, take back whole datagrams.
///
/// Bounded by construction — the length field is a `u16`, so an incomplete
/// record can never hold more than [`MAX_UDP_RECORD_PAYLOAD`] plus its header,
/// and complete records leave the buffer as soon as the caller drains them.
#[derive(Debug, Default)]
pub struct UdpRecordDecoder {
    buf: BytesMut,
}

impl UdpRecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one carrier chunk. Chunk boundaries carry no meaning — a chunk
    /// may hold any number of records, whole or partial.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pops the next complete datagram, or `None` while the head record is
    /// still incomplete. Callers drain in a loop after every [`Self::push`].
    pub fn next_record(&mut self) -> Option<Bytes> {
        loop {
            if self.buf.len() < UDP_RECORD_HEADER_LEN {
                return None;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < UDP_RECORD_HEADER_LEN + len {
                return None;
            }
            self.buf.advance(UDP_RECORD_HEADER_LEN);
            if len == 0 {
                // Never emitted by `encode_record_into`; skip it rather than
                // surfacing an empty datagram (or stalling on it).
                continue;
            }
            return Some(self.buf.split_to(len).freeze());
        }
    }

    /// Bytes currently held pending reassembly. Diagnostics / bound checks.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
#[path = "tests/udp_records.rs"]
mod tests;
