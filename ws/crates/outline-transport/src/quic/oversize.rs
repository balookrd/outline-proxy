//! Oversize-record stream: bidi QUIC stream that carries UDP payloads
//! which exceed `Connection::max_datagram_size()`.
//!
//! Wire format on the stream, repeating in both directions:
//!
//! ```text
//! [magic(8)]      ── only on the very first record sent in either
//!                    direction; identifies the stream as the oversize
//!                    fallback channel and disambiguates it from
//!                    VLESS-TCP / SS-TCP request streams that share the
//!                    same accept_bi loop on the server.
//! [len(2 BE) || record] *
//! ```
//!
//! `record` is opaque at this layer — for ALPN [`super::ALPN_VLESS_MTU`]
//! it is `[session_id_4B || payload]` (same content as a datagram on
//! that ALPN); for [`super::ALPN_SS_MTU`] it is one self-contained
//! SS-AEAD UDP packet.
//!
//! `len` is u16-BE, so a record is bounded at 65 535 bytes — comfortably
//! above any single UDP datagram size. Each `send_record` call writes
//! `[len || record]` atomically using `write_all`, so concurrent senders
//! cannot interleave bytes; a `Mutex` around the `SendStream` enforces
//! this in the cooperative-scheduler sense.
//!
//! Reader semantics: `recv_record().await` returns `Ok(Some(Bytes))` for
//! each well-formed record, `Ok(None)` on clean EOF (peer closed the
//! send side), and `Err` on protocol violation or transport failure.
//!
//! Magic-prefix rationale: VLESS-TCP request streams begin with byte
//! `0x00` (`VLESS_VERSION`); SS-TCP streams begin with random salt bytes.
//! The 8-byte magic `OUTLINE\x01` (which begins with `0x4F`, `'O'`)
//! disambiguates from VLESS deterministically and from SS-AEAD random
//! salts probabilistically (collision rate ≈ 2⁻⁶⁴ per stream — a
//! universe-age-of-attempts before one false match).

#![cfg(feature = "quic")]

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use tokio::sync::Mutex;

/// Magic prefix written as the first 8 bytes by whichever side opens the
/// oversize-record bidi stream. The receiver matches it before consuming
/// any length-prefixed records to confirm the stream is the oversize
/// fallback channel and not a freshly-opened VLESS-TCP / SS-TCP stream.
pub const OVERSIZE_STREAM_MAGIC: &[u8; 8] = b"OUTLINE\x01";

/// Maximum record size on the stream (payload length carried in the
/// 2-byte big-endian length prefix). Caps allocation per record on the
/// receiver and bounds the worst-case length of one record.
pub const MAX_OVERSIZE_RECORD_LEN: usize = u16::MAX as usize;

/// Owns the bidi pair backing the oversize-record stream and serialises
/// concurrent senders via a `Mutex` over the `SendStream`. The `RecvStream`
/// half is held under its own `Mutex` so a single reader task can drive
/// `recv_record` in a loop without blocking other tasks that are sending.
///
/// Lifetime is tied to the underlying QUIC connection: when the
/// connection closes, both halves return errors / EOF and any task
/// awaiting them unwinds.
pub struct OversizeStream {
    send: Mutex<quinn::SendStream>,
    recv: Mutex<quinn::RecvStream>,
    /// `true` if the local side opened the stream and has not yet
    /// written the magic prefix — flipped to `false` after the first
    /// `send_record` call. Avoids re-sending the magic on every record.
    pending_magic: Mutex<bool>,
    /// `true` if the receiver still expects to read the magic prefix
    /// before any records — flipped to `false` after `validate_magic`.
    expect_magic: Mutex<bool>,
}

impl OversizeStream {
    /// Build from a freshly-opened bidi pair where the LOCAL side
    /// initiated the stream. The first `send_record` call will prepend
    /// [`OVERSIZE_STREAM_MAGIC`] to its frame; the first `recv_record`
    /// call will consume the peer's magic before reading any length
    /// prefix.
    pub fn from_local_open(send: quinn::SendStream, recv: quinn::RecvStream) -> Arc<Self> {
        Arc::new(Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            pending_magic: Mutex::new(true),
            expect_magic: Mutex::new(true),
        })
    }

    /// Build from a bidi pair where the REMOTE side initiated the
    /// stream and we have already validated the inbound magic prefix
    /// (e.g., the server peeked the first 8 bytes off `accept_bi` to
    /// distinguish this stream from a VLESS-TCP / SS-TCP request).
    /// The local side still owes the peer a magic on first send so the
    /// peer's reader passes its own validation symmetrically.
    pub fn from_accept_validated(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Arc<Self> {
        Arc::new(Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            pending_magic: Mutex::new(true),
            // Caller already drained the magic before constructing.
            expect_magic: Mutex::new(false),
        })
    }

    /// Atomically write `[len_be(2) || record]`, prepending
    /// [`OVERSIZE_STREAM_MAGIC`] on the very first call. Returns
    /// `Err` if `record.len()` exceeds [`MAX_OVERSIZE_RECORD_LEN`] or
    /// the underlying stream rejects the write.
    pub async fn send_record(&self, record: &[u8]) -> Result<()> {
        if record.len() > MAX_OVERSIZE_RECORD_LEN {
            bail!(
                "oversize record exceeds 16-bit length cap: {} > {}",
                record.len(),
                MAX_OVERSIZE_RECORD_LEN
            );
        }
        let mut send = self.send.lock().await;
        let mut pending_magic = self.pending_magic.lock().await;
        // Coalesce magic + length + payload into one write_all so the
        // peer never sees a torn frame that would fail a partial-magic
        // validation. quinn's SendStream::write_all is internally one
        // congestion-controlled write per call.
        let frame_len = if *pending_magic { OVERSIZE_STREAM_MAGIC.len() } else { 0 } + 2 + record.len();
        let mut frame = Vec::with_capacity(frame_len);
        if *pending_magic {
            frame.extend_from_slice(OVERSIZE_STREAM_MAGIC);
        }
        frame.extend_from_slice(&(record.len() as u16).to_be_bytes());
        frame.extend_from_slice(record);
        send.write_all(&frame).await.context("oversize stream write_all failed")?;
        *pending_magic = false;
        Ok(())
    }

    /// Read one length-prefixed record. On the first call, validates
    /// the inbound [`OVERSIZE_STREAM_MAGIC`] (unless the constructor
    /// declared it pre-validated). Returns `Ok(None)` on clean EOF
    /// before any record header is read.
    pub async fn recv_record(&self) -> Result<Option<Bytes>> {
        let mut recv = self.recv.lock().await;
        let mut expect_magic = self.expect_magic.lock().await;
        if *expect_magic {
            let mut magic = [0u8; OVERSIZE_STREAM_MAGIC.len()];
            match recv.read_exact(&mut magic).await {
                Ok(()) => {},
                Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
                Err(error) => {
                    return Err(anyhow!("oversize stream magic read failed: {error}"));
                },
            }
            if &magic != OVERSIZE_STREAM_MAGIC {
                bail!("oversize stream: bad magic prefix {magic:02x?}");
            }
            *expect_magic = false;
        }
        drop(expect_magic);

        let mut len_buf = [0u8; 2];
        match recv.read_exact(&mut len_buf).await {
            Ok(()) => {},
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(error) => {
                return Err(anyhow!("oversize stream length read failed: {error}"));
            },
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.map_err(|error| {
            anyhow!("oversize stream record read failed (len={len}): {error}")
        })?;
        Ok(Some(Bytes::from(buf)))
    }

    /// Best-effort write-side close. Idempotent; surfaced to callers as
    /// `Result` so propagation matches the rest of the QUIC primitives,
    /// but a failure here is informational — the stream will be torn
    /// down anyway when the surrounding `SharedQuicConnection` closes.
    pub async fn close(&self) -> Result<()> {
        let mut send = self.send.lock().await;
        let _ = send.finish();
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/oversize.rs"]
mod tests;
