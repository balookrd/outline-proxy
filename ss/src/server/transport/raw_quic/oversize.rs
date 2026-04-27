//! Server-side oversize-record stream: bidi QUIC stream that carries
//! UDP payloads which exceed `Connection::max_datagram_size()`.
//!
//! Wire format on the stream, repeating in both directions:
//!
//! ```text
//! [magic(8)]      ── only on the very first record sent in either
//!                    direction; identifies the stream as the oversize
//!                    fallback channel and disambiguates it from
//!                    VLESS-TCP / SS-TCP request streams that share
//!                    the same accept_bi loop.
//! [len(2 BE) || record] *
//! ```
//!
//! `record` is opaque at this layer — for ALPN `vless-mtu` it is
//! `[session_id_4B || payload]` (same content as a datagram on that
//! ALPN); for `ss-mtu` it is one self-contained SS-AEAD UDP packet.
//!
//! This file mirrors outline-ws-rust/crates/outline-transport/src/quic/
//! oversize.rs byte-for-byte on the wire — the format is the protocol
//! contract between the two repositories. Any change to magic / length
//! width / ordering MUST be made on both sides simultaneously and bump
//! the ALPN version.

use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use tokio::sync::Mutex;

/// Magic prefix written by whichever side opens the oversize-record
/// stream first. The receiver matches it before consuming records to
/// confirm the stream is the oversize fallback channel.
pub const OVERSIZE_STREAM_MAGIC: &[u8; 8] = b"OUTLINE\x01";

/// Maximum record size on the stream (payload length carried in the
/// 2-byte big-endian length prefix). Caps allocation per record on
/// the receiver and bounds the worst-case length of one record to
/// the entire IP/UDP datagram range.
pub const MAX_OVERSIZE_RECORD_LEN: usize = u16::MAX as usize;

/// Owns the bidi pair backing the oversize-record stream and
/// serialises concurrent senders / readers via per-half `Mutex`es.
pub struct OversizeStream {
    send: Mutex<quinn::SendStream>,
    recv: Mutex<quinn::RecvStream>,
    /// `true` if the local side opened the stream and has not yet
    /// written the magic prefix — flipped to `false` after the first
    /// `send_record` call.
    pending_magic: Mutex<bool>,
    /// `true` if the receiver still expects to read the magic prefix
    /// before any records — flipped to `false` after `validate_magic`.
    expect_magic: Mutex<bool>,
}

impl OversizeStream {
    /// Build from a freshly-opened bidi pair where the LOCAL side
    /// initiated the stream.
    pub fn from_local_open(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            pending_magic: Mutex::new(true),
            expect_magic: Mutex::new(true),
        }
    }

    /// Build from a bidi pair where the REMOTE side initiated the
    /// stream and the caller has already consumed and validated the
    /// inbound magic prefix off the recv half.
    pub fn from_accept_validated(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            pending_magic: Mutex::new(true),
            expect_magic: Mutex::new(false),
        }
    }

    /// Atomically write `[len_be(2) || record]`, prepending the magic
    /// prefix on the very first call.
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
        let frame_len =
            if *pending_magic { OVERSIZE_STREAM_MAGIC.len() } else { 0 } + 2 + record.len();
        let mut frame = Vec::with_capacity(frame_len);
        if *pending_magic {
            frame.extend_from_slice(OVERSIZE_STREAM_MAGIC);
        }
        frame.extend_from_slice(&(record.len() as u16).to_be_bytes());
        frame.extend_from_slice(record);
        send.write_all(&frame)
            .await
            .map_err(|e| anyhow!("oversize stream write_all failed: {e}"))?;
        *pending_magic = false;
        Ok(())
    }

    /// Read one length-prefixed record. Validates the inbound magic
    /// prefix on first call (unless the constructor declared it
    /// pre-validated). Returns `Ok(None)` on clean EOF before any
    /// record header is read.
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
        recv.read_exact(&mut buf)
            .await
            .map_err(|error| anyhow!("oversize stream record read failed (len={len}): {error}"))?;
        Ok(Some(Bytes::from(buf)))
    }

    /// Best-effort write-side close.
    #[allow(dead_code)]
    pub async fn close(&self) -> Result<()> {
        let mut send = self.send.lock().await;
        let _ = send.finish();
        Ok(())
    }
}

/// Connection-level slot that lazy-holds the oversize-record stream
/// once either side opens it. Idempotent install — first writer wins,
/// subsequent calls return the already-stored handle so both halves of
/// the connection observe the same stream regardless of who opened
/// first.
#[derive(Default)]
pub struct OversizeStreamSlot {
    inner: OnceLock<Arc<OversizeStream>>,
}

impl OversizeStreamSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, stream: Arc<OversizeStream>) -> Arc<OversizeStream> {
        // Race loser's `stream` is dropped here, which closes the
        // redundant bidi pair — same behaviour as the prior Mutex.
        let mut slot = Some(stream);
        Arc::clone(self.inner.get_or_init(|| slot.take().expect("first call")))
    }

    pub fn get(&self) -> Option<Arc<OversizeStream>> {
        self.inner.get().map(Arc::clone)
    }
}

/// Peek the first 8 bytes of a freshly-accepted bidi recv stream and
/// determine whether it is an oversize-record stream (magic match) or
/// a VLESS / SS request stream (anything else).
///
/// On magic match, returns the magic-validated stream half ready for
/// length-prefixed reads. On mismatch, returns the consumed bytes so
/// the caller can prepend them back into the stream's parser before
/// continuing — the bytes ARE valid VLESS/SS protocol bytes that
/// happened to be the first 8 of the request stream.
pub enum StreamKind {
    /// Magic matched. The recv half had its magic consumed; pair it
    /// with the recv (and the corresponding send half) into an
    /// `OversizeStream::from_accept_validated`.
    Oversize,
    /// Magic did not match. Caller must prepend `consumed` to whatever
    /// inbound buffer it uses for the request-stream parser.
    Other { consumed: [u8; 8] },
}

/// Read 8 bytes off `recv`. If they equal [`OVERSIZE_STREAM_MAGIC`],
/// returns `Oversize`. Otherwise returns `Other { consumed }` so the
/// caller can splice the bytes back. EOF before 8 bytes => Err.
pub async fn classify_accept_bi(recv: &mut quinn::RecvStream) -> Result<StreamKind> {
    let mut head = [0u8; OVERSIZE_STREAM_MAGIC.len()];
    recv.read_exact(&mut head)
        .await
        .map_err(|error| anyhow!("accept_bi peek failed: {error}"))?;
    if &head == OVERSIZE_STREAM_MAGIC {
        Ok(StreamKind::Oversize)
    } else {
        Ok(StreamKind::Other { consumed: head })
    }
}
