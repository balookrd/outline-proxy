//! Shared upstream→client relay loop used by both websocket/H3 transports and
//! the raw shadowsocks TCP listener.
//!
//! The per-transport differences (where the ciphertext is written, teardown
//! semantics, ancillary logging) are captured by the [`UpstreamSink`] trait so
//! the read/encrypt loop itself lives in a single place.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Notify,
};

use crate::{
    crypto::{AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE},
    metrics::{AppProtocol, Metrics, Protocol},
};

use super::scratch::ScratchBuf;

/// Upper bound for the greedy-drain loop in [`relay_upstream_to_client`]
/// and the matching VLESS-WS / VLESS-mux readers. Once the in-progress
/// chunk reaches this size we stop polling for more already-buffered
/// bytes and proceed to encrypt + send. Sized to one legacy-AEAD record
/// (16 KiB - 1) so a single greedy-drained chunk fans out to one
/// full-sized AEAD chunk per WS frame on the SS path: tighter coalescing
/// would not produce larger frames anyway because `encrypt_legacy_chunks`
/// re-splits at this boundary, and looser coalescing would risk pinning
/// the relay reader long enough to starve the cancel arm. The VLESS
/// paths reuse the same target so per-frame overhead (mux header,
/// metric record, mpsc push) amortises across the same chunk size.
pub(in crate::server) const GREEDY_DRAIN_TARGET: usize = 0x3fff;

/// Outcome of [`relay_upstream_to_client`]. Distinguishes the natural
/// upstream-EOF path from a caller-requested cancellation (used by
/// session-resumption to harvest the still-live upstream reader for
/// parking).
pub(in crate::server) enum UpstreamRelayOutcome<R> {
    /// The upstream half-closed naturally (read returned `0`) or the sink
    /// errored. The reader has been consumed and is not returned.
    Closed,
    /// The caller fired the `cancel` notify before the upstream EOF.
    /// Returns the still-live reader for hand-off.
    Cancelled(R),
}

/// Destination for encrypted upstream bytes, parameterised by transport.
pub(in crate::server) trait UpstreamSink: Send {
    /// Forward a ciphertext chunk to the client.
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()>;

    /// Signal end-of-stream to the client.  Errors are best-effort.
    async fn close(&mut self);

    /// Hook fired when the first non-empty upstream payload is observed.
    fn on_first_payload(&mut self, _bytes: usize) {}

    /// Hook fired when upstream closed before sending any payload.
    fn on_eof_before_payload(&mut self) {}

    /// Hook fired after each successful chunk encryption.
    fn on_chunk_encrypted(&mut self, _plaintext: usize, _ciphertext: usize) {}
}

pub(in crate::server) async fn relay_upstream_to_client<R, S>(
    mut upstream_reader: R,
    mut sink: S,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    app_protocol: AppProtocol,
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
) -> Result<UpstreamRelayOutcome<R>>
where
    R: AsyncRead + Unpin,
    S: UpstreamSink,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.tcp_out(app_protocol, protocol);
    let aead_overhead_out = user_counters.tcp_aead_out(app_protocol, protocol);
    let mut buffer = ScratchBuf::take();
    let mut out_buf = BytesMut::with_capacity(MAX_CHUNK_SIZE);
    let mut saw_payload = false;
    loop {
        buffer.clear();
        buffer.reserve(MAX_CHUNK_SIZE);
        // Cancel arm: when no cancel is registered we substitute a future
        // that never resolves, so the select degenerates to the legacy
        // single-arm read.
        let cancelled = async {
            match cancel.as_deref() {
                Some(notify) => notify.notified().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            _ = cancelled => {
                // The sink is intentionally NOT closed: the caller is
                // about to hand the reader off to a new transport stream
                // that will install a fresh encryptor and wire its own
                // sink. Closing here would push a benign EOF the client
                // might race against the resume.
                return Ok(UpstreamRelayOutcome::Cancelled(upstream_reader));
            }
            read_result = upstream_reader.read_buf(&mut *buffer) => {
                let read = read_result.context("failed to read from upstream")?;
                if read == 0 {
                    if !saw_payload {
                        sink.on_eof_before_payload();
                    }
                    break;
                }

                // Greedy-drain: pull every byte the kernel already has
                // buffered into our chunk before encrypting+sending,
                // rather than letting one TCP-segment-sized read turn
                // into one WS Binary frame. On bulk downloads a busy
                // upstream produces ~1.4 KB segments; without this the
                // relay emits ~14k frames/sec at 170 Mbit, each with
                // its own TLS-record header, AEAD pair, and `await
                // send`. The drain is non-blocking: it never yields,
                // so it cannot delay ack-only or low-rate streams.
                while buffer.len() < GREEDY_DRAIN_TARGET {
                    match try_read_now(&mut upstream_reader, &mut buffer)
                        .await
                        .context("failed to drain upstream")?
                    {
                        Some(0) => break, // EOF: stop draining; encrypt what we have
                        Some(_) => {},    // got more, keep pulling
                        None => break,    // nothing immediately available
                    }
                }
                let read = buffer.len();

                if !saw_payload {
                    saw_payload = true;
                    sink.on_first_payload(read);
                }

                target_to_client.increment(read as u64);
                encryptor.encrypt_chunk(&buffer, &mut out_buf)?;
                let ciphertext = out_buf.split().freeze();
                aead_overhead_out
                    .increment((ciphertext.len() as u64).saturating_sub(read as u64));
                sink.on_chunk_encrypted(read, ciphertext.len());
                sink.send_ciphertext(ciphertext).await?;
            }
        }
    }

    sink.close().await;
    Ok(UpstreamRelayOutcome::Closed)
}

/// Relay decrypted client bytes to the upstream after the shadowsocks handshake.
///
/// Writes `initial_payload` first (already-decrypted bytes left over from the
/// handshake), then loops: read ciphertext from the client, decrypt, write
/// plaintext to upstream.  Shuts down the upstream writer on clean client EOF.
pub(in crate::server) async fn relay_client_to_upstream<R, W>(
    mut client_reader: R,
    mut decryptor: AeadStreamDecryptor,
    initial_payload: Vec<u8>,
    mut upstream_writer: W,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    app_protocol: AppProtocol,
    user_id: Arc<str>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let user_counters = metrics.user_counters(&user_id);
    let client_to_target = user_counters.tcp_in(app_protocol, protocol);
    if !initial_payload.is_empty() {
        client_to_target.increment(initial_payload.len() as u64);
        upstream_writer
            .write_all(&initial_payload)
            .await
            .context("failed to write initial payload to upstream")?;
    }

    let mut plaintext = ScratchBuf::take();
    loop {
        decryptor.ciphertext_buffer_mut().reserve(MAX_CHUNK_SIZE);
        let read = client_reader
            .read_buf(decryptor.ciphertext_buffer_mut())
            .await
            .context("failed to read from client")?;
        if read == 0 {
            break;
        }
        match decryptor.drain_plaintext(&mut plaintext) {
            Ok(()) => {},
            Err(CryptoError::UnknownUser) => break,
            Err(error) => return Err(anyhow!(error)),
        }
        if !plaintext.is_empty() {
            client_to_target.increment(plaintext.len() as u64);
            upstream_writer
                .write_all(&plaintext)
                .await
                .context("failed to write decrypted data to upstream")?;
            plaintext.clear();
        }
    }
    upstream_writer.shutdown().await.ok();
    Ok(())
}

/// Single non-blocking poll of `reader`, appending whatever is already
/// available to `buffer` without yielding the runtime.
///
/// Returns:
/// - `Ok(Some(n))` — `n` bytes read (`n == 0` is EOF).
/// - `Ok(None)`    — the reader returned `Poll::Pending`; nothing was
///   buffered in the kernel beyond what the caller has already consumed.
/// - `Err(_)`      — the underlying `poll_read` reported an I/O error.
///
/// The caller is expected to have reserved enough spare capacity in
/// `buffer` before calling — we write into `spare_capacity_mut` and only
/// commit the filled bytes via `set_len` on success.
async fn try_read_now<R>(reader: &mut R, buffer: &mut Vec<u8>) -> std::io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    poll_fn(|cx| {
        let prev_len = buffer.len();
        let spare = buffer.spare_capacity_mut();
        if spare.is_empty() {
            return Poll::Ready(Ok(Some(0)));
        }
        let mut read_buf = ReadBuf::uninit(spare);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                // SAFETY: `poll_read` populated the first `n` bytes of
                // the spare-capacity slice with initialised bytes.
                unsafe { buffer.set_len(prev_len + n) };
                Poll::Ready(Ok(Some(n)))
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

/// Slice-flavoured counterpart of [`try_read_now`]. Used by the VLESS
/// upstream readers, which share a fixed-length scratch slice across
/// the loop instead of a `Vec` with grow-on-demand capacity. Caller
/// passes the empty-tail half of the buffer (`&mut buf[total_read..]`)
/// and adds the returned byte count to its running total.
///
/// Same return semantics as [`try_read_now`]: `Some(0)` is EOF,
/// `Some(n)` for `n > 0` is bytes-buffered, `None` is `Poll::Pending`.
pub(in crate::server) async fn try_read_now_into_slice<R>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    if buf.is_empty() {
        return Ok(Some(0));
    }
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}
