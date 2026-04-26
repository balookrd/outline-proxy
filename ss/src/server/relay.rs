//! Shared upstream→client relay loop used by both websocket/H3 transports and
//! the raw shadowsocks TCP listener.
//!
//! The per-transport differences (where the ciphertext is written, teardown
//! semantics, ancillary logging) are captured by the [`UpstreamSink`] trait so
//! the read/encrypt loop itself lives in a single place.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use crate::{
    crypto::{AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE},
    metrics::{Metrics, Protocol},
};

use super::scratch::ScratchBuf;

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
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
) -> Result<UpstreamRelayOutcome<R>>
where
    R: AsyncRead + Unpin,
    S: UpstreamSink,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.tcp_out(protocol);
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
                if !saw_payload {
                    saw_payload = true;
                    sink.on_first_payload(read);
                }

                target_to_client.increment(read as u64);
                encryptor.encrypt_chunk(&buffer, &mut out_buf)?;
                let ciphertext = out_buf.split().freeze();
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
    user_id: Arc<str>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let user_counters = metrics.user_counters(&user_id);
    let client_to_target = user_counters.tcp_in(protocol);
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
