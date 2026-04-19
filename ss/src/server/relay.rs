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
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::{
    crypto::{AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE},
    metrics::{Metrics, Protocol},
};

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

pub(in crate::server) async fn relay_upstream_to_client<S: UpstreamSink>(
    mut upstream_reader: OwnedReadHalf,
    mut sink: S,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(MAX_CHUNK_SIZE);
    let mut saw_payload = false;
    loop {
        buffer.clear();
        buffer.reserve(MAX_CHUNK_SIZE);
        let read = upstream_reader
            .read_buf(&mut buffer)
            .await
            .context("failed to read from upstream")?;
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

        metrics.record_tcp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", read);
        let ciphertext = encryptor.encrypt_chunk(&buffer)?;
        sink.on_chunk_encrypted(read, ciphertext.len());
        sink.send_ciphertext(ciphertext.into()).await?;
    }

    sink.close().await;
    Ok(())
}

/// Relay decrypted client bytes to the upstream after the shadowsocks handshake.
///
/// Writes `initial_payload` first (already-decrypted bytes left over from the
/// handshake), then loops: read ciphertext from the client, decrypt, write
/// plaintext to upstream.  Shuts down the upstream writer on clean client EOF.
pub(in crate::server) async fn relay_client_to_upstream(
    mut client_reader: OwnedReadHalf,
    mut decryptor: AeadStreamDecryptor,
    initial_payload: Vec<u8>,
    mut upstream_writer: OwnedWriteHalf,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
) -> Result<()> {
    if !initial_payload.is_empty() {
        metrics.record_tcp_payload_bytes(
            Arc::clone(&user_id),
            protocol,
            "client_to_target",
            initial_payload.len(),
        );
        upstream_writer
            .write_all(&initial_payload)
            .await
            .context("failed to write initial payload to upstream")?;
    }

    let mut plaintext = Vec::with_capacity(MAX_CHUNK_SIZE);
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
            metrics.record_tcp_payload_bytes(
                Arc::clone(&user_id),
                protocol,
                "client_to_target",
                plaintext.len(),
            );
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
