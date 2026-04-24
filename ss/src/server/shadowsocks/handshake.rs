use std::{net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow};
use tokio::{
    io::AsyncReadExt,
    net::tcp::OwnedReadHalf,
    time::{Duration, timeout},
};
use tracing::{debug, warn};

use crate::{
    crypto::{AeadStreamDecryptor, CryptoError, MAX_CHUNK_SIZE, UserKey, diagnose_stream_handshake},
    protocol::{TargetAddr, parse_target_addr},
};

use super::super::constants::SS_TCP_HANDSHAKE_TIMEOUT_SECS;

pub(super) struct SsHandshakeOutcome {
    pub(super) user: UserKey,
    pub(super) target: TargetAddr,
    pub(super) initial_payload: Vec<u8>,
    pub(super) decryptor: AeadStreamDecryptor,
}

pub(super) async fn ss_tcp_handshake(
    client_reader: &mut OwnedReadHalf,
    users: Arc<[UserKey]>,
    peer_addr: Option<SocketAddr>,
) -> Result<Option<SsHandshakeOutcome>> {
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);

    loop {
        let buffered_before = decryptor.buffered_data().len();
        decryptor.ciphertext_buffer_mut().reserve(MAX_CHUNK_SIZE);
        let read_fut = client_reader.read_buf(decryptor.ciphertext_buffer_mut());

        let read = match timeout(Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS), read_fut).await {
            Ok(result) => result.map_err(|e| anyhow!(e).context("failed to read from shadowsocks client"))?,
            Err(_) => {
                let encrypted_buffered = decryptor.buffered_data();
                let handshake_attempts = (!encrypted_buffered.is_empty())
                    .then(|| diagnose_stream_handshake(users.as_ref(), encrypted_buffered));
                let authenticated_user = decryptor.user().map(|u| u.id().to_string());
                warn!(
                    peer_addr = ?peer_addr,
                    encrypted_buffered_bytes = encrypted_buffered.len(),
                    plaintext_buffer_len = plaintext_buffer.len(),
                    authenticated_user = authenticated_user.as_deref(),
                    handshake_attempts = ?handshake_attempts,
                    "socket tcp handshake timed out while waiting for a complete client request"
                );
                return Err(anyhow!(
                    "shadowsocks tcp handshake timed out (encrypted_buffered_bytes={}, plaintext_buffer_len={}, authenticated_user={:?}, handshake_attempts={:?})",
                    encrypted_buffered.len(),
                    plaintext_buffer.len(),
                    authenticated_user,
                    handshake_attempts
                ));
            },
        };

        if read == 0 {
            debug!(peer_addr = ?peer_addr, "socket tcp client closed connection");
            return Ok(None);
        }

        debug!(
            peer_addr = ?peer_addr,
            encrypted_bytes = read,
            buffered_before,
            "socket tcp received encrypted bytes"
        );
        match decryptor.drain_plaintext(&mut plaintext_buffer) {
            Ok(()) => {
                debug!(
                    peer_addr = ?peer_addr,
                    plaintext_buffer_len = plaintext_buffer.len(),
                    buffered_after = decryptor.buffered_data().len(),
                    authenticated_user = decryptor.user().map(|u| u.id()),
                    "socket tcp decrypted client bytes"
                );
            },
            Err(CryptoError::UnknownUser) => {
                debug!(
                    peer_addr = ?peer_addr,
                    buffered = decryptor.buffered_data().len(),
                    attempts = ?diagnose_stream_handshake(users.as_ref(), decryptor.buffered_data()),
                    "socket tcp authentication failed for all configured users"
                );
                return Ok(None);
            },
            Err(error) => return Err(anyhow!(error)),
        }

        let Some((target, consumed)) = parse_target_addr(&plaintext_buffer)? else {
            continue;
        };
        let Some(user) = decryptor.user().cloned() else {
            continue;
        };

        debug!(
            peer_addr = ?peer_addr,
            user = user.id(),
            cipher = user.cipher().as_str(),
            "socket tcp shadowsocks user authenticated"
        );
        debug!(
            peer_addr = ?peer_addr,
            user = user.id(),
            target = %target.display_host_port(),
            initial_payload_bytes = plaintext_buffer.len().saturating_sub(consumed),
            "socket tcp parsed target address"
        );

        plaintext_buffer.drain(..consumed);
        return Ok(Some(SsHandshakeOutcome {
            user,
            target,
            initial_payload: plaintext_buffer,
            decryptor,
        }));
    }
}
