use std::{fmt, sync::Arc};

use bytes::{Buf, BytesMut};
use rand::Rng as _;
use shadowsocks_crypto::{
    AeadCipher, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_MAX_PAYLOAD, SHADOWSOCKS_TAG_LEN, StreamNonce,
    stream::{
        drain_chunk_from_bytes, open_payload_in_place, seal_legacy_chunks, seal_payload_chunk,
        seal_ss2022_response_first_frame,
    },
};

use super::{
    error::CryptoError,
    ss2022_header::{
        SS2022_REQUEST_FIXED_CIPHERTEXT_LEN, SS2022_REQUEST_FIXED_HEADER_LEN,
        parse_ss2022_request_header, validate_ss2022_request_fixed_header,
    },
    user_key::UserKey,
};
use crate::clock;

#[derive(Clone, Debug)]
pub struct StreamResponseContext {
    pub(super) request_salt: Arc<[u8]>,
}

impl StreamResponseContext {
    /// The context an SS-2022 responder derives from the request salt it just
    /// authenticated. In production it only ever comes from
    /// [`AeadStreamDecryptor::response_context`]; this constructor exists so a
    /// test can drive the *encryptor* without first replaying a whole SS-2022
    /// request handshake, which says nothing about what it is testing.
    #[cfg(test)]
    pub(crate) fn for_test(request_salt: &[u8]) -> Self {
        Self { request_salt: Arc::from(request_salt) }
    }
}

struct ActiveStream {
    user: UserKey,
    /// Position of [`Self::user`] inside the original `users` slice. Exposed
    /// via [`AeadStreamDecryptor::user_index`] so the server can record a
    /// per-peer hint for the next handshake.
    user_index: usize,
    key: AeadCipher,
    nonce: StreamNonce,
    mode: ActiveStreamMode,
}

enum ActiveStreamMode {
    Legacy {
        /// The authenticated request salt. Unlike SS-2022 the legacy responder
        /// does not need it to build its reply; it is retained only so the
        /// server can feed it to the TCP handshake anti-replay filter.
        request_salt: Arc<[u8]>,
        pending_chunk_len: Option<usize>,
    },
    Ss2022 {
        request_salt: Arc<[u8]>,
        header_parsed: bool,
        pending_header_len: Option<usize>,
        pending_chunk_len: Option<usize>,
    },
}

pub struct AeadStreamDecryptor {
    users: Arc<[UserKey]>,
    buffer: BytesMut,
    active: Option<ActiveStream>,
    /// Optional last-seen user index from the per-peer cache. When set, the
    /// candidate scan tries this index first; on AEAD failure (stale hint,
    /// cipher mismatch, user reorder) the scan falls through to the full
    /// loop so correctness is unaffected.
    user_hint: Option<usize>,
}

impl fmt::Debug for AeadStreamDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadStreamDecryptor")
            .field("buffer_len", &self.buffer.len())
            .field("active_user", &self.active.as_ref().map(|active| active.user.id()))
            .finish()
    }
}

impl AeadStreamDecryptor {
    pub fn new(users: Arc<[UserKey]>) -> Self {
        Self {
            users,
            buffer: BytesMut::new(),
            active: None,
            user_hint: None,
        }
    }

    /// Sets a candidate user index to try first at the next handshake.
    /// Out-of-bounds or otherwise unfit hints are silently ignored — the
    /// full scan still runs.
    pub fn set_user_hint(&mut self, hint: Option<usize>) {
        self.user_hint = hint.filter(|&idx| idx < self.users.len());
    }

    /// Returns the position of the authenticated user inside the `users`
    /// slice handed to [`Self::new`], or `None` if the handshake has not
    /// completed.
    pub fn user_index(&self) -> Option<usize> {
        self.active.as_ref().map(|active| active.user_index)
    }

    pub fn feed_ciphertext(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Direct access to the internal ciphertext buffer so callers can fill it
    /// zero-copy via `AsyncReadExt::read_buf`. Caller is responsible for
    /// reserving capacity before each read.
    pub fn ciphertext_buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    pub fn user(&self) -> Option<&UserKey> {
        self.active.as_ref().map(|active| &active.user)
    }

    /// The authenticated request salt, exposed for anti-replay bookkeeping.
    /// `None` until the handshake completes. Available for both SS-2022 and
    /// legacy AEAD streams.
    pub fn request_salt(&self) -> Option<&Arc<[u8]>> {
        match &self.active.as_ref()?.mode {
            ActiveStreamMode::Legacy { request_salt, .. }
            | ActiveStreamMode::Ss2022 { request_salt, .. } => Some(request_salt),
        }
    }

    pub fn response_context(&self) -> Option<StreamResponseContext> {
        match self.active.as_ref()?.mode {
            ActiveStreamMode::Legacy { .. } => None,
            ActiveStreamMode::Ss2022 { ref request_salt, .. } => {
                Some(StreamResponseContext { request_salt: Arc::clone(request_salt) })
            },
        }
    }

    pub fn buffered_data(&self) -> &[u8] {
        &self.buffer
    }

    pub fn drain_plaintext(&mut self, output: &mut Vec<u8>) -> Result<(), CryptoError> {
        self.ensure_session_key()?;

        while let Some(active) = &mut self.active {
            match &mut active.mode {
                ActiveStreamMode::Legacy { pending_chunk_len, .. } => {
                    if !drain_chunk_from_bytes(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce,
                        pending_chunk_len,
                        LEGACY_MAX_PAYLOAD_LEN,
                        output,
                    )? {
                        break;
                    }
                },
                ActiveStreamMode::Ss2022 {
                    header_parsed,
                    pending_header_len,
                    pending_chunk_len,
                    ..
                } => {
                    if !*header_parsed {
                        let Some(header_len) = *pending_header_len else {
                            return Err(CryptoError::InvalidHeader);
                        };
                        if self.buffer.len() < header_len + SHADOWSOCKS_TAG_LEN {
                            break;
                        }

                        let mut encrypted_header =
                            self.buffer.split_to(header_len + SHADOWSOCKS_TAG_LEN);
                        let pt_len = open_payload_in_place(
                            &active.key,
                            &mut active.nonce,
                            &mut encrypted_header,
                        )?;
                        let initial_plaintext =
                            parse_ss2022_request_header(&encrypted_header[..pt_len])?;
                        output.extend_from_slice(&initial_plaintext);
                        *header_parsed = true;
                        *pending_header_len = None;
                        continue;
                    }

                    if !drain_chunk_from_bytes(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce,
                        pending_chunk_len,
                        SHADOWSOCKS_MAX_PAYLOAD,
                        output,
                    )? {
                        break;
                    }
                },
            }
        }

        Ok(())
    }

    fn ensure_session_key(&mut self) -> Result<(), CryptoError> {
        if self.active.is_some() {
            return Ok(());
        }

        if self.users.is_empty() {
            return Err(CryptoError::UnknownUser);
        }

        let mut any_candidate = false;
        let mut any_too_short = false;

        // Try the cached hint first when present. A hit here turns N HKDF +
        // AEAD probes into 1; on miss we fall through to the full scan.
        if let Some(hint) = self.user_hint
            && let Some(user) = self.users.get(hint)
        {
            match Self::try_user(&mut self.buffer, user, hint, &mut self.active)? {
                CandidateOutcome::Authenticated => return Ok(()),
                CandidateOutcome::Probed => any_candidate = true,
                CandidateOutcome::TooShort => any_too_short = true,
            }
        }

        for (idx, user) in self.users.iter().enumerate() {
            if Some(idx) == self.user_hint {
                continue;
            }
            match Self::try_user(&mut self.buffer, user, idx, &mut self.active)? {
                CandidateOutcome::Authenticated => return Ok(()),
                CandidateOutcome::Probed => any_candidate = true,
                CandidateOutcome::TooShort => any_too_short = true,
            }
        }

        if any_candidate && !any_too_short {
            Err(CryptoError::UnknownUser)
        } else {
            Ok(())
        }
    }

    /// Tries to authenticate the buffered handshake bytes against `user`. On
    /// success, populates `active` and returns [`CandidateOutcome::Authenticated`].
    /// On failure, leaves the buffer untouched and returns whether the
    /// candidate could be tested ([`CandidateOutcome::Probed`]) or simply did
    /// not have enough bytes available yet ([`CandidateOutcome::TooShort`]).
    fn try_user(
        buffer: &mut BytesMut,
        user: &UserKey,
        user_index: usize,
        active: &mut Option<ActiveStream>,
    ) -> Result<CandidateOutcome, CryptoError> {
        if user.cipher().is_ss2022() {
            let salt_len = user.cipher().salt_len();
            if buffer.len() < salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN {
                return Ok(CandidateOutcome::TooShort);
            }

            // Stack buffer — avoids a heap allocation for every candidate
            // that fails AEAD verification.
            let mut encrypted_fixed = [0u8; SS2022_REQUEST_FIXED_CIPHERTEXT_LEN];
            encrypted_fixed
                .copy_from_slice(&buffer[salt_len..salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN]);
            let key = AeadCipher::from_master_and_salt(
                user.cipher(),
                user.master_key(),
                &buffer[..salt_len],
            )?;
            let mut nonce = StreamNonce::new();
            let first_nonce = nonce.next()?;
            if let Ok(header) = key.open_fixed_in_place(
                &first_nonce,
                &mut encrypted_fixed,
                SS2022_REQUEST_FIXED_HEADER_LEN,
            ) {
                let header_len = validate_ss2022_request_fixed_header(header)?;
                // One allocation per successful handshake — unavoidable.
                let request_salt: Arc<[u8]> = Arc::from(&buffer[..salt_len]);
                buffer.advance(salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN);
                *active = Some(ActiveStream {
                    user: user.clone(),
                    user_index,
                    key,
                    nonce,
                    mode: ActiveStreamMode::Ss2022 {
                        request_salt,
                        header_parsed: false,
                        pending_header_len: Some(header_len),
                        pending_chunk_len: None,
                    },
                });
                return Ok(CandidateOutcome::Authenticated);
            }
        } else {
            let salt_len = user.cipher().salt_len();
            if buffer.len() < salt_len + 2 + SHADOWSOCKS_TAG_LEN {
                return Ok(CandidateOutcome::TooShort);
            }

            // Stack buffer — avoids a heap allocation for every candidate
            // that fails AEAD verification.
            let mut candidate = [0u8; 2 + SHADOWSOCKS_TAG_LEN];
            candidate.copy_from_slice(&buffer[salt_len..salt_len + 2 + SHADOWSOCKS_TAG_LEN]);
            let key = AeadCipher::from_master_and_salt(
                user.cipher(),
                user.master_key(),
                &buffer[..salt_len],
            )?;
            if let Ok(plaintext_len) = key.open_fixed_in_place(&[0u8; 12], &mut candidate, 2) {
                let chunk_len = u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                if chunk_len <= LEGACY_MAX_PAYLOAD_LEN {
                    // Capture the salt before advancing past it — the anti-replay
                    // filter keys on it. One allocation per successful handshake.
                    let request_salt: Arc<[u8]> = Arc::from(&buffer[..salt_len]);
                    buffer.advance(salt_len);
                    *active = Some(ActiveStream {
                        user: user.clone(),
                        user_index,
                        key,
                        nonce: StreamNonce::new(),
                        mode: ActiveStreamMode::Legacy { request_salt, pending_chunk_len: None },
                    });
                    return Ok(CandidateOutcome::Authenticated);
                }
            }
        }
        Ok(CandidateOutcome::Probed)
    }
}

#[derive(Debug, Clone, Copy)]
enum CandidateOutcome {
    /// AEAD verification succeeded, `active` is now populated.
    Authenticated,
    /// Candidate had enough buffered bytes to attempt verification but the
    /// AEAD did not match. Used to distinguish "all configured keys
    /// rejected" (`UnknownUser`) from "still buffering more bytes".
    Probed,
    /// Not enough buffered bytes yet for this cipher's salt + fixed header.
    /// The decryptor will retry on the next `feed_ciphertext` call.
    TooShort,
}

pub struct AeadStreamEncryptor {
    mode: StreamEncryptorMode,
}

enum StreamEncryptorMode {
    Legacy {
        key: AeadCipher,
        nonce: StreamNonce,
        salt: Vec<u8>,
        sent_salt: bool,
    },
    Ss2022 {
        key: AeadCipher,
        nonce: StreamNonce,
        salt: Vec<u8>,
        sent_header: bool,
        request_salt: Arc<[u8]>,
    },
}

impl fmt::Debug for AeadStreamEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadStreamEncryptor").finish()
    }
}

impl AeadStreamEncryptor {
    pub fn new(
        user: &UserKey,
        response_context: Option<StreamResponseContext>,
    ) -> Result<Self, CryptoError> {
        let mut salt = vec![0_u8; user.cipher().salt_len()];
        rand::rng().fill_bytes(&mut salt);
        let key = AeadCipher::from_master_and_salt(user.cipher(), user.master_key(), &salt)?;

        let mode = if user.cipher().is_ss2022() {
            let context = response_context.ok_or(CryptoError::MissingResponseContext)?;
            StreamEncryptorMode::Ss2022 {
                key,
                nonce: StreamNonce::new(),
                salt,
                sent_header: false,
                request_salt: context.request_salt,
            }
        } else {
            StreamEncryptorMode::Legacy {
                key,
                nonce: StreamNonce::new(),
                salt,
                sent_salt: false,
            }
        };

        Ok(Self { mode })
    }

    /// Bytes the next [`Self::encrypt_chunk`] writes in front of its first
    /// chunk on top of the per-chunk framing: the salt (legacy), or the salt
    /// plus the response header's type, timestamp and request salt (SS-2022).
    /// `0` once that prefix has gone out.
    pub fn pending_prefix_len(&self) -> usize {
        match &self.mode {
            StreamEncryptorMode::Legacy { salt, sent_salt, .. } => {
                if *sent_salt {
                    0
                } else {
                    salt.len()
                }
            },
            StreamEncryptorMode::Ss2022 { salt, sent_header, request_salt, .. } => {
                if *sent_header {
                    0
                } else {
                    salt.len() + 1 + 8 + request_salt.len()
                }
            },
        }
    }

    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        output: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        match &mut self.mode {
            StreamEncryptorMode::Legacy { key, nonce, salt, sent_salt } => {
                Ok(seal_legacy_chunks(key, nonce, salt, sent_salt, plaintext, output)?)
            },
            StreamEncryptorMode::Ss2022 {
                key,
                nonce,
                salt,
                sent_header,
                request_salt,
            } => {
                if !*sent_header {
                    seal_ss2022_response_first_frame(
                        key,
                        nonce,
                        salt,
                        request_salt,
                        clock::current_unix_secs(),
                        plaintext,
                        output,
                    )?;
                    *sent_header = true;
                } else {
                    seal_payload_chunk(
                        key,
                        nonce,
                        SHADOWSOCKS_MAX_PAYLOAD,
                        None,
                        plaintext,
                        output,
                    )?;
                }
                Ok(())
            },
        }
    }
}

#[cfg(test)]
#[path = "tests/stream.rs"]
mod tests;
