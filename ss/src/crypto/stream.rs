use std::{fmt, sync::Arc};

use bytes::{Buf, BytesMut};
use ring::{
    aead::{Aad, LessSafeKey},
    rand::{SecureRandom, SystemRandom},
};

use super::{
    error::CryptoError,
    primitives::{
        LEGACY_MAX_CHUNK_SIZE, MAX_CHUNK_SIZE, SS2022_REQUEST_FIXED_CIPHERTEXT_LEN,
        SS2022_REQUEST_FIXED_HEADER_LEN, SS2022_TCP_RESPONSE_TYPE, TAG_LEN, build_session_key,
        next_stream_nonce, nonce_zero, parse_ss2022_request_header, try_open_fixed_header,
        validate_ss2022_request_fixed_header,
    },
    user_key::UserKey,
};
use crate::clock;

#[derive(Clone, Debug)]
pub struct StreamResponseContext {
    pub(super) request_salt: Arc<[u8]>,
}

struct ActiveStream {
    user: UserKey,
    key: LessSafeKey,
    nonce_counter: u64,
    mode: ActiveStreamMode,
}

enum ActiveStreamMode {
    Legacy {
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
        }
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

        loop {
            let Some(active) = &mut self.active else {
                break;
            };

            match &mut active.mode {
                ActiveStreamMode::Legacy { pending_chunk_len } => {
                    if !drain_legacy_payload(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce_counter,
                        pending_chunk_len,
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
                        if self.buffer.len() < header_len + TAG_LEN {
                            break;
                        }

                        let mut encrypted_header = self.buffer.split_to(header_len + TAG_LEN);
                        let nonce = next_stream_nonce(&mut active.nonce_counter)?;
                        let header =
                            active.key.open_in_place(nonce, Aad::empty(), &mut encrypted_header)?;
                        let initial_plaintext = parse_ss2022_request_header(header)?;
                        output.extend_from_slice(&initial_plaintext);
                        *header_parsed = true;
                        *pending_header_len = None;
                        continue;
                    }

                    if !drain_ss2022_payload(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce_counter,
                        pending_chunk_len,
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

        let mut any_candidate = false;
        for user in self.users.iter() {
            if user.cipher().is_2022() {
                let salt_len = user.cipher().salt_len();
                if self.buffer.len() < salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN {
                    continue;
                }
                any_candidate = true;

                // Stack buffer — avoids a heap allocation for every candidate
                // that fails AEAD verification.
                let mut encrypted_fixed = [0u8; SS2022_REQUEST_FIXED_CIPHERTEXT_LEN];
                encrypted_fixed.copy_from_slice(
                    &self.buffer[salt_len..salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN],
                );
                let less_safe =
                    build_session_key(user.cipher(), user.master_key(), &self.buffer[..salt_len])?;
                if let Ok(header) = try_open_fixed_header(
                    &less_safe,
                    nonce_zero(),
                    &mut encrypted_fixed,
                    SS2022_REQUEST_FIXED_HEADER_LEN,
                ) {
                    let header_len = validate_ss2022_request_fixed_header(header)?;
                    // One allocation per successful handshake — unavoidable.
                    let request_salt: Arc<[u8]> = Arc::from(&self.buffer[..salt_len]);
                    self.buffer.advance(salt_len + SS2022_REQUEST_FIXED_CIPHERTEXT_LEN);
                    self.active = Some(ActiveStream {
                        user: user.clone(),
                        key: less_safe,
                        nonce_counter: 1,
                        mode: ActiveStreamMode::Ss2022 {
                            request_salt,
                            header_parsed: false,
                            pending_header_len: Some(header_len),
                            pending_chunk_len: None,
                        },
                    });
                    return Ok(());
                }
            } else {
                let salt_len = user.cipher().salt_len();
                if self.buffer.len() < salt_len + 2 + TAG_LEN {
                    continue;
                }
                any_candidate = true;

                // Stack buffer — avoids a heap allocation for every candidate
                // that fails AEAD verification.
                let mut candidate = [0u8; 2 + TAG_LEN];
                candidate.copy_from_slice(&self.buffer[salt_len..salt_len + 2 + TAG_LEN]);
                let less_safe =
                    build_session_key(user.cipher(), user.master_key(), &self.buffer[..salt_len])?;
                if let Ok(plaintext_len) =
                    try_open_fixed_header(&less_safe, nonce_zero(), &mut candidate, 2)
                {
                    let chunk_len =
                        u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                    if chunk_len <= LEGACY_MAX_CHUNK_SIZE {
                        self.buffer.advance(salt_len);
                        self.active = Some(ActiveStream {
                            user: user.clone(),
                            key: less_safe,
                            nonce_counter: 0,
                            mode: ActiveStreamMode::Legacy { pending_chunk_len: None },
                        });
                        return Ok(());
                    }
                }
            }
        }

        if any_candidate {
            Err(CryptoError::UnknownUser)
        } else {
            Ok(())
        }
    }
}

pub struct AeadStreamEncryptor {
    mode: StreamEncryptorMode,
}

enum StreamEncryptorMode {
    Legacy {
        key: LessSafeKey,
        nonce_counter: u64,
        salt: Vec<u8>,
        sent_salt: bool,
    },
    Ss2022 {
        key: LessSafeKey,
        nonce_counter: u64,
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
        SystemRandom::new().fill(&mut salt).map_err(|_| CryptoError::Random)?;
        let key = build_session_key(user.cipher(), user.master_key(), &salt)?;

        let mode = if user.cipher().is_2022() {
            let context = response_context.ok_or(CryptoError::MissingResponseContext)?;
            StreamEncryptorMode::Ss2022 {
                key,
                nonce_counter: 0,
                salt,
                sent_header: false,
                request_salt: context.request_salt,
            }
        } else {
            StreamEncryptorMode::Legacy {
                key,
                nonce_counter: 0,
                salt,
                sent_salt: false,
            }
        };

        Ok(Self { mode })
    }

    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        output: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        match &mut self.mode {
            StreamEncryptorMode::Legacy { key, nonce_counter, salt, sent_salt } => {
                encrypt_legacy_chunks(key, nonce_counter, salt, sent_salt, plaintext, output)
            },
            StreamEncryptorMode::Ss2022 {
                key,
                nonce_counter,
                salt,
                sent_header,
                request_salt,
            } => encrypt_ss2022_chunk(
                key,
                nonce_counter,
                salt,
                sent_header,
                request_salt,
                plaintext,
                output,
            ),
        }
    }
}

fn drain_length_header(
    buffer: &mut BytesMut,
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    max_chunk_size: usize,
) -> Result<Option<usize>, CryptoError> {
    if buffer.len() < 2 + TAG_LEN {
        return Ok(None);
    }

    let mut encrypted_len = buffer.split_to(2 + TAG_LEN);
    let nonce = next_stream_nonce(nonce_counter)?;
    let decrypted_len = key
        .open_in_place(nonce, Aad::empty(), &mut encrypted_len)
        .map_err(|_| CryptoError::InvalidLengthHeader)?;
    if decrypted_len.len() != 2 {
        return Err(CryptoError::InvalidLengthHeader);
    }

    let chunk_len = u16::from_be_bytes([decrypted_len[0], decrypted_len[1]]) as usize;
    if chunk_len > max_chunk_size {
        return Err(CryptoError::InvalidChunkSize(chunk_len));
    }
    Ok(Some(chunk_len))
}

fn drain_legacy_payload(
    buffer: &mut BytesMut,
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    pending_chunk_len: &mut Option<usize>,
    output: &mut Vec<u8>,
) -> Result<bool, CryptoError> {
    if pending_chunk_len.is_none() {
        *pending_chunk_len =
            drain_length_header(buffer, key, nonce_counter, LEGACY_MAX_CHUNK_SIZE)?;
        if pending_chunk_len.is_none() {
            return Ok(false);
        }
    }

    let chunk_len = pending_chunk_len.expect("set above");
    if buffer.len() < chunk_len + TAG_LEN {
        return Ok(false);
    }

    let mut encrypted_payload = buffer.split_to(chunk_len + TAG_LEN);
    let nonce = next_stream_nonce(nonce_counter)?;
    let decrypted_payload = key.open_in_place(nonce, Aad::empty(), &mut encrypted_payload)?;
    output.extend_from_slice(decrypted_payload);
    *pending_chunk_len = None;
    Ok(true)
}

fn drain_ss2022_payload(
    buffer: &mut BytesMut,
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    pending_chunk_len: &mut Option<usize>,
    output: &mut Vec<u8>,
) -> Result<bool, CryptoError> {
    if pending_chunk_len.is_none() {
        *pending_chunk_len = drain_length_header(buffer, key, nonce_counter, MAX_CHUNK_SIZE)?;
        if pending_chunk_len.is_none() {
            return Ok(false);
        }
    }

    let chunk_len = pending_chunk_len.expect("set above");
    if buffer.len() < chunk_len + TAG_LEN {
        return Ok(false);
    }

    let mut encrypted_payload = buffer.split_to(chunk_len + TAG_LEN);
    let nonce = next_stream_nonce(nonce_counter)?;
    let decrypted_payload = key.open_in_place(nonce, Aad::empty(), &mut encrypted_payload)?;
    output.extend_from_slice(decrypted_payload);
    *pending_chunk_len = None;
    Ok(true)
}

fn encrypt_legacy_chunks(
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    salt: &[u8],
    sent_salt: &mut bool,
    plaintext: &[u8],
    output: &mut BytesMut,
) -> Result<(), CryptoError> {
    let chunk_count = plaintext.len().div_ceil(LEGACY_MAX_CHUNK_SIZE).max(1);
    output.reserve(
        (!*sent_salt as usize) * salt.len()
            + plaintext.len()
            + chunk_count * (2 + TAG_LEN + TAG_LEN),
    );

    for chunk in plaintext.chunks(LEGACY_MAX_CHUNK_SIZE) {
        encrypt_legacy_chunk(key, nonce_counter, salt, sent_salt, chunk, output)?;
    }

    Ok(())
}

fn encrypt_legacy_chunk(
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    salt: &[u8],
    sent_salt: &mut bool,
    plaintext: &[u8],
    output: &mut BytesMut,
) -> Result<(), CryptoError> {
    if plaintext.len() > LEGACY_MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidChunkSize(plaintext.len()));
    }

    let salt_len = if *sent_salt { 0 } else { salt.len() };
    output.reserve(salt_len + 2 + TAG_LEN + plaintext.len() + TAG_LEN);
    if !*sent_salt {
        output.extend_from_slice(salt);
        *sent_salt = true;
    }
    let length = u16::try_from(plaintext.len())
        .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
        .to_be_bytes();
    let len_start = output.len();
    output.extend_from_slice(&length);
    let len_nonce = next_stream_nonce(nonce_counter)?;
    let tag = key
        .seal_in_place_separate_tag(len_nonce, Aad::empty(), &mut output[len_start..])
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(tag.as_ref());

    let payload_start = output.len();
    output.extend_from_slice(plaintext);
    let payload_nonce = next_stream_nonce(nonce_counter)?;
    let tag = key
        .seal_in_place_separate_tag(payload_nonce, Aad::empty(), &mut output[payload_start..])
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(tag.as_ref());

    Ok(())
}

fn encrypt_ss2022_chunk(
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    salt: &[u8],
    sent_header: &mut bool,
    request_salt: &[u8],
    plaintext: &[u8],
    output: &mut BytesMut,
) -> Result<(), CryptoError> {
    if plaintext.len() > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidChunkSize(plaintext.len()));
    }

    let capacity = if !*sent_header {
        salt.len() + (1 + 8 + request_salt.len() + 2) + TAG_LEN + plaintext.len() + TAG_LEN
    } else {
        2 + TAG_LEN + plaintext.len() + TAG_LEN
    };
    output.reserve(capacity);
    if !*sent_header {
        output.extend_from_slice(salt);
        let header_start = output.len();
        output.extend_from_slice(&[SS2022_TCP_RESPONSE_TYPE]);
        output.extend_from_slice(&clock::current_unix_secs().to_be_bytes());
        output.extend_from_slice(request_salt);
        output.extend_from_slice(
            &u16::try_from(plaintext.len())
                .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
                .to_be_bytes(),
        );
        let header_nonce = next_stream_nonce(nonce_counter)?;
        let tag = key
            .seal_in_place_separate_tag(header_nonce, Aad::empty(), &mut output[header_start..])
            .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(tag.as_ref());

        let payload_start = output.len();
        output.extend_from_slice(plaintext);
        let payload_nonce = next_stream_nonce(nonce_counter)?;
        let tag = key
            .seal_in_place_separate_tag(payload_nonce, Aad::empty(), &mut output[payload_start..])
            .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(tag.as_ref());
        *sent_header = true;
        return Ok(());
    }

    let len_start = output.len();
    output.extend_from_slice(
        &u16::try_from(plaintext.len())
            .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
            .to_be_bytes(),
    );
    let len_nonce = next_stream_nonce(nonce_counter)?;
    let tag = key
        .seal_in_place_separate_tag(len_nonce, Aad::empty(), &mut output[len_start..])
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(tag.as_ref());

    let payload_start = output.len();
    output.extend_from_slice(plaintext);
    let payload_nonce = next_stream_nonce(nonce_counter)?;
    let tag = key
        .seal_in_place_separate_tag(payload_nonce, Aad::empty(), &mut output[payload_start..])
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(tag.as_ref());
    Ok(())
}
