use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{
    Aes128, Aes256, cipher::BlockDecrypt, cipher::BlockEncrypt, cipher::KeyInit,
    cipher::generic_array::GenericArray,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::AeadInPlace as _};
use md5::{Digest as _, Md5};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use thiserror::Error;

use crate::{
    config::CipherKind,
    protocol::{TargetAddr, parse_target_addr},
};

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const XNONCE_LEN: usize = 24;
const LEGACY_MAX_CHUNK_SIZE: usize = 0x3fff;
pub const MAX_CHUNK_SIZE: usize = 0xffff;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
const SS2022_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const SS2022_TCP_REQUEST_TYPE: u8 = 0;
const SS2022_TCP_RESPONSE_TYPE: u8 = 1;
const SS2022_UDP_CLIENT_TYPE: u8 = 0;
const SS2022_UDP_SERVER_TYPE: u8 = 1;
const SS2022_REQUEST_FIXED_HEADER_LEN: usize = 11;
const SS2022_RESPONSE_FIXED_HEADER_LEN: usize = 27;
const SS2022_UDP_SEPARATE_HEADER_LEN: usize = 16;
const SS2022_MAX_PADDING_LEN: usize = 900;
const SS2022_MAX_TIME_DIFF_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("failed to decode base64 pre-shared key")]
    InvalidBase64Key,
    #[error("invalid pre-shared key length for {cipher}: expected {expected} bytes, got {actual}")]
    InvalidPskLength {
        cipher: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("failed to derive session key")]
    KeyDerivation,
    #[error("unsupported chunk size {0}")]
    InvalidChunkSize(usize),
    #[error("invalid encrypted length header")]
    InvalidLengthHeader,
    #[error("invalid shadowsocks 2022 header")]
    InvalidHeader,
    #[error("invalid shadowsocks 2022 timestamp")]
    InvalidTimestamp,
    #[error("missing shadowsocks 2022 response context")]
    MissingResponseContext,
    #[error("cipher error")]
    Cipher,
    #[error("randomness unavailable")]
    Random,
    #[error("packet too short")]
    PacketTooShort,
    #[error("no configured key matched the incoming data")]
    UnknownUser,
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Cipher
    }
}

#[derive(Clone)]
pub struct UserKey {
    id: Arc<str>,
    cipher: CipherKind,
    master_key: Vec<u8>,
    fwmark: Option<u32>,
    ws_path_tcp: Arc<str>,
    ws_path_udp: Arc<str>,
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKey").field("id", &self.id).finish()
    }
}

impl UserKey {
    pub fn new(
        id: impl Into<String>,
        password: &str,
        fwmark: Option<u32>,
        cipher: CipherKind,
        ws_path_tcp: impl Into<String>,
        ws_path_udp: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            id: Arc::from(id.into()),
            cipher,
            master_key: password_to_master_key(password, cipher)?,
            fwmark,
            ws_path_tcp: Arc::from(ws_path_tcp.into()),
            ws_path_udp: Arc::from(ws_path_udp.into()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }

    pub fn ws_path_tcp(&self) -> &str {
        &self.ws_path_tcp
    }

    pub fn ws_path_udp(&self) -> &str {
        &self.ws_path_udp
    }
}

#[derive(Clone, Debug)]
pub struct StreamResponseContext {
    request_salt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpSession {
    Legacy,
    Aes2022 { client_session_id: [u8; 8] },
    Chacha2022 { client_session_id: [u8; 8] },
}

impl UdpSession {
    pub fn client_session_id(&self) -> Option<[u8; 8]> {
        match self {
            Self::Legacy => None,
            Self::Aes2022 { client_session_id } | Self::Chacha2022 { client_session_id } => {
                Some(*client_session_id)
            }
        }
    }
}

pub struct UdpPacket {
    pub user: UserKey,
    pub payload: Vec<u8>,
    pub session: UdpSession,
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
        request_salt: Vec<u8>,
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
            .field(
                "active_user",
                &self.active.as_ref().map(|active| active.user.id()),
            )
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

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn user(&self) -> Option<&UserKey> {
        self.active.as_ref().map(|active| &active.user)
    }

    pub fn response_context(&self) -> Option<StreamResponseContext> {
        match self.active.as_ref()?.mode {
            ActiveStreamMode::Legacy { .. } => None,
            ActiveStreamMode::Ss2022 {
                ref request_salt, ..
            } => Some(StreamResponseContext {
                request_salt: request_salt.clone(),
            }),
        }
    }

    pub fn buffered_data(&self) -> &[u8] {
        &self.buffer
    }

    pub fn pull_plaintext(&mut self, output: &mut Vec<u8>) -> Result<(), CryptoError> {
        self.ensure_session_key()?;

        loop {
            let Some(active) = &mut self.active else {
                break;
            };

            match &mut active.mode {
                ActiveStreamMode::Legacy { pending_chunk_len } => {
                    if !pull_legacy_payload(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce_counter,
                        pending_chunk_len,
                        output,
                    )? {
                        break;
                    }
                }
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
                        let header = active.key.open_in_place(
                            next_stream_nonce(&mut active.nonce_counter),
                            Aad::empty(),
                            &mut encrypted_header,
                        )?;
                        let initial_plaintext = parse_ss2022_request_header(header)?;
                        output.extend_from_slice(&initial_plaintext);
                        *header_parsed = true;
                        *pending_header_len = None;
                        continue;
                    }

                    if !pull_ss2022_payload(
                        &mut self.buffer,
                        &active.key,
                        &mut active.nonce_counter,
                        pending_chunk_len,
                        output,
                    )? {
                        break;
                    }
                }
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
            if user.cipher.is_2022() {
                let fixed_len = SS2022_REQUEST_FIXED_HEADER_LEN + TAG_LEN;
                let salt_len = user.cipher.salt_len();
                if self.buffer.len() < salt_len + fixed_len {
                    continue;
                }
                any_candidate = true;

                let salt = &self.buffer[..salt_len];
                let request_salt = salt.to_vec();
                let mut encrypted_fixed = self.buffer[salt_len..salt_len + fixed_len].to_vec();
                let session_key = derive_subkey(user.cipher, &user.master_key, salt)?;
                let algorithm = cipher_algorithm(user.cipher);
                let key =
                    UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
                let less_safe = LessSafeKey::new(key);
                if let Ok(header) =
                    less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut encrypted_fixed)
                {
                    if header.len() == SS2022_REQUEST_FIXED_HEADER_LEN {
                        let header_len = validate_ss2022_request_fixed_header(header)?;
                        self.buffer.advance(salt_len + fixed_len);
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
                }
            } else {
                let salt_len = user.cipher.salt_len();
                if self.buffer.len() < salt_len + 2 + TAG_LEN {
                    continue;
                }
                any_candidate = true;

                let salt = &self.buffer[..salt_len];
                let encrypted_len = &self.buffer[salt_len..salt_len + 2 + TAG_LEN];
                let session_key = derive_subkey(user.cipher, &user.master_key, salt)?;
                let algorithm = cipher_algorithm(user.cipher);
                let key =
                    UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
                let less_safe = LessSafeKey::new(key);

                let mut candidate = encrypted_len.to_vec();
                if let Ok(plaintext_len) =
                    less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate)
                {
                    if plaintext_len.len() == 2 {
                        let chunk_len =
                            u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                        if chunk_len <= LEGACY_MAX_CHUNK_SIZE {
                            self.buffer.advance(salt_len);
                            self.active = Some(ActiveStream {
                                user: user.clone(),
                                key: less_safe,
                                nonce_counter: 0,
                                mode: ActiveStreamMode::Legacy {
                                    pending_chunk_len: None,
                                },
                            });
                            return Ok(());
                        }
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
        request_salt: Vec<u8>,
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
        let mut salt = vec![0_u8; user.cipher.salt_len()];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| CryptoError::Random)?;
        let session_key = derive_subkey(user.cipher, &user.master_key, &salt)?;
        let algorithm = cipher_algorithm(user.cipher);
        let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
        let key = LessSafeKey::new(key);

        let mode = if user.cipher.is_2022() {
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

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match &mut self.mode {
            StreamEncryptorMode::Legacy {
                key,
                nonce_counter,
                salt,
                sent_salt,
            } => encrypt_legacy_chunks(key, nonce_counter, salt, sent_salt, plaintext),
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
            ),
        }
    }
}

pub fn decrypt_udp_packet(users: &[UserKey], packet: &[u8]) -> Result<UdpPacket, CryptoError> {
    decrypt_udp_packet_with_hint(users, packet, None).map(|(packet, _)| packet)
}

pub fn decrypt_udp_packet_with_hint(
    users: &[UserKey],
    packet: &[u8],
    preferred_user_index: Option<usize>,
) -> Result<(UdpPacket, usize), CryptoError> {
    if packet.len() < TAG_LEN {
        return Err(CryptoError::PacketTooShort);
    }

    if let Some(index) = preferred_user_index.filter(|&index| index < users.len()) {
        match try_decrypt_udp_packet_for_user(&users[index], packet)? {
            Some(udp_packet) => return Ok((udp_packet, index)),
            None => {}
        }
    }

    for (index, user) in users.iter().enumerate() {
        if Some(index) == preferred_user_index {
            continue;
        }
        match try_decrypt_udp_packet_for_user(user, packet)? {
            Some(udp_packet) => return Ok((udp_packet, index)),
            None => {}
        }
    }

    Err(CryptoError::UnknownUser)
}

fn try_decrypt_udp_packet_for_user(
    user: &UserKey,
    packet: &[u8],
) -> Result<Option<UdpPacket>, CryptoError> {
    if user.cipher == CipherKind::Chacha20Poly13052022 {
        if packet.len() < XNONCE_LEN + TAG_LEN {
            return Ok(None);
        }

        let (nonce_bytes, ciphertext) = packet.split_at(XNONCE_LEN);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&user.master_key).map_err(|_| CryptoError::Cipher)?;
        let mut candidate = ciphertext.to_vec();
        if cipher
            .decrypt_in_place(XNonce::from_slice(nonce_bytes), b"", &mut candidate)
            .is_ok()
        {
            let (payload, client_session_id) = parse_ss2022_chacha_udp_request_body(&candidate)?;
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpSession::Chacha2022 { client_session_id },
            }));
        }
        return Ok(None);
    }

    if user.cipher.is_2022_aes() {
        if packet.len() < SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN {
            return Ok(None);
        }

        let (encrypted_header, ciphertext) = packet.split_at(SS2022_UDP_SEPARATE_HEADER_LEN);
        let separate_header = decrypt_ss2022_separate_header(user, encrypted_header)?;
        let client_session_id = separate_header[..8]
            .try_into()
            .map_err(|_| CryptoError::InvalidHeader)?;
        let session_key = derive_subkey(user.cipher, &user.master_key, &separate_header[..8])?;
        let algorithm = cipher_algorithm(user.cipher);
        let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
        let less_safe = LessSafeKey::new(key);
        let mut candidate = ciphertext.to_vec();
        let nonce = ss2022_udp_nonce(&separate_header)?;
        if let Ok(body) = less_safe.open_in_place(nonce, Aad::empty(), &mut candidate) {
            let payload = parse_ss2022_udp_request_body(body)?;
            return Ok(Some(UdpPacket {
                user: user.clone(),
                payload,
                session: UdpSession::Aes2022 { client_session_id },
            }));
        }
        return Ok(None);
    }

    let salt_len = user.cipher.salt_len();
    if packet.len() < salt_len + TAG_LEN {
        return Ok(None);
    }

    let (salt, ciphertext) = packet.split_at(salt_len);
    let session_key = derive_subkey(user.cipher, &user.master_key, salt)?;
    let algorithm = cipher_algorithm(user.cipher);
    let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
    let less_safe = LessSafeKey::new(key);
    let mut candidate = ciphertext.to_vec();
    if let Ok(plaintext) = less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate) {
        return Ok(Some(UdpPacket {
            user: user.clone(),
            payload: plaintext.to_vec(),
            session: UdpSession::Legacy,
        }));
    }

    Ok(None)
}

pub fn encrypt_udp_packet(user: &UserKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0_u8; user.cipher.salt_len()];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| CryptoError::Random)?;

    let session_key = derive_subkey(user.cipher, &user.master_key, &salt)?;
    let algorithm = cipher_algorithm(user.cipher);
    let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
    let less_safe = LessSafeKey::new(key);

    let mut output = salt;
    let mut ciphertext = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(udp_nonce_zero(), Aad::empty(), &mut ciphertext)
        .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn encrypt_udp_packet_for_response(
    user: &UserKey,
    source: &TargetAddr,
    payload: &[u8],
    session: &UdpSession,
    server_session_id: Option<[u8; 8]>,
    packet_id: u64,
) -> Result<Vec<u8>, CryptoError> {
    match session {
        UdpSession::Legacy => {
            let mut plaintext = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            plaintext.extend_from_slice(payload);
            encrypt_udp_packet(user, &plaintext)
        }
        UdpSession::Aes2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let mut body = Vec::with_capacity(1 + 8 + 8 + 2 + target.len() + payload.len());
            body.push(SS2022_UDP_SERVER_TYPE);
            body.extend_from_slice(&current_unix_secs().to_be_bytes());
            body.extend_from_slice(client_session_id);
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&target);
            body.extend_from_slice(payload);

            let mut separate_header = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
            separate_header[..8].copy_from_slice(&server_session_id);
            separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());
            let session_key = derive_subkey(user.cipher, &user.master_key, &server_session_id)?;
            let algorithm = cipher_algorithm(user.cipher);
            let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
            let less_safe = LessSafeKey::new(key);
            less_safe
                .seal_in_place_append_tag(
                    ss2022_udp_nonce(&separate_header)?,
                    Aad::empty(),
                    &mut body,
                )
                .map_err(|_| CryptoError::Cipher)?;

            let encrypted_header = encrypt_ss2022_separate_header(user, &separate_header)?;
            let mut packet = encrypted_header.to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        }
        UdpSession::Chacha2022 { client_session_id } => {
            let server_session_id = server_session_id.ok_or(CryptoError::InvalidHeader)?;
            let target = source.encode().map_err(|_| CryptoError::InvalidHeader)?;
            let mut body = Vec::with_capacity(8 + 8 + 1 + 8 + 8 + 2 + target.len() + payload.len());
            body.extend_from_slice(&server_session_id);
            body.extend_from_slice(&packet_id.to_be_bytes());
            body.push(SS2022_UDP_SERVER_TYPE);
            body.extend_from_slice(&current_unix_secs().to_be_bytes());
            body.extend_from_slice(client_session_id);
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&target);
            body.extend_from_slice(payload);

            let mut nonce = [0_u8; XNONCE_LEN];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| CryptoError::Random)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&user.master_key)
                .map_err(|_| CryptoError::Cipher)?;
            cipher
                .encrypt_in_place(XNonce::from_slice(&nonce), b"", &mut body)
                .map_err(|_| CryptoError::Cipher)?;

            let mut packet = nonce.to_vec();
            packet.extend_from_slice(&body);
            Ok(packet)
        }
    }
}

pub fn diagnose_stream_handshake(users: &[UserKey], buffer: &[u8]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            if user.cipher.is_2022() {
                let salt_len = user.cipher.salt_len();
                let fixed_len = SS2022_REQUEST_FIXED_HEADER_LEN + TAG_LEN;
                if buffer.len() < salt_len + fixed_len {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need={})",
                        user.id(),
                        user.cipher.as_str(),
                        buffer.len(),
                        salt_len + fixed_len
                    );
                }
                let salt = &buffer[..salt_len];
                let mut candidate = buffer[salt_len..salt_len + fixed_len].to_vec();
                let session_key = match derive_subkey(user.cipher, &user.master_key, salt) {
                    Ok(key) => key,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher.as_str(),
                            error
                        );
                    }
                };
                let algorithm = cipher_algorithm(user.cipher);
                let key = match UnboundKey::new(algorithm, &session_key) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher.as_str());
                    }
                };
                let less_safe = LessSafeKey::new(key);
                match less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(header) if header.len() == SS2022_REQUEST_FIXED_HEADER_LEN => {
                        match validate_ss2022_request_fixed_header(header) {
                            Ok(header_len) => format!(
                                "{}:{} header_ok(header_len={})",
                                user.id(),
                                user.cipher.as_str(),
                                header_len
                            ),
                            Err(error) => format!(
                                "{}:{} header_invalid({})",
                                user.id(),
                                user.cipher.as_str(),
                                error
                            ),
                        }
                    }
                    Ok(header) => format!(
                        "{}:{} invalid_header_len({})",
                        user.id(),
                        user.cipher.as_str(),
                        header.len()
                    ),
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher.as_str()),
                }
            } else {
                let salt_len = user.cipher.salt_len();
                if buffer.len() < salt_len {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need_salt={})",
                        user.id(),
                        user.cipher.as_str(),
                        buffer.len(),
                        salt_len
                    );
                }
                if buffer.len() < salt_len + 2 + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(buffer={}, need_header={})",
                        user.id(),
                        user.cipher.as_str(),
                        buffer.len(),
                        salt_len + 2 + TAG_LEN
                    );
                }

                let salt = &buffer[..salt_len];
                let encrypted_len = &buffer[salt_len..salt_len + 2 + TAG_LEN];
                let session_key = match derive_subkey(user.cipher, &user.master_key, salt) {
                    Ok(key) => key,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher.as_str(),
                            error
                        );
                    }
                };
                let algorithm = cipher_algorithm(user.cipher);
                let key = match UnboundKey::new(algorithm, &session_key) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher.as_str());
                    }
                };
                let less_safe = LessSafeKey::new(key);
                let mut candidate = encrypted_len.to_vec();
                match less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(plaintext_len) if plaintext_len.len() == 2 => {
                        let chunk_len =
                            u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                        if chunk_len <= LEGACY_MAX_CHUNK_SIZE {
                            format!(
                                "{}:{} header_ok(chunk_len={})",
                                user.id(),
                                user.cipher.as_str(),
                                chunk_len
                            )
                        } else {
                            format!(
                                "{}:{} invalid_chunk_len({})",
                                user.id(),
                                user.cipher.as_str(),
                                chunk_len
                            )
                        }
                    }
                    Ok(plaintext_len) => format!(
                        "{}:{} invalid_header_len({})",
                        user.id(),
                        user.cipher.as_str(),
                        plaintext_len.len()
                    ),
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher.as_str()),
                }
            }
        })
        .collect()
}

pub fn diagnose_udp_packet(users: &[UserKey], packet: &[u8]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            if user.cipher == CipherKind::Chacha20Poly13052022 {
                if packet.len() < XNONCE_LEN + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher.as_str(),
                        packet.len(),
                        XNONCE_LEN + TAG_LEN
                    );
                }
                let (nonce, ciphertext) = packet.split_at(XNONCE_LEN);
                let cipher = match XChaCha20Poly1305::new_from_slice(&user.master_key) {
                    Ok(cipher) => cipher,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher.as_str());
                    }
                };
                let mut candidate = ciphertext.to_vec();
                match cipher.decrypt_in_place(XNonce::from_slice(nonce), b"", &mut candidate) {
                    Ok(()) => match parse_ss2022_chacha_udp_request_body(&candidate) {
                        Ok((plaintext, _)) => format!(
                            "{}:{} packet_ok(payload_len={})",
                            user.id(),
                            user.cipher.as_str(),
                            plaintext.len()
                        ),
                        Err(error) => format!(
                            "{}:{} header_invalid({})",
                            user.id(),
                            user.cipher.as_str(),
                            error
                        ),
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher.as_str()),
                }
            } else if user.cipher.is_2022_aes() {
                if packet.len() < SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher.as_str(),
                        packet.len(),
                        SS2022_UDP_SEPARATE_HEADER_LEN + TAG_LEN
                    );
                }
                let (encrypted_header, ciphertext) =
                    packet.split_at(SS2022_UDP_SEPARATE_HEADER_LEN);
                let separate_header = match decrypt_ss2022_separate_header(user, encrypted_header) {
                    Ok(header) => header,
                    Err(_) => {
                        return format!(
                            "{}:{} separate_header_auth_failed",
                            user.id(),
                            user.cipher.as_str()
                        );
                    }
                };
                let session_key =
                    match derive_subkey(user.cipher, &user.master_key, &separate_header[..8]) {
                        Ok(key) => key,
                        Err(error) => {
                            return format!(
                                "{}:{} subkey_error({})",
                                user.id(),
                                user.cipher.as_str(),
                                error
                            );
                        }
                    };
                let algorithm = cipher_algorithm(user.cipher);
                let key = match UnboundKey::new(algorithm, &session_key) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher.as_str());
                    }
                };
                let less_safe = LessSafeKey::new(key);
                let mut candidate = ciphertext.to_vec();
                match less_safe.open_in_place(
                    ss2022_udp_nonce(&separate_header).unwrap_or_else(|_| udp_nonce_zero()),
                    Aad::empty(),
                    &mut candidate,
                ) {
                    Ok(body) => match parse_ss2022_udp_request_body(body) {
                        Ok(plaintext) => format!(
                            "{}:{} packet_ok(payload_len={})",
                            user.id(),
                            user.cipher.as_str(),
                            plaintext.len()
                        ),
                        Err(error) => format!(
                            "{}:{} header_invalid({})",
                            user.id(),
                            user.cipher.as_str(),
                            error
                        ),
                    },
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher.as_str()),
                }
            } else {
                let salt_len = user.cipher.salt_len();
                if packet.len() < salt_len + TAG_LEN {
                    return format!(
                        "{}:{} insufficient_data(packet={}, need={})",
                        user.id(),
                        user.cipher.as_str(),
                        packet.len(),
                        salt_len + TAG_LEN
                    );
                }

                let (salt, ciphertext) = packet.split_at(salt_len);
                let session_key = match derive_subkey(user.cipher, &user.master_key, salt) {
                    Ok(key) => key,
                    Err(error) => {
                        return format!(
                            "{}:{} subkey_error({})",
                            user.id(),
                            user.cipher.as_str(),
                            error
                        );
                    }
                };
                let algorithm = cipher_algorithm(user.cipher);
                let key = match UnboundKey::new(algorithm, &session_key) {
                    Ok(key) => key,
                    Err(_) => {
                        return format!("{}:{} key_init_failed", user.id(), user.cipher.as_str());
                    }
                };
                let less_safe = LessSafeKey::new(key);
                let mut candidate = ciphertext.to_vec();
                match less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate) {
                    Ok(plaintext) => format!(
                        "{}:{} packet_ok(payload_len={})",
                        user.id(),
                        user.cipher.as_str(),
                        plaintext.len()
                    ),
                    Err(_) => format!("{}:{} auth_failed", user.id(), user.cipher.as_str()),
                }
            }
        })
        .collect()
}

fn password_to_master_key(password: &str, cipher: CipherKind) -> Result<Vec<u8>, CryptoError> {
    if cipher.is_2022() {
        let key = STANDARD
            .decode(password.as_bytes())
            .map_err(|_| CryptoError::InvalidBase64Key)?;
        if key.len() != cipher.key_len() {
            return Err(CryptoError::InvalidPskLength {
                cipher: cipher.as_str(),
                expected: cipher.key_len(),
                actual: key.len(),
            });
        }
        Ok(key)
    } else {
        bytes_to_key(password.as_bytes(), cipher.key_len())
    }
}

fn pull_legacy_payload(
    buffer: &mut BytesMut,
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    pending_chunk_len: &mut Option<usize>,
    output: &mut Vec<u8>,
) -> Result<bool, CryptoError> {
    if pending_chunk_len.is_none() {
        if buffer.len() < 2 + TAG_LEN {
            return Ok(false);
        }

        let mut encrypted_len = buffer.split_to(2 + TAG_LEN);
        let nonce = next_stream_nonce(nonce_counter);
        let decrypted_len = key
            .open_in_place(nonce, Aad::empty(), &mut encrypted_len)
            .map_err(|_| CryptoError::InvalidLengthHeader)?;
        if decrypted_len.len() != 2 {
            return Err(CryptoError::InvalidLengthHeader);
        }

        let chunk_len = u16::from_be_bytes([decrypted_len[0], decrypted_len[1]]) as usize;
        if chunk_len > LEGACY_MAX_CHUNK_SIZE {
            return Err(CryptoError::InvalidChunkSize(chunk_len));
        }
        *pending_chunk_len = Some(chunk_len);
    }

    let chunk_len = pending_chunk_len.expect("set above");
    if buffer.len() < chunk_len + TAG_LEN {
        return Ok(false);
    }

    let mut encrypted_payload = buffer.split_to(chunk_len + TAG_LEN);
    let nonce = next_stream_nonce(nonce_counter);
    let decrypted_payload = key.open_in_place(nonce, Aad::empty(), &mut encrypted_payload)?;
    output.extend_from_slice(decrypted_payload);
    *pending_chunk_len = None;
    Ok(true)
}

fn pull_ss2022_payload(
    buffer: &mut BytesMut,
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    pending_chunk_len: &mut Option<usize>,
    output: &mut Vec<u8>,
) -> Result<bool, CryptoError> {
    if pending_chunk_len.is_none() {
        if buffer.len() < 2 + TAG_LEN {
            return Ok(false);
        }

        let mut encrypted_len = buffer.split_to(2 + TAG_LEN);
        let nonce = next_stream_nonce(nonce_counter);
        let decrypted_len = key
            .open_in_place(nonce, Aad::empty(), &mut encrypted_len)
            .map_err(|_| CryptoError::InvalidLengthHeader)?;
        if decrypted_len.len() != 2 {
            return Err(CryptoError::InvalidLengthHeader);
        }

        let chunk_len = u16::from_be_bytes([decrypted_len[0], decrypted_len[1]]) as usize;
        if chunk_len > MAX_CHUNK_SIZE {
            return Err(CryptoError::InvalidChunkSize(chunk_len));
        }
        *pending_chunk_len = Some(chunk_len);
    }

    let chunk_len = pending_chunk_len.expect("set above");
    if buffer.len() < chunk_len + TAG_LEN {
        return Ok(false);
    }

    let mut encrypted_payload = buffer.split_to(chunk_len + TAG_LEN);
    let nonce = next_stream_nonce(nonce_counter);
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
) -> Result<Vec<u8>, CryptoError> {
    let chunk_count = plaintext.len().div_ceil(LEGACY_MAX_CHUNK_SIZE).max(1);
    let mut output = Vec::with_capacity(
        (!*sent_salt as usize) * salt.len()
            + plaintext.len()
            + chunk_count * (2 + TAG_LEN + TAG_LEN),
    );

    for chunk in plaintext.chunks(LEGACY_MAX_CHUNK_SIZE) {
        output.extend_from_slice(&encrypt_legacy_chunk(
            key,
            nonce_counter,
            salt,
            sent_salt,
            chunk,
        )?);
    }

    Ok(output)
}

fn encrypt_legacy_chunk(
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    salt: &[u8],
    sent_salt: &mut bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > LEGACY_MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidChunkSize(plaintext.len()));
    }

    let salt_len = if *sent_salt { 0 } else { salt.len() };
    let mut output = Vec::with_capacity(salt_len + 2 + TAG_LEN + plaintext.len() + TAG_LEN);
    if !*sent_salt {
        output.extend_from_slice(salt);
        *sent_salt = true;
    }
    let length = u16::try_from(plaintext.len())
        .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
        .to_be_bytes();
    let mut encrypted_len = Vec::with_capacity(2 + TAG_LEN);
    encrypted_len.extend_from_slice(&length);
    key.seal_in_place_append_tag(
        next_stream_nonce(nonce_counter),
        Aad::empty(),
        &mut encrypted_len,
    )
    .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&encrypted_len);

    let mut encrypted_payload = plaintext.to_vec();
    key.seal_in_place_append_tag(
        next_stream_nonce(nonce_counter),
        Aad::empty(),
        &mut encrypted_payload,
    )
    .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&encrypted_payload);

    Ok(output)
}

fn encrypt_ss2022_chunk(
    key: &LessSafeKey,
    nonce_counter: &mut u64,
    salt: &[u8],
    sent_header: &mut bool,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidChunkSize(plaintext.len()));
    }

    let mut output = Vec::new();
    if !*sent_header {
        output.extend_from_slice(salt);
        let mut fixed_header = Vec::with_capacity(SS2022_RESPONSE_FIXED_HEADER_LEN + TAG_LEN);
        fixed_header.push(SS2022_TCP_RESPONSE_TYPE);
        fixed_header.extend_from_slice(&current_unix_secs().to_be_bytes());
        fixed_header.extend_from_slice(request_salt);
        fixed_header.extend_from_slice(
            &u16::try_from(plaintext.len())
                .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
                .to_be_bytes(),
        );
        key.seal_in_place_append_tag(
            next_stream_nonce(nonce_counter),
            Aad::empty(),
            &mut fixed_header,
        )
        .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(&fixed_header);

        let mut encrypted_payload = plaintext.to_vec();
        key.seal_in_place_append_tag(
            next_stream_nonce(nonce_counter),
            Aad::empty(),
            &mut encrypted_payload,
        )
        .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(&encrypted_payload);
        *sent_header = true;
        return Ok(output);
    }

    let mut encrypted_len = Vec::with_capacity(2 + TAG_LEN);
    encrypted_len.extend_from_slice(
        &u16::try_from(plaintext.len())
            .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
            .to_be_bytes(),
    );
    key.seal_in_place_append_tag(
        next_stream_nonce(nonce_counter),
        Aad::empty(),
        &mut encrypted_len,
    )
    .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&encrypted_len);

    let mut encrypted_payload = plaintext.to_vec();
    key.seal_in_place_append_tag(
        next_stream_nonce(nonce_counter),
        Aad::empty(),
        &mut encrypted_payload,
    )
    .map_err(|_| CryptoError::Cipher)?;
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

fn parse_ss2022_request_header(header: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let Some((target, consumed)) =
        parse_target_addr(header).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    if header.len() < consumed + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    let padding_len = u16::from_be_bytes([header[consumed], header[consumed + 1]]) as usize;
    if padding_len > SS2022_MAX_PADDING_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    if header.len() < consumed + 2 + padding_len {
        return Err(CryptoError::InvalidHeader);
    }

    let payload = &header[consumed + 2 + padding_len..];
    if padding_len == 0 && payload.is_empty() {
        return Err(CryptoError::InvalidHeader);
    }

    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_ss2022_udp_request_body(body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if body.len() < 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp = u64::from_be_bytes(
        body[1..9]
            .try_into()
            .map_err(|_| CryptoError::InvalidHeader)?,
    );
    validate_timestamp(timestamp)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(CryptoError::InvalidHeader);
    }

    let body = &body[padding_len..];
    let Some((target, consumed)) =
        parse_target_addr(body).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(&body[consumed..]);
    Ok(output)
}

fn parse_ss2022_chacha_udp_request_body(body: &[u8]) -> Result<(Vec<u8>, [u8; 8]), CryptoError> {
    if body.len() < 8 + 8 + 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    let client_session_id = body[..8]
        .try_into()
        .map_err(|_| CryptoError::InvalidHeader)?;
    let body = &body[16..];
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp = u64::from_be_bytes(
        body[1..9]
            .try_into()
            .map_err(|_| CryptoError::InvalidHeader)?,
    );
    validate_timestamp(timestamp)?;
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let body = &body[11..];
    if body.len() < padding_len {
        return Err(CryptoError::InvalidHeader);
    }
    let body = &body[padding_len..];
    let Some((target, consumed)) =
        parse_target_addr(body).map_err(|_| CryptoError::InvalidHeader)?
    else {
        return Err(CryptoError::InvalidHeader);
    };
    let mut output = target.encode().map_err(|_| CryptoError::InvalidHeader)?;
    output.extend_from_slice(&body[consumed..]);
    Ok((output, client_session_id))
}

fn validate_ss2022_request_fixed_header(header: &[u8]) -> Result<usize, CryptoError> {
    if header.len() != SS2022_REQUEST_FIXED_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    if header[0] != SS2022_TCP_REQUEST_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp = u64::from_be_bytes(
        header[1..9]
            .try_into()
            .map_err(|_| CryptoError::InvalidHeader)?,
    );
    validate_timestamp(timestamp)?;
    Ok(u16::from_be_bytes([header[9], header[10]]) as usize)
}

fn validate_timestamp(timestamp: u64) -> Result<(), CryptoError> {
    let now = current_unix_secs();
    if now.abs_diff(timestamp) > SS2022_MAX_TIME_DIFF_SECS {
        return Err(CryptoError::InvalidTimestamp);
    }
    Ok(())
}

fn bytes_to_key(password: &[u8], key_len: usize) -> Result<Vec<u8>, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }

    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut material = Vec::with_capacity(previous.len() + password.len());
        if !previous.is_empty() {
            material.extend_from_slice(&previous);
        }
        material.extend_from_slice(password);
        previous = Md5::digest(&material).to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    Ok(key)
}

fn derive_subkey(
    cipher: CipherKind,
    master_key: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if cipher.is_2022() {
        let mut material = Vec::with_capacity(master_key.len() + salt.len());
        material.extend_from_slice(master_key);
        material.extend_from_slice(salt);
        Ok(
            blake3::derive_key(SS2022_SUBKEY_CONTEXT, &material).as_slice()[..cipher.key_len()]
                .to_vec(),
        )
    } else {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let prk = salt.extract(master_key);
        let okm = prk
            .expand(&[SS_SUBKEY_INFO], HkdfLen(cipher.key_len()))
            .map_err(|_| CryptoError::KeyDerivation)?;
        let mut session_key = vec![0_u8; cipher.key_len()];
        okm.fill(&mut session_key)
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(session_key)
    }
}

fn cipher_algorithm(cipher: CipherKind) -> &'static aead::Algorithm {
    match cipher {
        CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => &aead::AES_128_GCM,
        CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => &aead::AES_256_GCM,
        CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
            &aead::CHACHA20_POLY1305
        }
    }
}

fn encrypt_ss2022_separate_header(
    user: &UserKey,
    separate_header: &[u8; SS2022_UDP_SEPARATE_HEADER_LEN],
) -> Result<[u8; SS2022_UDP_SEPARATE_HEADER_LEN], CryptoError> {
    let mut block = GenericArray::clone_from_slice(separate_header);
    match user.cipher {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(&user.master_key).map_err(|_| CryptoError::Cipher)?;
            cipher.encrypt_block(&mut block);
        }
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(&user.master_key).map_err(|_| CryptoError::Cipher)?;
            cipher.encrypt_block(&mut block);
        }
        _ => return Err(CryptoError::InvalidHeader),
    }
    let mut out = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}

fn decrypt_ss2022_separate_header(
    user: &UserKey,
    encrypted: &[u8],
) -> Result<[u8; SS2022_UDP_SEPARATE_HEADER_LEN], CryptoError> {
    let mut block = GenericArray::clone_from_slice(encrypted);
    match user.cipher {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(&user.master_key).map_err(|_| CryptoError::Cipher)?;
            cipher.decrypt_block(&mut block);
        }
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(&user.master_key).map_err(|_| CryptoError::Cipher)?;
            cipher.decrypt_block(&mut block);
        }
        _ => return Err(CryptoError::InvalidHeader),
    }
    let mut out = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}

fn next_stream_nonce(counter: &mut u64) -> Nonce {
    let current = *counter;
    *counter = counter.saturating_add(1);

    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&current.to_le_bytes());
    Nonce::assume_unique_for_key(nonce)
}

fn udp_nonce_zero() -> Nonce {
    Nonce::assume_unique_for_key([0_u8; NONCE_LEN])
}

fn ss2022_udp_nonce(separate_header: &[u8]) -> Result<Nonce, CryptoError> {
    if separate_header.len() != SS2022_UDP_SEPARATE_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&separate_header[4..16]);
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

trait BytesMutAdvance {
    fn advance(&mut self, count: usize);
}

impl BytesMutAdvance for BytesMut {
    fn advance(&mut self, count: usize) {
        let _ = self.split_to(count);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use ring::aead::{Aad, LessSafeKey, UnboundKey};

    use super::{
        AeadStreamDecryptor, AeadStreamEncryptor, UdpSession, UserKey, decrypt_udp_packet,
        decrypt_udp_packet_with_hint, encrypt_udp_packet, encrypt_udp_packet_for_response,
    };
    use crate::{config::CipherKind, protocol::TargetAddr};

    fn users(cipher: CipherKind, password_a: &str, password_b: &str) -> Arc<[UserKey]> {
        Arc::from(
            vec![
                UserKey::new("alice", password_a, Some(1001), cipher, "/tcp", "/udp").unwrap(),
                UserKey::new("bob", password_b, Some(1002), cipher, "/tcp", "/udp").unwrap(),
            ]
            .into_boxed_slice(),
        )
    }

    #[test]
    fn roundtrip_chacha20_stream() {
        let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
        let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"hello over websocket").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users.clone());
        decryptor.push(&ciphertext);
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
        assert_eq!(plaintext, b"hello over websocket");
    }

    #[test]
    fn decryptor_handles_fragmented_frames() {
        let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
        let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"fragmented").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        for chunk in ciphertext.chunks(3) {
            decryptor.push(chunk);
        }
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
        assert_eq!(plaintext, b"fragmented");
    }

    #[test]
    fn roundtrip_aes128_stream() {
        let users = users(CipherKind::Aes128Gcm, "secret-a", "secret-b");
        let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"aes128").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        decryptor.push(&ciphertext);
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
        assert_eq!(plaintext, b"aes128");
    }

    #[test]
    fn legacy_stream_encryptor_splits_large_responses() {
        let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
        let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
        let plaintext = vec![0x5a; super::LEGACY_MAX_CHUNK_SIZE + 10_000];
        let ciphertext = encryptor.encrypt_chunk(&plaintext).unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        decryptor.push(&ciphertext);
        let mut decrypted = Vec::new();
        decryptor.pull_plaintext(&mut decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_udp_packet() {
        let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
        let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
        let packet = decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();

        assert_eq!(packet.user.id(), "bob");
        assert_eq!(packet.payload, b"udp payload");
        assert_eq!(packet.session, UdpSession::Legacy);
    }

    #[test]
    fn hinted_udp_packet_decrypt_falls_back_to_matching_user() {
        let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
        let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
        let (packet, user_index) =
            decrypt_udp_packet_with_hint(users.as_ref(), &ciphertext, Some(0)).unwrap();

        assert_eq!(user_index, 1);
        assert_eq!(packet.user.id(), "bob");
        assert_eq!(packet.payload, b"udp payload");
        assert_eq!(packet.session, UdpSession::Legacy);
    }

    #[test]
    fn decryptor_matches_user_with_different_cipher() {
        let users: Arc<[UserKey]> = Arc::from(
            vec![
                UserKey::new(
                    "alice",
                    "secret-a",
                    Some(1001),
                    CipherKind::Aes256Gcm,
                    "/alice",
                    "/alice-udp",
                )
                .unwrap(),
                UserKey::new(
                    "bob",
                    "secret-b",
                    Some(1002),
                    CipherKind::Chacha20IetfPoly1305,
                    "/bob",
                    "/bob-udp",
                )
                .unwrap(),
            ]
            .into_boxed_slice(),
        );
        let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"mixed cipher").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        decryptor.push(&ciphertext);
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
        assert_eq!(plaintext, b"mixed cipher");
    }

    #[test]
    fn roundtrip_ss2022_tcp_stream() {
        let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
        let users = users(CipherKind::Aes128Gcm2022, psk, psk);
        let request_salt = [7_u8; 16];
        let target = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)));
        let target_bytes = target.encode().unwrap();
        let mut request = Vec::new();
        request.extend_from_slice(&request_salt);

        let session_key = super::derive_subkey(
            CipherKind::Aes128Gcm2022,
            &users[0].master_key,
            &request_salt,
        )
        .unwrap();
        let key = LessSafeKey::new(
            UnboundKey::new(
                super::cipher_algorithm(CipherKind::Aes128Gcm2022),
                &session_key,
            )
            .unwrap(),
        );
        let mut nonce_counter = 0;

        let mut fixed_header = Vec::from([super::SS2022_TCP_REQUEST_TYPE]);
        fixed_header.extend_from_slice(&super::current_unix_secs().to_be_bytes());
        fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
        let mut fixed_ct = fixed_header.clone();
        key.seal_in_place_append_tag(
            super::next_stream_nonce(&mut nonce_counter),
            Aad::empty(),
            &mut fixed_ct,
        )
        .unwrap();
        request.extend_from_slice(&fixed_ct);

        let mut var_header = target_bytes.clone();
        var_header.extend_from_slice(&1_u16.to_be_bytes());
        var_header.push(0xaa);
        let mut var_ct = var_header.clone();
        key.seal_in_place_append_tag(
            super::next_stream_nonce(&mut nonce_counter),
            Aad::empty(),
            &mut var_ct,
        )
        .unwrap();
        request.extend_from_slice(&var_ct);

        let mut decryptor = AeadStreamDecryptor::new(users.clone());
        decryptor.push(&request);
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();
        assert_eq!(plaintext, target_bytes);

        let context = decryptor.response_context();
        let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
        let response = encryptor.encrypt_chunk(b"pong").unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn roundtrip_ss2022_chacha_tcp_stream() {
        let psk = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let users = users(CipherKind::Chacha20Poly13052022, psk, psk);
        let request_salt = [9_u8; 32];
        let target = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)));
        let target_bytes = target.encode().unwrap();
        let mut request = Vec::new();
        request.extend_from_slice(&request_salt);

        let session_key = super::derive_subkey(
            CipherKind::Chacha20Poly13052022,
            &users[0].master_key,
            &request_salt,
        )
        .unwrap();
        let key = LessSafeKey::new(
            UnboundKey::new(
                super::cipher_algorithm(CipherKind::Chacha20Poly13052022),
                &session_key,
            )
            .unwrap(),
        );
        let mut nonce_counter = 0;

        let mut fixed_header = vec![super::SS2022_TCP_REQUEST_TYPE];
        fixed_header.extend_from_slice(&super::current_unix_secs().to_be_bytes());
        fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
        let mut fixed_ct = fixed_header.clone();
        key.seal_in_place_append_tag(
            super::next_stream_nonce(&mut nonce_counter),
            Aad::empty(),
            &mut fixed_ct,
        )
        .unwrap();
        request.extend_from_slice(&fixed_ct);

        let mut var_header = target_bytes.clone();
        var_header.extend_from_slice(&1_u16.to_be_bytes());
        var_header.push(0xbb);
        let mut var_ct = var_header.clone();
        key.seal_in_place_append_tag(
            super::next_stream_nonce(&mut nonce_counter),
            Aad::empty(),
            &mut var_ct,
        )
        .unwrap();
        request.extend_from_slice(&var_ct);

        let mut decryptor = AeadStreamDecryptor::new(users.clone());
        decryptor.push(&request);
        let mut plaintext = Vec::new();
        decryptor.pull_plaintext(&mut plaintext).unwrap();
        assert_eq!(plaintext, target_bytes);

        let context = decryptor.response_context();
        let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
        let response = encryptor.encrypt_chunk(b"pong").unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn encrypts_ss2022_udp_response() {
        let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
        let user = UserKey::new(
            "alice",
            psk,
            None,
            CipherKind::Aes128Gcm2022,
            "/tcp",
            "/udp",
        )
        .unwrap();
        let packet = encrypt_udp_packet_for_response(
            &user,
            &TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53))),
            b"dns",
            &UdpSession::Aes2022 {
                client_session_id: [1; 8],
            },
            Some([2; 8]),
            0,
        )
        .unwrap();
        assert!(packet.len() > 16);
    }

    #[test]
    fn encrypts_ss2022_chacha_udp_response() {
        let psk = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let user = UserKey::new(
            "alice",
            psk,
            None,
            CipherKind::Chacha20Poly13052022,
            "/tcp",
            "/udp",
        )
        .unwrap();
        let packet = encrypt_udp_packet_for_response(
            &user,
            &TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 0, 0, 1), 5353))),
            b"mdns",
            &UdpSession::Chacha2022 {
                client_session_id: [3; 8],
            },
            Some([4; 8]),
            0,
        )
        .unwrap();
        assert!(packet.len() > super::XNONCE_LEN);
    }

    #[test]
    fn rejects_bad_ss2022_psk_length() {
        let error = UserKey::new(
            "alice",
            "c2hvcnQ=",
            None,
            CipherKind::Aes256Gcm2022,
            "/tcp",
            "/udp",
        )
        .unwrap_err();
        assert!(matches!(error, super::CryptoError::InvalidPskLength { .. }));
    }
}
