use std::{fmt, sync::Arc};

use bytes::BytesMut;
use md5::{Digest as _, Md5};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use thiserror::Error;

use crate::config::CipherKind;

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
pub const MAX_CHUNK_SIZE: usize = 0x3fff;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("failed to derive session key")]
    KeyDerivation,
    #[error("unsupported chunk size {0}")]
    InvalidChunkSize(usize),
    #[error("invalid encrypted length header")]
    InvalidLengthHeader,
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
            master_key: bytes_to_key(password.as_bytes(), cipher.key_len())?,
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

pub struct AeadStreamDecryptor {
    users: Arc<[UserKey]>,
    buffer: BytesMut,
    active_user: Option<UserKey>,
    key: Option<LessSafeKey>,
    nonce_counter: u64,
    pending_chunk_len: Option<usize>,
}

impl fmt::Debug for AeadStreamDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadStreamDecryptor")
            .field("buffer_len", &self.buffer.len())
            .field("active_user", &self.active_user.as_ref().map(UserKey::id))
            .field("has_key", &self.key.is_some())
            .field("nonce_counter", &self.nonce_counter)
            .field("pending_chunk_len", &self.pending_chunk_len)
            .finish()
    }
}

impl AeadStreamDecryptor {
    pub fn new(users: Arc<[UserKey]>) -> Self {
        Self {
            users,
            buffer: BytesMut::new(),
            active_user: None,
            key: None,
            nonce_counter: 0,
            pending_chunk_len: None,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn user(&self) -> Option<&UserKey> {
        self.active_user.as_ref()
    }

    pub fn buffered_data(&self) -> &[u8] {
        &self.buffer
    }

    pub fn pull_plaintext(&mut self) -> Result<Vec<Vec<u8>>, CryptoError> {
        self.ensure_session_key()?;

        let mut plaintext_chunks = Vec::new();
        loop {
            let Some(key) = &self.key else {
                break;
            };

            if self.pending_chunk_len.is_none() {
                if self.buffer.len() < 2 + TAG_LEN {
                    break;
                }

                let mut encrypted_len = self.buffer.split_to(2 + TAG_LEN).to_vec();
                let nonce = next_stream_nonce(&mut self.nonce_counter);
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
                self.pending_chunk_len = Some(chunk_len);
            }

            let chunk_len = self.pending_chunk_len.expect("set above");
            if self.buffer.len() < chunk_len + TAG_LEN {
                break;
            }

            let mut encrypted_payload = self.buffer.split_to(chunk_len + TAG_LEN).to_vec();
            let nonce = next_stream_nonce(&mut self.nonce_counter);
            let decrypted_payload =
                key.open_in_place(nonce, Aad::empty(), &mut encrypted_payload)?;
            plaintext_chunks.push(decrypted_payload.to_vec());
            self.pending_chunk_len = None;
        }

        Ok(plaintext_chunks)
    }

    fn ensure_session_key(&mut self) -> Result<(), CryptoError> {
        if self.key.is_some() {
            return Ok(());
        }

        for user in self.users.iter() {
            let salt_len = user.cipher.salt_len();
            if self.buffer.len() < salt_len + 2 + TAG_LEN {
                continue;
            }

            let salt = &self.buffer[..salt_len];
            let encrypted_len = &self.buffer[salt_len..salt_len + 2 + TAG_LEN];
            let session_key = derive_subkey(user.cipher, &user.master_key, salt)?;
            let algorithm = cipher_algorithm(user.cipher);
            let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
            let less_safe = LessSafeKey::new(key);

            let mut candidate = encrypted_len.to_vec();
            if let Ok(plaintext_len) =
                less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate)
            {
                if plaintext_len.len() == 2 {
                    let chunk_len =
                        u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]) as usize;
                    if chunk_len <= MAX_CHUNK_SIZE {
                        self.buffer.advance(salt_len);
                        self.active_user = Some(user.clone());
                        self.key = Some(less_safe);
                        return Ok(());
                    }
                }
            }
        }

        Err(CryptoError::UnknownUser)
    }
}

pub struct AeadStreamEncryptor {
    key: LessSafeKey,
    nonce_counter: u64,
    salt: Vec<u8>,
    sent_salt: bool,
}

impl fmt::Debug for AeadStreamEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadStreamEncryptor")
            .field("nonce_counter", &self.nonce_counter)
            .field("sent_salt", &self.sent_salt)
            .finish()
    }
}

impl AeadStreamEncryptor {
    pub fn new(user: &UserKey) -> Result<Self, CryptoError> {
        let mut salt = vec![0_u8; user.cipher.salt_len()];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| CryptoError::Random)?;
        let session_key = derive_subkey(user.cipher, &user.master_key, &salt)?;
        let algorithm = cipher_algorithm(user.cipher);
        let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;

        Ok(Self {
            key: LessSafeKey::new(key),
            nonce_counter: 0,
            salt,
            sent_salt: false,
        })
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_CHUNK_SIZE {
            return Err(CryptoError::InvalidChunkSize(plaintext.len()));
        }

        let mut output = Vec::new();
        if !self.sent_salt {
            output.extend_from_slice(&self.salt);
            self.sent_salt = true;
        }

        let length = u16::try_from(plaintext.len())
            .map_err(|_| CryptoError::InvalidChunkSize(plaintext.len()))?
            .to_be_bytes();
        let mut encrypted_len = length.to_vec();
        self.key
            .seal_in_place_append_tag(
                next_stream_nonce(&mut self.nonce_counter),
                Aad::empty(),
                &mut encrypted_len,
            )
            .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(&encrypted_len);

        let mut encrypted_payload = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                next_stream_nonce(&mut self.nonce_counter),
                Aad::empty(),
                &mut encrypted_payload,
            )
            .map_err(|_| CryptoError::Cipher)?;
        output.extend_from_slice(&encrypted_payload);

        Ok(output)
    }
}

pub struct UdpPacket {
    pub user: UserKey,
    pub payload: Vec<u8>,
}

pub fn decrypt_udp_packet(
    users: &[UserKey],
    packet: &[u8],
) -> Result<UdpPacket, CryptoError> {
    if users
        .iter()
        .map(|user| user.cipher.salt_len() + TAG_LEN)
        .min()
        .is_some_and(|min_len| packet.len() < min_len)
    {
        return Err(CryptoError::PacketTooShort);
    }

    for user in users {
        let salt_len = user.cipher.salt_len();
        if packet.len() < salt_len + TAG_LEN {
            continue;
        }

        let (salt, ciphertext) = packet.split_at(salt_len);
        let session_key = derive_subkey(user.cipher, &user.master_key, salt)?;
        let algorithm = cipher_algorithm(user.cipher);
        let key = UnboundKey::new(algorithm, &session_key).map_err(|_| CryptoError::Cipher)?;
        let less_safe = LessSafeKey::new(key);
        let mut candidate = ciphertext.to_vec();
        if let Ok(plaintext) =
            less_safe.open_in_place(udp_nonce_zero(), Aad::empty(), &mut candidate)
        {
            return Ok(UdpPacket {
                user: user.clone(),
                payload: plaintext.to_vec(),
            });
        }
    }

    Err(CryptoError::UnknownUser)
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

pub fn diagnose_stream_handshake(users: &[UserKey], buffer: &[u8]) -> Vec<String> {
    users.iter()
        .map(|user| {
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
                    if chunk_len <= MAX_CHUNK_SIZE {
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
        })
        .collect()
}

pub fn diagnose_udp_packet(users: &[UserKey], packet: &[u8]) -> Vec<String> {
    users.iter()
        .map(|user| {
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
        })
        .collect()
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

fn cipher_algorithm(cipher: CipherKind) -> &'static aead::Algorithm {
    match cipher {
        CipherKind::Aes256Gcm => &aead::AES_256_GCM,
        CipherKind::Chacha20IetfPoly1305 => &aead::CHACHA20_POLY1305,
    }
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
    use std::sync::Arc;

    use super::{
        AeadStreamDecryptor, AeadStreamEncryptor, UserKey, decrypt_udp_packet, encrypt_udp_packet,
    };
    use crate::config::CipherKind;

    fn users(cipher: CipherKind) -> Arc<[UserKey]> {
        Arc::from(
            vec![
                UserKey::new("alice", "secret-a", Some(1001), cipher, "/tcp", "/udp").unwrap(),
                UserKey::new("bob", "secret-b", Some(1002), cipher, "/tcp", "/udp").unwrap(),
            ]
            .into_boxed_slice(),
        )
    }

    #[test]
    fn roundtrip_chacha20_stream() {
        let users = users(CipherKind::Chacha20IetfPoly1305);
        let mut encryptor = AeadStreamEncryptor::new(&users[1]).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"hello over websocket").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users.clone());
        decryptor.push(&ciphertext);
        let plaintext = decryptor.pull_plaintext().unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
        assert_eq!(plaintext, vec![b"hello over websocket".to_vec()]);
    }

    #[test]
    fn decryptor_handles_fragmented_frames() {
        let users = users(CipherKind::Aes256Gcm);
        let mut encryptor = AeadStreamEncryptor::new(&users[0]).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"fragmented").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        for chunk in ciphertext.chunks(3) {
            decryptor.push(chunk);
        }
        let plaintext = decryptor.pull_plaintext().unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
        assert_eq!(plaintext, vec![b"fragmented".to_vec()]);
    }

    #[test]
    fn roundtrip_udp_packet() {
        let users = users(CipherKind::Aes256Gcm);
        let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
        let packet = decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();

        assert_eq!(packet.user.id(), "bob");
        assert_eq!(packet.payload, b"udp payload");
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
        let mut encryptor = AeadStreamEncryptor::new(&users[1]).unwrap();
        let ciphertext = encryptor.encrypt_chunk(b"mixed cipher").unwrap();

        let mut decryptor = AeadStreamDecryptor::new(users);
        decryptor.push(&ciphertext);
        let plaintext = decryptor.pull_plaintext().unwrap();

        assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
        assert_eq!(plaintext, vec![b"mixed cipher".to_vec()]);
    }
}
