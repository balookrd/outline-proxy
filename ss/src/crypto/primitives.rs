use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use ring::{
    aead::{self, Nonce},
    hkdf,
};

use super::error::CryptoError;
use crate::{config::CipherKind, protocol::parse_target_addr};

pub(super) const TAG_LEN: usize = 16;
pub(super) const NONCE_LEN: usize = 12;
pub(super) const XNONCE_LEN: usize = 24;
pub(super) const LEGACY_MAX_CHUNK_SIZE: usize = 0x3fff;
pub const MAX_CHUNK_SIZE: usize = 0xffff;
pub(super) const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub(super) const SS2022_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
pub(super) const SS2022_TCP_REQUEST_TYPE: u8 = 0;
pub(super) const SS2022_TCP_RESPONSE_TYPE: u8 = 1;
pub(super) const SS2022_UDP_CLIENT_TYPE: u8 = 0;
pub(super) const SS2022_UDP_SERVER_TYPE: u8 = 1;
pub(super) const SS2022_REQUEST_FIXED_HEADER_LEN: usize = 11;
pub(super) const SS2022_REQUEST_FIXED_CIPHERTEXT_LEN: usize =
    SS2022_REQUEST_FIXED_HEADER_LEN + TAG_LEN;
pub(super) const SS2022_UDP_SEPARATE_HEADER_LEN: usize = 16;
pub(super) const SS2022_MAX_PADDING_LEN: usize = 900;
pub(super) const SS2022_MAX_TIME_DIFF_SECS: u64 = 30;

pub(super) const MAX_SUBKEY_LEN: usize = 32;

pub(super) fn derive_subkey(
    cipher: CipherKind,
    master_key: &[u8],
    salt: &[u8],
    out: &mut [u8; MAX_SUBKEY_LEN],
) -> Result<usize, CryptoError> {
    let key_len = cipher.key_len();
    if cipher.is_2022() {
        let mut hasher = blake3::Hasher::new_derive_key(SS2022_SUBKEY_CONTEXT);
        hasher.update(master_key);
        hasher.update(salt);
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut out[..key_len]);
    } else {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let prk = salt.extract(master_key);
        let okm = prk
            .expand(&[SS_SUBKEY_INFO], HkdfLen(key_len))
            .map_err(|_| CryptoError::KeyDerivation)?;
        okm.fill(&mut out[..key_len]).map_err(|_| CryptoError::KeyDerivation)?;
    }
    Ok(key_len)
}

#[inline]
pub(super) fn cipher_algorithm(cipher: CipherKind) -> &'static aead::Algorithm {
    match cipher {
        CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => &aead::AES_128_GCM,
        CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => &aead::AES_256_GCM,
        CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
            &aead::CHACHA20_POLY1305
        },
    }
}

#[inline]
pub(super) fn next_stream_nonce(counter: &mut u64) -> Nonce {
    let current = *counter;
    *counter = counter.wrapping_add(1);

    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&current.to_le_bytes());
    Nonce::assume_unique_for_key(nonce)
}

#[inline]
pub(super) fn nonce_zero() -> Nonce {
    Nonce::assume_unique_for_key([0_u8; NONCE_LEN])
}

#[inline]
pub(super) fn ss2022_udp_nonce(separate_header: &[u8]) -> Result<Nonce, CryptoError> {
    if separate_header.len() != SS2022_UDP_SEPARATE_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&separate_header[4..16]);
    Ok(Nonce::assume_unique_for_key(nonce))
}

pub(super) fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn validate_timestamp(timestamp: u64) -> Result<(), CryptoError> {
    let now = current_unix_secs();
    if now.abs_diff(timestamp) > SS2022_MAX_TIME_DIFF_SECS {
        return Err(CryptoError::InvalidTimestamp);
    }
    Ok(())
}

pub(super) fn validate_ss2022_request_fixed_header(header: &[u8]) -> Result<usize, CryptoError> {
    if header.len() != SS2022_REQUEST_FIXED_HEADER_LEN {
        return Err(CryptoError::InvalidHeader);
    }
    if header[0] != SS2022_TCP_REQUEST_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(header[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
    validate_timestamp(timestamp)?;
    Ok(u16::from_be_bytes([header[9], header[10]]) as usize)
}

pub(super) fn parse_ss2022_request_header(header: &[u8]) -> Result<Vec<u8>, CryptoError> {
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

pub(super) fn parse_ss2022_udp_request_body(body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if body.len() < 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
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

pub(super) fn parse_ss2022_chacha_udp_request_body(
    body: &[u8],
) -> Result<(Vec<u8>, [u8; 8]), CryptoError> {
    if body.len() < 8 + 8 + 1 + 8 + 2 {
        return Err(CryptoError::InvalidHeader);
    }
    let client_session_id = body[..8].try_into().map_err(|_| CryptoError::InvalidHeader)?;
    let body = &body[16..];
    if body[0] != SS2022_UDP_CLIENT_TYPE {
        return Err(CryptoError::InvalidHeader);
    }
    let timestamp =
        u64::from_be_bytes(body[1..9].try_into().map_err(|_| CryptoError::InvalidHeader)?);
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

pub(super) struct HkdfLen(pub(super) usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub(super) trait BytesMutAdvance {
    fn advance(&mut self, count: usize);
}

impl BytesMutAdvance for BytesMut {
    fn advance(&mut self, count: usize) {
        let _ = self.split_to(count);
    }
}
