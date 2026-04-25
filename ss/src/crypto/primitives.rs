use ring::{
    aead::{self, Nonce},
    hkdf,
};

use super::error::CryptoError;
use crate::config::CipherKind;

pub(super) const TAG_LEN: usize = 16;
pub(super) const NONCE_LEN: usize = 12;
pub(super) const XNONCE_LEN: usize = 24;
pub(super) const LEGACY_MAX_CHUNK_SIZE: usize = 0x3fff;
pub const MAX_CHUNK_SIZE: usize = 0xffff;
pub(super) const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub(super) const SS2022_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

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
        okm.fill(&mut out[..key_len])
            .map_err(|_| CryptoError::KeyDerivation)?;
    }
    Ok(key_len)
}

pub(super) fn build_session_key(
    cipher: CipherKind,
    master_key: &[u8],
    salt: &[u8],
) -> Result<aead::LessSafeKey, CryptoError> {
    let mut subkey = [0_u8; MAX_SUBKEY_LEN];
    let key_len = derive_subkey(cipher, master_key, salt, &mut subkey)?;
    let algorithm = cipher_algorithm(cipher);
    let unbound =
        aead::UnboundKey::new(algorithm, &subkey[..key_len]).map_err(|_| CryptoError::Cipher)?;
    Ok(aead::LessSafeKey::new(unbound))
}

/// AEAD-open a fixed-length header and require the plaintext length to match
/// `expected_plaintext_len`. Returns `Err(CryptoError::Cipher)` on auth failure
/// and `Err(CryptoError::InvalidHeader)` on length mismatch — diagnostic
/// callers distinguish these, production callers collapse both into "try next".
pub(super) fn try_open_fixed_header<'a>(
    key: &aead::LessSafeKey,
    nonce: aead::Nonce,
    ciphertext: &'a mut [u8],
    expected_plaintext_len: usize,
) -> Result<&'a [u8], CryptoError> {
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), ciphertext)
        .map_err(|_| CryptoError::Cipher)?;
    if plaintext.len() != expected_plaintext_len {
        return Err(CryptoError::InvalidHeader);
    }
    Ok(plaintext)
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

/// Per-key invocation limit for stream AEADs. Matches NIST SP 800-38D
/// guidance for AES-GCM (<2^32 invocations per key); the same bound is
/// applied uniformly to all supported ciphers to keep the session-rotation
/// logic symmetric.
pub(super) const MAX_NONCE_COUNTER: u64 = 1 << 32;

#[inline]
pub(super) fn next_stream_nonce(counter: &mut u64) -> Result<Nonce, CryptoError> {
    let current = *counter;
    if current >= MAX_NONCE_COUNTER {
        return Err(CryptoError::NonceExhausted);
    }
    *counter = current + 1;

    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&current.to_le_bytes());
    Ok(Nonce::assume_unique_for_key(nonce))
}

#[inline]
pub(super) fn nonce_zero() -> Nonce {
    Nonce::assume_unique_for_key([0_u8; NONCE_LEN])
}

pub(super) struct HkdfLen(pub(super) usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}
