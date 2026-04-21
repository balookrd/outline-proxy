use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};

pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;

const CIPHER_CHACHA: &str = "chacha20-poly1305";
const CIPHER_AES_128: &str = "aes-128-gcm";
const CIPHER_AES_256: &str = "aes-256-gcm";

/// A pre-initialised AEAD cipher instance.
///
/// Constructing an `Aes128Gcm` / `Aes256Gcm` / `ChaCha20Poly1305` from a key
/// performs the per-key setup (AES key expansion, etc.). Doing that once per
/// session and then reusing the instance for every chunk avoids the setup
/// cost on the hot path — `TcpShadowsocksWriter::send_payload_frame` encrypts
/// twice per frame (length block + payload), so an active session performs
/// this key setup thousands of times over its lifetime without an instance
/// cache.
pub enum AeadCipher {
    Chacha(Box<ChaCha20Poly1305>),
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl AeadCipher {
    pub fn new(cipher: CipherKind, key: &[u8]) -> Result<Self> {
        match cipher {
            CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .map(|c| Self::Chacha(Box::new(c)))
                    .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_CHACHA })
            },
            CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => Aes128Gcm::new_from_slice(key)
                .map(|c| Self::Aes128(Box::new(c)))
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_128 }),
            CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => Aes256Gcm::new_from_slice(key)
                .map(|c| Self::Aes256(Box::new(c)))
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_256 }),
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = payload.to_vec();
        let tag = match self {
            Self::Chacha(c) => c
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_CHACHA })?,
            Self::Aes128(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_AES_128 })?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_AES_256 })?,
        };
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    /// Encrypt `payload` in-place into `out`, appending ciphertext + tag.
    pub fn encrypt_into(&self, nonce: &[u8; 12], payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(payload);
        let tag = match self {
            Self::Chacha(c) => c
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut out[start..])
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_CHACHA })?,
            Self::Aes128(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut out[start..])
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_AES_128 })?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut out[start..])
                .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_AES_256 })?,
        };
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = payload.to_vec();
        self.decrypt_in_place(nonce, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt `buf` (layout: `[ciphertext || tag]`) in-place.
    /// On success `buf` is truncated to the plaintext length; no new allocation.
    pub fn decrypt_in_place(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < SHADOWSOCKS_TAG_LEN {
            return Err(CryptoError::ShortCiphertext);
        }
        let split_at = buf.len() - SHADOWSOCKS_TAG_LEN;
        // Copy the tag to the stack before taking &mut buf[..split_at].
        let mut tag_arr = [0u8; SHADOWSOCKS_TAG_LEN];
        tag_arr.copy_from_slice(&buf[split_at..]);
        let tag: &[u8] = &tag_arr;
        match self {
            Self::Chacha(c) => c
                .decrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buf[..split_at], tag.into())
                .map_err(|_| CryptoError::DecryptFailed { cipher: CIPHER_CHACHA })?,
            Self::Aes128(c) => c
                .decrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buf[..split_at], tag.into())
                .map_err(|_| CryptoError::DecryptFailed { cipher: CIPHER_AES_128 })?,
            Self::Aes256(c) => c
                .decrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buf[..split_at], tag.into())
                .map_err(|_| CryptoError::DecryptFailed { cipher: CIPHER_AES_256 })?,
        };
        buf.truncate(split_at);
        Ok(())
    }
}

/// One-shot encrypt — constructs a fresh [`AeadCipher`] for every call.
/// Prefer [`AeadCipher::new`] + [`AeadCipher::encrypt`] on the hot path so the
/// per-key setup is amortised across many frames; this helper is kept for
/// call sites where a session cipher would add no benefit (UDP packets that
/// use a per-datagram key).
pub fn encrypt(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<Vec<u8>> {
    AeadCipher::new(cipher, key)?.encrypt(nonce, payload)
}

pub fn decrypt(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<Vec<u8>> {
    AeadCipher::new(cipher, key)?.decrypt(nonce, payload)
}

pub fn encrypt_into(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    AeadCipher::new(cipher, key)?.encrypt_into(nonce, payload, out)
}

/// Increments the AEAD nonce by 1 (little-endian, as required by Shadowsocks).
///
/// Returns `Err` if all 96 bits carry over and the nonce wraps back to all-zeros.
/// Reusing the same `(key, nonce)` pair would break AEAD confidentiality, so the
/// caller must treat this as a fatal error and close the connection.
///
/// In practice a 96-bit nonce requires 2^96 encrypt/decrypt operations to overflow
/// within a single TCP stream — this branch should never be reached.
pub fn increment_nonce(nonce: &mut [u8; 12]) -> Result<()> {
    for byte in nonce.iter_mut() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return Ok(());
        }
    }
    Err(CryptoError::NonceOverflow)
}
