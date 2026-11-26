use aws_lc_rs::aead::{
    AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
};

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};
use crate::keys::derive_subkey;

pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_NONCE_LEN: usize = 12;
pub const SHADOWSOCKS_XNONCE_LEN: usize = 24;
pub const LEGACY_MAX_PAYLOAD_LEN: usize = 0x3fff;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;
/// Maximum number of AEAD calls allowed per stream key (NIST SP 800-38D).
pub const MAX_STREAM_NONCE_COUNTER: u64 = 1 << 32;

const CIPHER_CHACHA: &str = "chacha20-poly1305";
const CIPHER_AES_128: &str = "aes-128-gcm";
const CIPHER_AES_256: &str = "aes-256-gcm";

/// A pre-initialised AEAD cipher instance backed by `aws-lc-rs`.
///
/// Constructing a [`LessSafeKey`] performs the per-key setup once per session
/// so reusing the instance across frames avoids repeating key expansion on the
/// hot path.
pub struct AeadCipher {
    key: LessSafeKey,
    cipher_name: &'static str,
}

impl AeadCipher {
    pub fn new(cipher: CipherKind, key: &[u8]) -> Result<Self> {
        let (alg, cipher_name): (&'static Algorithm, &'static str) = match cipher {
            CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
                (&CHACHA20_POLY1305, CIPHER_CHACHA)
            },
            CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => (&AES_128_GCM, CIPHER_AES_128),
            CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => (&AES_256_GCM, CIPHER_AES_256),
        };
        let unbound = UnboundKey::new(alg, key)
            .map_err(|_| CryptoError::InvalidKey { cipher: cipher_name })?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            cipher_name,
        })
    }

    pub fn from_master_and_salt(
        cipher: CipherKind,
        master_key: &[u8],
        salt: &[u8],
    ) -> Result<Self> {
        let subkey = derive_subkey(cipher, master_key, salt)?;
        Self::new(cipher, &subkey[..cipher.key_len()])
    }

    pub fn seal_in_place_separate_tag(
        &self,
        nonce: &[u8; 12],
        in_out: &mut [u8],
    ) -> Result<[u8; SHADOWSOCKS_TAG_LEN]> {
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::empty(), in_out)
            .map_err(|_| CryptoError::EncryptFailed { cipher: self.cipher_name })?;
        let mut out = [0u8; SHADOWSOCKS_TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(payload.len() + SHADOWSOCKS_TAG_LEN);
        self.encrypt_into(nonce, payload, &mut buffer)?;
        Ok(buffer)
    }

    /// Encrypt `payload` in-place into `out`, appending ciphertext + tag.
    pub fn encrypt_into(&self, nonce: &[u8; 12], payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.reserve(payload.len() + SHADOWSOCKS_TAG_LEN);
        let start = out.len();
        out.extend_from_slice(payload);
        let tag = self.seal_in_place_separate_tag(nonce, &mut out[start..])?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = payload.to_vec();
        self.decrypt_in_place(nonce, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt `buf` (layout: `[ciphertext || tag]`) in place and return the
    /// plaintext length. Does NOT resize `buf` — the caller truncates its own
    /// container (works for `Vec`, `BytesMut`, or any `&mut [u8]` backing) once
    /// this returns. No new allocation.
    pub fn decrypt_detached_in_place(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<usize> {
        if buf.len() < SHADOWSOCKS_TAG_LEN {
            return Err(CryptoError::ShortCiphertext);
        }
        let plaintext = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), buf)
            .map_err(|_| CryptoError::DecryptFailed { cipher: self.cipher_name })?;
        Ok(plaintext.len())
    }

    /// Decrypt `buf` (layout: `[ciphertext || tag]`) in-place and truncate it to
    /// the plaintext length. On success no new allocation is made.
    pub fn decrypt_in_place(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> Result<()> {
        let plaintext_len = self.decrypt_detached_in_place(nonce, buf)?;
        buf.truncate(plaintext_len);
        Ok(())
    }

    /// Decrypt a fixed-length AEAD frame in place and verify its plaintext length.
    pub fn open_fixed_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        ciphertext: &'a mut [u8],
        expected_plaintext_len: usize,
    ) -> Result<&'a [u8]> {
        let plaintext = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), ciphertext)
            .map_err(|_| CryptoError::DecryptFailed { cipher: self.cipher_name })?;
        if plaintext.len() != expected_plaintext_len {
            return Err(CryptoError::InvalidHeaderLength);
        }
        Ok(plaintext)
    }
}

/// Little-endian 96-bit stream nonce capped at [`MAX_STREAM_NONCE_COUNTER`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamNonce(u64);

impl StreamNonce {
    pub const fn new() -> Self {
        Self(0)
    }

    pub const fn from_counter(counter: u64) -> Self {
        Self(counter)
    }

    pub const fn counter(&self) -> u64 {
        self.0
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<[u8; SHADOWSOCKS_NONCE_LEN]> {
        let current = self.0;
        if current >= MAX_STREAM_NONCE_COUNTER {
            return Err(CryptoError::NonceOverflow);
        }
        self.0 = current + 1;
        let mut nonce = [0u8; SHADOWSOCKS_NONCE_LEN];
        nonce[..8].copy_from_slice(&current.to_le_bytes());
        Ok(nonce)
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
