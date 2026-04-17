use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use crate::cipher_kind::CipherKind;

pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;

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
    Chacha(ChaCha20Poly1305),
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AeadCipher {
    pub fn new(cipher: CipherKind, key: &[u8]) -> Result<Self> {
        match cipher {
            CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => Ok(
                Self::Chacha(ChaCha20Poly1305::new_from_slice(key).context("invalid chacha20 key")?),
            ),
            CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => Ok(Self::Aes128(
                Aes128Gcm::new_from_slice(key).context("invalid aes-128-gcm key")?,
            )),
            CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => Ok(Self::Aes256(
                Aes256Gcm::new_from_slice(key).context("invalid aes-256-gcm key")?,
            )),
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = payload.to_vec();
        let tag = match self {
            Self::Chacha(c) => c
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("chacha20 encryption failed"))?,
            Self::Aes128(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("aes-128-gcm encryption failed"))?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("aes-256-gcm encryption failed"))?,
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
                .map_err(|_| anyhow!("chacha20 encryption failed"))?,
            Self::Aes128(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut out[start..])
                .map_err(|_| anyhow!("aes-128-gcm encryption failed"))?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut out[start..])
                .map_err(|_| anyhow!("aes-256-gcm encryption failed"))?,
        };
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn decrypt(&self, nonce: &[u8; 12], payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < SHADOWSOCKS_TAG_LEN {
            bail!("ciphertext is shorter than tag");
        }
        let split_at = payload.len() - SHADOWSOCKS_TAG_LEN;
        let mut buffer = payload[..split_at].to_vec();
        let tag = &payload[split_at..];
        match self {
            Self::Chacha(c) => c
                .decrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buffer, tag.into())
                .map_err(|_| anyhow!("chacha20 decryption failed"))?,
            Self::Aes128(c) => c
                .decrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer, tag.into())
                .map_err(|_| anyhow!("aes-128-gcm decryption failed"))?,
            Self::Aes256(c) => c
                .decrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer, tag.into())
                .map_err(|_| anyhow!("aes-256-gcm decryption failed"))?,
        };
        Ok(buffer)
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
    bail!(
        "AEAD nonce overflow: nonce wrapped to zero — \
         close this connection to prevent (key, nonce) reuse"
    )
}
