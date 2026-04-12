use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};

use crate::types::CipherKind;

pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;

pub fn encrypt(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut buffer = payload.to_vec();
    match cipher {
        CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).context("invalid chacha20 key")?;
            let tag = cipher
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("chacha20 encryption failed"))?;
            buffer.extend_from_slice(&tag);
        }
        CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => {
            let cipher = Aes128Gcm::new_from_slice(key).context("invalid aes-128-gcm key")?;
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("aes-128-gcm encryption failed"))?;
            buffer.extend_from_slice(&tag);
        }
        CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => {
            let cipher = Aes256Gcm::new_from_slice(key).context("invalid aes-256-gcm key")?;
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("aes-256-gcm encryption failed"))?;
            buffer.extend_from_slice(&tag);
        }
    }
    Ok(buffer)
}

pub fn decrypt(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() < SHADOWSOCKS_TAG_LEN {
        bail!("ciphertext is shorter than tag");
    }

    let split_at = payload.len() - SHADOWSOCKS_TAG_LEN;
    let mut buffer = payload[..split_at].to_vec();
    let tag = &payload[split_at..];

    match cipher {
        CipherKind::Chacha20IetfPoly1305 | CipherKind::Chacha20Poly13052022 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).context("invalid chacha20 key")?;
            cipher
                .decrypt_in_place_detached(
                    ChaNonce::from_slice(nonce),
                    b"",
                    &mut buffer,
                    tag.into(),
                )
                .map_err(|_| anyhow!("chacha20 decryption failed"))?;
        }
        CipherKind::Aes128Gcm | CipherKind::Aes128Gcm2022 => {
            let cipher = Aes128Gcm::new_from_slice(key).context("invalid aes-128-gcm key")?;
            cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(nonce),
                    b"",
                    &mut buffer,
                    tag.into(),
                )
                .map_err(|_| anyhow!("aes-128-gcm decryption failed"))?;
        }
        CipherKind::Aes256Gcm | CipherKind::Aes256Gcm2022 => {
            let cipher = Aes256Gcm::new_from_slice(key).context("invalid aes-256-gcm key")?;
            cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(nonce),
                    b"",
                    &mut buffer,
                    tag.into(),
                )
                .map_err(|_| anyhow!("aes-256-gcm decryption failed"))?;
        }
    }
    Ok(buffer)
}

pub fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}
