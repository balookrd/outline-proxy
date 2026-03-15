use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha1::Sha1;

use crate::types::CipherKind;

pub const SHADOWSOCKS_INFO: &[u8] = b"ss-subkey";
pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0x3fff;
const UDP_ZERO_NONCE: [u8; 12] = [0u8; 12];

impl CipherKind {
    pub fn derive_master_key(self, password: &str) -> Vec<u8> {
        evp_bytes_to_key(password.as_bytes(), self.key_len())
    }
}

pub fn derive_subkey(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = vec![0u8; cipher.key_len()];
    hk.expand(SHADOWSOCKS_INFO, &mut subkey)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;
    Ok(subkey)
}

pub fn encrypt(
    cipher: CipherKind,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut buffer = payload.to_vec();
    match cipher {
        CipherKind::Chacha20IetfPoly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).context("invalid chacha20 key")?;
            let tag = cipher
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("chacha20 encryption failed"))?;
            buffer.extend_from_slice(&tag);
        }
        CipherKind::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).context("invalid aes-128-gcm key")?;
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), b"", &mut buffer)
                .map_err(|_| anyhow!("aes-128-gcm encryption failed"))?;
            buffer.extend_from_slice(&tag);
        }
        CipherKind::Aes256Gcm => {
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
        CipherKind::Chacha20IetfPoly1305 => {
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
        CipherKind::Aes128Gcm => {
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
        CipherKind::Aes256Gcm => {
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

pub fn encrypt_udp_packet(
    cipher: CipherKind,
    master_key: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let salt_len = cipher.salt_len();
    // Use a stack buffer (max salt size = max key size = 32 bytes) to avoid heap allocation
    let mut salt_buf = [0u8; 32];
    let salt = &mut salt_buf[..salt_len];
    rand::thread_rng().fill_bytes(salt);
    let key = derive_subkey(cipher, master_key, salt)?;
    let mut encrypted = encrypt(cipher, &key, &UDP_ZERO_NONCE, payload)?;
    let mut packet = Vec::with_capacity(salt_len + encrypted.len());
    packet.extend_from_slice(salt);
    packet.append(&mut encrypted);
    Ok(packet)
}

pub fn decrypt_udp_packet(cipher: CipherKind, master_key: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + SHADOWSOCKS_TAG_LEN {
        bail!("UDP packet is too short");
    }
    let (salt, ciphertext) = packet.split_at(salt_len);
    let key = derive_subkey(cipher, master_key, salt)?;
    decrypt(cipher, &key, &UDP_ZERO_NONCE, ciphertext)
}

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();

    while key.len() < key_len {
        let mut input = Vec::with_capacity(prev.len() + password.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(password);
        prev = md5::compute(input).0.to_vec();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_len);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_key_matches_known_vector() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(
            hex(&key),
            "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08"
        );
    }

    #[test]
    fn nonce_is_incremented_little_endian() {
        let mut nonce = [0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[0], 1);

        nonce[0] = 0xff;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
    }

    #[test]
    fn shadowsocks_udp_packet_round_trip() {
        let cipher = CipherKind::Chacha20IetfPoly1305;
        let master_key = cipher.derive_master_key("password");
        let packet = encrypt_udp_packet(cipher, &master_key, b"payload").unwrap();
        let payload = decrypt_udp_packet(cipher, &master_key, &packet).unwrap();
        assert_eq!(payload, b"payload");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
