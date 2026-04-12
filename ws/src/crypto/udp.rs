use anyhow::{Result, bail};
use rand::RngCore;

use crate::types::CipherKind;

use super::aead::{SHADOWSOCKS_TAG_LEN, decrypt, encrypt};
use super::keys::derive_subkey;
use super::ss2022_udp::{decrypt_udp_packet_2022, encrypt_udp_packet_2022};

const UDP_ZERO_NONCE: [u8; 12] = [0u8; 12];

pub fn encrypt_udp_packet(
    cipher: CipherKind,
    master_key: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if cipher.is_ss2022() {
        return encrypt_udp_packet_2022(cipher, master_key, rand::random::<u64>(), 0, payload);
    }
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
    if cipher.is_ss2022() {
        let (_, _, payload) = decrypt_udp_packet_2022(cipher, master_key, 0, packet)?;
        return Ok(payload);
    }
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + SHADOWSOCKS_TAG_LEN {
        bail!("UDP packet is too short");
    }
    let (salt, ciphertext) = packet.split_at(salt_len);
    let key = derive_subkey(cipher, master_key, salt)?;
    decrypt(cipher, &key, &UDP_ZERO_NONCE, ciphertext)
}
