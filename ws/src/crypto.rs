use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChaNonce, XChaCha20Poly1305, XNonce as XChaNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::CipherKind;

pub const SHADOWSOCKS_INFO: &[u8] = b"ss-subkey";
pub const SHADOWSOCKS_2022_INFO: &str = "shadowsocks 2022 session subkey";
pub const SHADOWSOCKS_TAG_LEN: usize = 16;
pub const SHADOWSOCKS_MAX_PAYLOAD: usize = 0xffff;
const UDP_ZERO_NONCE: [u8; 12] = [0u8; 12];
const SS2022_UDP_CLIENT_PACKET: u8 = 0;
const SS2022_UDP_SERVER_PACKET: u8 = 1;

impl CipherKind {
    pub fn derive_master_key(self, password: &str) -> Result<Vec<u8>> {
        if self.is_ss2022() {
            let key = base64::engine::general_purpose::STANDARD
                .decode(password)
                .context("failed to decode ss2022 PSK as base64")?;
            if key.len() != self.key_len() {
                bail!(
                    "invalid ss2022 PSK length for {self}: expected {} bytes, got {}",
                    self.key_len(),
                    key.len()
                );
            }
            Ok(key)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }
}

pub fn derive_subkey(cipher: CipherKind, master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let mut subkey = vec![0u8; cipher.key_len()];
    if cipher.is_ss2022() {
        let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
        key_material.extend_from_slice(master_key);
        key_material.extend_from_slice(salt);
        let derived = blake3::derive_key(SHADOWSOCKS_2022_INFO, &key_material);
        subkey.copy_from_slice(&derived[..cipher.key_len()]);
    } else {
        let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
        hk.expand(SHADOWSOCKS_INFO, &mut subkey)
            .map_err(|_| anyhow!("HKDF expansion failed"))?;
    }
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

pub fn encrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022() {
        bail!("ss2022 UDP framing requires a 2022 cipher");
    }

    let plaintext = build_ss2022_udp_client_plaintext(cipher, session_id, packet_id, payload)?;
    if cipher.is_ss2022_chacha() {
        return encrypt_udp_packet_2022_chacha(cipher, master_key, &plaintext);
    }
    encrypt_udp_packet_2022_aes(cipher, master_key, session_id, packet_id, &plaintext)
}

fn encrypt_udp_packet_2022_aes(
    cipher: CipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut separate_header = [0u8; 16];
    separate_header[..8].copy_from_slice(&session_id.to_be_bytes());
    separate_header[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&separate_header[4..16]);

    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let mut encrypted_body = encrypt(cipher, &key, &nonce, plaintext)?;
    let encrypted_header = encrypt_udp_separate_header(cipher, master_key, &separate_header)?;

    let mut packet = Vec::with_capacity(16 + encrypted_body.len());
    packet.extend_from_slice(&encrypted_header);
    packet.append(&mut encrypted_body);
    Ok(packet)
}

pub fn decrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if !cipher.is_ss2022() {
        bail!("ss2022 UDP framing requires a 2022 cipher");
    }
    if cipher.is_ss2022_chacha() {
        return decrypt_udp_packet_2022_chacha(
            cipher,
            master_key,
            expected_client_session_id,
            packet,
        );
    }
    decrypt_udp_packet_2022_aes(cipher, master_key, expected_client_session_id, packet)
}

fn decrypt_udp_packet_2022_aes(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if packet.len() < 16 + SHADOWSOCKS_TAG_LEN {
        bail!("UDP packet is too short");
    }

    let mut encrypted_header = [0u8; 16];
    encrypted_header.copy_from_slice(&packet[..16]);
    let separate_header = decrypt_udp_separate_header(cipher, master_key, &encrypted_header)?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&separate_header[4..16]);
    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let plaintext = decrypt(cipher, &key, &nonce, &packet[16..])?;

    let session_id = u64::from_be_bytes(separate_header[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(separate_header[8..].try_into().unwrap());
    let payload = parse_ss2022_udp_server_plaintext(expected_client_session_id, &plaintext)?;
    Ok((session_id, packet_id, payload))
}

pub fn encrypt_udp_separate_header(
    cipher: CipherKind,
    master_key: &[u8],
    header: &[u8; 16],
) -> Result<[u8; 16]> {
    let mut block = *header;
    match cipher {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(master_key).context("invalid aes-128 ss2022 key")?;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        }
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(master_key).context("invalid aes-256 ss2022 key")?;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        }
        _ => bail!("UDP separate header is only defined for ss2022 AES methods"),
    }
    Ok(block)
}

pub fn decrypt_udp_separate_header(
    cipher: CipherKind,
    master_key: &[u8],
    header: &[u8; 16],
) -> Result<[u8; 16]> {
    let mut block = *header;
    match cipher {
        CipherKind::Aes128Gcm2022 => {
            let cipher =
                Aes128::new_from_slice(master_key).context("invalid aes-128 ss2022 key")?;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        }
        CipherKind::Aes256Gcm2022 => {
            let cipher =
                Aes256::new_from_slice(master_key).context("invalid aes-256 ss2022 key")?;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        }
        _ => bail!("UDP separate header is only defined for ss2022 AES methods"),
    }
    Ok(block)
}

fn encrypt_udp_packet_2022_chacha(
    cipher: CipherKind,
    master_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022_chacha() {
        bail!("ss2022 chacha UDP framing requires a 2022 chacha cipher");
    }
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut buffer = plaintext.to_vec();
    let cipher =
        XChaCha20Poly1305::new_from_slice(master_key).context("invalid ss2022 chacha key")?;
    let tag = cipher
        .encrypt_in_place_detached(XChaNonce::from_slice(&nonce), b"", &mut buffer)
        .map_err(|_| anyhow!("xchacha20 encryption failed"))?;
    buffer.extend_from_slice(&tag);

    let mut packet = Vec::with_capacity(nonce.len() + buffer.len());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&buffer);
    Ok(packet)
}

fn decrypt_udp_packet_2022_chacha(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if !cipher.is_ss2022_chacha() {
        bail!("ss2022 chacha UDP framing requires a 2022 chacha cipher");
    }
    if packet.len() < 24 + SHADOWSOCKS_TAG_LEN {
        bail!("UDP packet is too short");
    }

    let mut buffer = packet[24..packet.len() - SHADOWSOCKS_TAG_LEN].to_vec();
    let tag = &packet[packet.len() - SHADOWSOCKS_TAG_LEN..];
    let cipher =
        XChaCha20Poly1305::new_from_slice(master_key).context("invalid ss2022 chacha key")?;
    cipher
        .decrypt_in_place_detached(
            XChaNonce::from_slice(&packet[..24]),
            b"",
            &mut buffer,
            tag.into(),
        )
        .map_err(|_| anyhow!("xchacha20 decryption failed"))?;

    parse_ss2022_udp_server_chacha_plaintext(expected_client_session_id, &buffer)
}

fn build_ss2022_udp_client_plaintext(
    cipher: CipherKind,
    session_id: u64,
    packet_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    let mut plaintext = Vec::with_capacity(payload.len() + 32);
    if cipher.is_ss2022_chacha() {
        plaintext.extend_from_slice(&session_id.to_be_bytes());
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
    }
    plaintext.push(SS2022_UDP_CLIENT_PACKET);
    plaintext.extend_from_slice(&timestamp.to_be_bytes());
    plaintext.extend_from_slice(&0u16.to_be_bytes());
    plaintext.extend_from_slice(payload);
    Ok(plaintext)
}

fn parse_ss2022_udp_server_plaintext(
    expected_client_session_id: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let min_len = 1 + 8 + 8 + 2;
    if plaintext.len() < min_len {
        bail!("ss2022 UDP payload is too short");
    }
    if plaintext[0] != SS2022_UDP_SERVER_PACKET {
        bail!("invalid ss2022 UDP server packet type: {}", plaintext[0]);
    }
    let client_session_offset = 9;
    let client_session_end = client_session_offset + 8;
    let client_session_id = u64::from_be_bytes(
        plaintext[client_session_offset..client_session_end]
            .try_into()
            .unwrap(),
    );
    if expected_client_session_id != 0 && client_session_id != expected_client_session_id {
        bail!("ss2022 UDP client session id mismatch");
    }
    let padding_len_offset = client_session_end;
    let padding_len = u16::from_be_bytes([
        plaintext[padding_len_offset],
        plaintext[padding_len_offset + 1],
    ]) as usize;
    let payload_offset = padding_len_offset + 2 + padding_len;
    if plaintext.len() < payload_offset {
        bail!("ss2022 UDP padding exceeds payload length");
    }
    Ok(plaintext[payload_offset..].to_vec())
}

fn parse_ss2022_udp_server_chacha_plaintext(
    expected_client_session_id: u64,
    plaintext: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    let min_len = 8 + 8 + 1 + 8 + 8 + 2;
    if plaintext.len() < min_len {
        bail!("ss2022 chacha UDP payload is too short");
    }
    let server_session_id = u64::from_be_bytes(plaintext[..8].try_into().unwrap());
    let server_packet_id = u64::from_be_bytes(plaintext[8..16].try_into().unwrap());
    if plaintext[16] != SS2022_UDP_SERVER_PACKET {
        bail!(
            "invalid ss2022 chacha UDP server packet type: {}",
            plaintext[16]
        );
    }
    let client_session_offset = 25;
    let client_session_end = client_session_offset + 8;
    let client_session_id = u64::from_be_bytes(
        plaintext[client_session_offset..client_session_end]
            .try_into()
            .unwrap(),
    );
    if expected_client_session_id != 0 && client_session_id != expected_client_session_id {
        bail!("ss2022 chacha UDP client session id mismatch");
    }
    let padding_len_offset = client_session_end;
    let padding_len = u16::from_be_bytes([
        plaintext[padding_len_offset],
        plaintext[padding_len_offset + 1],
    ]) as usize;
    let payload_offset = padding_len_offset + 2 + padding_len;
    if plaintext.len() < payload_offset {
        bail!("ss2022 chacha UDP padding exceeds payload length");
    }
    Ok((
        server_session_id,
        server_packet_id,
        plaintext[payload_offset..].to_vec(),
    ))
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
        let master_key = cipher.derive_master_key("password").unwrap();
        let packet = encrypt_udp_packet(cipher, &master_key, b"payload").unwrap();
        let payload = decrypt_udp_packet(cipher, &master_key, &packet).unwrap();
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn ss2022_key_uses_base64_psk() {
        let cipher = CipherKind::Aes128Gcm2022;
        let key = cipher
            .derive_master_key("AQIDBAUGBwgJCgsMDQ4PEA==")
            .unwrap();
        assert_eq!(hex(&key), "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn ss2022_udp_packet_round_trip() {
        let cipher = CipherKind::Aes128Gcm2022;
        let master_key = cipher
            .derive_master_key("AQIDBAUGBwgJCgsMDQ4PEA==")
            .unwrap();
        let client_session_id = 7u64;
        let server_session_id = 17u64;
        let server_packet_id = 19u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut plaintext = Vec::new();
        plaintext.push(SS2022_UDP_SERVER_PACKET);
        plaintext.extend_from_slice(&timestamp.to_be_bytes());
        plaintext.extend_from_slice(&client_session_id.to_be_bytes());
        plaintext.extend_from_slice(&0u16.to_be_bytes());
        plaintext.extend_from_slice(b"\x01\x08\x08\x08\x08\x00\x35payload");
        let packet = encrypt_udp_packet_2022_aes(
            cipher,
            &master_key,
            server_session_id,
            server_packet_id,
            &plaintext,
        )
        .unwrap();
        let (session_id, packet_id, payload) =
            decrypt_udp_packet_2022(cipher, &master_key, client_session_id, &packet).unwrap();
        assert_eq!(session_id, server_session_id);
        assert_eq!(packet_id, server_packet_id);
        assert_eq!(payload, b"\x01\x08\x08\x08\x08\x00\x35payload");
    }

    #[test]
    fn ss2022_chacha_udp_packet_round_trip() {
        let cipher = CipherKind::Chacha20Poly13052022;
        let master_key = cipher
            .derive_master_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
            .unwrap();
        let client_session_id = 7u64;
        let server_session_id = 17u64;
        let server_packet_id = 19u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&server_session_id.to_be_bytes());
        plaintext.extend_from_slice(&server_packet_id.to_be_bytes());
        plaintext.push(SS2022_UDP_SERVER_PACKET);
        plaintext.extend_from_slice(&timestamp.to_be_bytes());
        plaintext.extend_from_slice(&client_session_id.to_be_bytes());
        plaintext.extend_from_slice(&0u16.to_be_bytes());
        plaintext.extend_from_slice(b"\x01\x08\x08\x08\x08\x00\x35payload");
        let packet = encrypt_udp_packet_2022_chacha(cipher, &master_key, &plaintext).unwrap();
        let (decoded_session_id, decoded_packet_id, payload) =
            decrypt_udp_packet_2022(cipher, &master_key, client_session_id, &packet).unwrap();
        assert_eq!(decoded_session_id, server_session_id);
        assert_eq!(decoded_packet_id, server_packet_id);
        assert_eq!(payload, b"\x01\x08\x08\x08\x08\x00\x35payload");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
