use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce as XChaNonce};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::CipherKind;

use super::aead::{SHADOWSOCKS_TAG_LEN, decrypt, encrypt};
use super::keys::derive_subkey;

pub(crate) const SS2022_UDP_SERVER_PACKET: u8 = 1;
const SS2022_UDP_CLIENT_PACKET: u8 = 0;
/// Maximum allowed clock skew for SS2022 timestamp validation (seconds).
const SS2022_TIMESTAMP_WINDOW_SECS: u64 = 30;

/// Validates that an SS2022 timestamp is within the acceptable clock-skew window.
/// Timestamps outside ±30 s of the current time are rejected to prevent replay attacks.
pub fn validate_ss2022_timestamp(timestamp_secs: u64) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    let diff = now.abs_diff(timestamp_secs);
    if diff > SS2022_TIMESTAMP_WINDOW_SECS {
        bail!(
            "ss2022 timestamp out of acceptable window: diff={diff}s (limit={SS2022_TIMESTAMP_WINDOW_SECS}s)"
        );
    }
    Ok(())
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

pub(crate) fn encrypt_udp_packet_2022_aes(
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

    let mut session_bytes = [0u8; 8];
    session_bytes.copy_from_slice(&separate_header[..8]);
    let session_id = u64::from_be_bytes(session_bytes);

    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&separate_header[8..]);
    let packet_id = u64::from_be_bytes(packet_id_bytes);

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

pub(crate) fn encrypt_udp_packet_2022_chacha(
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
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[1..9]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let client_session_offset = 9;
    let client_session_end = client_session_offset + 8;
    let mut session_bytes = [0u8; 8];
    session_bytes.copy_from_slice(&plaintext[client_session_offset..client_session_end]);
    let client_session_id = u64::from_be_bytes(session_bytes);

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
    let mut session_bytes = [0u8; 8];
    session_bytes.copy_from_slice(&plaintext[..8]);
    let server_session_id = u64::from_be_bytes(session_bytes);

    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&plaintext[8..16]);
    let server_packet_id = u64::from_be_bytes(packet_id_bytes);

    if plaintext[16] != SS2022_UDP_SERVER_PACKET {
        bail!(
            "invalid ss2022 chacha UDP server packet type: {}",
            plaintext[16]
        );
    }
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[17..25]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let client_session_offset = 25;
    let client_session_end = client_session_offset + 8;
    let mut client_session_bytes = [0u8; 8];
    client_session_bytes.copy_from_slice(&plaintext[client_session_offset..client_session_end]);
    let client_session_id = u64::from_be_bytes(client_session_bytes);

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
