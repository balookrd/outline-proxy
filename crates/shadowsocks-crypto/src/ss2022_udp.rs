use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce as XChaNonce};
use rand::rand_core::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

use outline_wire::ss2022::{
    Ss2022HeaderError, build_udp_request_body, encode_udp_separate_header,
    parse_chacha_udp_response_body, parse_udp_response_body, udp_nonce_from_separate_header,
};

use crate::cipher_kind::CipherKind;
use crate::error::{CryptoError, Result};

use super::aead::{SHADOWSOCKS_TAG_LEN, decrypt, encrypt};
use super::keys::derive_subkey;

#[cfg(test)]
pub(crate) use outline_wire::ss2022::SS2022_UDP_SERVER_TYPE as SS2022_UDP_SERVER_PACKET;

const CIPHER_XCHACHA: &str = "xchacha20-poly1305";
const CIPHER_AES_128_SS2022: &str = "aes-128 ss2022";
const CIPHER_AES_256_SS2022: &str = "aes-256 ss2022";

const ERR_REQUIRES_2022: &str = "ss2022 UDP framing requires a 2022 cipher";
const ERR_REQUIRES_2022_CHACHA: &str = "ss2022 chacha UDP framing requires a 2022 chacha cipher";
const ERR_SEPARATE_HEADER_AES_ONLY: &str =
    "UDP separate header is only defined for ss2022 AES methods";
const ERR_SS2022_INVALID_BODY: &str = "invalid ss2022 UDP server packet body";
const ERR_SS2022_INVALID_SERVER_TYPE: &str = "invalid ss2022 UDP server packet type";
const ERR_SS2022_CLIENT_SESSION_MISMATCH: &str = "ss2022 UDP client session id mismatch";

fn unix_now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| CryptoError::ClockBeforeEpoch)
}

/// Collapses wire-layer response-body errors into [`CryptoError`], keeping
/// the timestamp-skew and session-mismatch cases distinguishable.
fn map_response_body_err(err: Ss2022HeaderError) -> CryptoError {
    match err {
        Ss2022HeaderError::TimestampSkew { skew_secs } => {
            CryptoError::Ss2022TimestampSkew { skew_secs: skew_secs as i64 }
        },
        Ss2022HeaderError::InvalidResponseType(_) => {
            CryptoError::Protocol(ERR_SS2022_INVALID_SERVER_TYPE)
        },
        Ss2022HeaderError::ClientSessionMismatch => {
            CryptoError::Protocol(ERR_SS2022_CLIENT_SESSION_MISMATCH)
        },
        _ => CryptoError::Protocol(ERR_SS2022_INVALID_BODY),
    }
}

/// Validates that an SS2022 timestamp is within the acceptable clock-skew window.
/// Timestamps outside ±30 s of the current time are rejected to prevent replay attacks.
pub fn validate_ss2022_timestamp(timestamp_secs: u64) -> Result<()> {
    let now = unix_now_secs()?;
    outline_wire::ss2022::validate_timestamp(timestamp_secs, now).map_err(|_| {
        CryptoError::Ss2022TimestampSkew {
            skew_secs: now.abs_diff(timestamp_secs) as i64,
        }
    })
}

pub fn encrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    session_id: u64,
    packet_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022));
    }

    let session_id_bytes = session_id.to_be_bytes();
    let chacha_session = cipher.is_ss2022_chacha().then_some((&session_id_bytes, packet_id));
    let plaintext = build_udp_request_body(chacha_session, unix_now_secs()?, payload);
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
    let separate_header = encode_udp_separate_header(&session_id.to_be_bytes(), packet_id);
    let nonce = udp_nonce_from_separate_header(&separate_header);

    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let encrypted_body = encrypt(cipher, &key[..cipher.key_len()], &nonce, plaintext)?;
    let encrypted_header = encrypt_udp_separate_header(cipher, master_key, &separate_header)?;

    let mut packet = Vec::with_capacity(16 + encrypted_body.len());
    packet.extend_from_slice(&encrypted_header);
    packet.extend_from_slice(&encrypted_body);
    Ok(packet)
}

pub fn decrypt_udp_packet_2022(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if !cipher.is_ss2022() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022));
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

/// `0` historically means "do not check the echoed client session id";
/// the wire-layer parsers express the same with `None`.
fn expected_session_bytes(expected_client_session_id: u64) -> Option<[u8; 8]> {
    (expected_client_session_id != 0).then(|| expected_client_session_id.to_be_bytes())
}

fn decrypt_udp_packet_2022_aes(
    cipher: CipherKind,
    master_key: &[u8],
    expected_client_session_id: u64,
    packet: &[u8],
) -> Result<(u64, u64, Vec<u8>)> {
    if packet.len() < 16 + SHADOWSOCKS_TAG_LEN {
        return Err(CryptoError::UdpPacketTooShort);
    }

    let mut encrypted_header = [0u8; 16];
    encrypted_header.copy_from_slice(&packet[..16]);
    let separate_header = decrypt_udp_separate_header(cipher, master_key, &encrypted_header)?;

    let nonce = udp_nonce_from_separate_header(&separate_header);
    let key = derive_subkey(cipher, master_key, &separate_header[..8])?;
    let plaintext = decrypt(cipher, &key[..cipher.key_len()], &nonce, &packet[16..])?;

    let mut session_bytes = [0u8; 8];
    session_bytes.copy_from_slice(&separate_header[..8]);
    let session_id = u64::from_be_bytes(session_bytes);

    let mut packet_id_bytes = [0u8; 8];
    packet_id_bytes.copy_from_slice(&separate_header[8..]);
    let packet_id = u64::from_be_bytes(packet_id_bytes);

    let expected = expected_session_bytes(expected_client_session_id);
    let payload = parse_udp_response_body(&plaintext, expected.as_ref(), unix_now_secs()?)
        .map_err(map_response_body_err)?;
    Ok((session_id, packet_id, payload.to_vec()))
}

pub fn encrypt_udp_separate_header(
    cipher: CipherKind,
    master_key: &[u8],
    header: &[u8; 16],
) -> Result<[u8; 16]> {
    let mut block = *header;
    match cipher {
        CipherKind::Aes128Gcm2022 => {
            let cipher = Aes128::new_from_slice(master_key)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_128_SS2022 })?;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        },
        CipherKind::Aes256Gcm2022 => {
            let cipher = Aes256::new_from_slice(master_key)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_256_SS2022 })?;
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        },
        _ => return Err(CryptoError::Protocol(ERR_SEPARATE_HEADER_AES_ONLY)),
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
            let cipher = Aes128::new_from_slice(master_key)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_128_SS2022 })?;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        },
        CipherKind::Aes256Gcm2022 => {
            let cipher = Aes256::new_from_slice(master_key)
                .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_AES_256_SS2022 })?;
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        },
        _ => return Err(CryptoError::Protocol(ERR_SEPARATE_HEADER_AES_ONLY)),
    }
    Ok(block)
}

pub(crate) fn encrypt_udp_packet_2022_chacha(
    cipher: CipherKind,
    master_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !cipher.is_ss2022_chacha() {
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022_CHACHA));
    }
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let mut buffer = plaintext.to_vec();
    let cipher = XChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_XCHACHA })?;
    let tag = cipher
        .encrypt_in_place_detached(XChaNonce::from_slice(&nonce), b"", &mut buffer)
        .map_err(|_| CryptoError::EncryptFailed { cipher: CIPHER_XCHACHA })?;
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
        return Err(CryptoError::Protocol(ERR_REQUIRES_2022_CHACHA));
    }
    if packet.len() < 24 + SHADOWSOCKS_TAG_LEN {
        return Err(CryptoError::UdpPacketTooShort);
    }

    let mut buffer = packet[24..packet.len() - SHADOWSOCKS_TAG_LEN].to_vec();
    let tag = &packet[packet.len() - SHADOWSOCKS_TAG_LEN..];
    let cipher = XChaCha20Poly1305::new_from_slice(master_key)
        .map_err(|_| CryptoError::InvalidKey { cipher: CIPHER_XCHACHA })?;
    cipher
        .decrypt_in_place_detached(
            XChaNonce::from_slice(&packet[..24]),
            b"",
            &mut buffer,
            tag.into(),
        )
        .map_err(|_| CryptoError::DecryptFailed { cipher: CIPHER_XCHACHA })?;

    let expected = expected_session_bytes(expected_client_session_id);
    let response = parse_chacha_udp_response_body(&buffer, expected.as_ref(), unix_now_secs()?)
        .map_err(map_response_body_err)?;
    Ok((
        u64::from_be_bytes(response.server_session_id),
        response.packet_id,
        response.addressed_payload.to_vec(),
    ))
}
