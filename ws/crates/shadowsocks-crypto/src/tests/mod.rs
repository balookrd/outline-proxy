use std::time::{SystemTime, UNIX_EPOCH};

use crate::cipher_kind::CipherKind;

use super::aead::increment_nonce;
use super::keys::evp_bytes_to_key;
use super::ss2022_udp::{
    SS2022_UDP_SERVER_PACKET, decrypt_udp_packet_2022, encrypt_udp_packet_2022_aes,
    encrypt_udp_packet_2022_chacha,
};
use super::udp::{decrypt_udp_packet, encrypt_udp_packet};

#[test]
fn bytes_to_key_matches_known_vector() {
    let key = evp_bytes_to_key(b"password", 32);
    assert_eq!(hex(&key), "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08");
}

#[test]
fn nonce_is_incremented_little_endian() {
    let mut nonce = [0u8; 12];
    increment_nonce(&mut nonce).unwrap();
    assert_eq!(nonce[0], 1);

    nonce[0] = 0xff;
    increment_nonce(&mut nonce).unwrap();
    assert_eq!(nonce[0], 0);
    assert_eq!(nonce[1], 1);
}

#[test]
fn nonce_overflow_returns_error() {
    // A fully saturated nonce wraps to [0; 12], which would reuse the same
    // (key, nonce) pair — increment_nonce must detect and reject this.
    let mut nonce = [0xffu8; 12];
    assert!(
        increment_nonce(&mut nonce).is_err(),
        "expected Err on nonce overflow, but got Ok"
    );
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
    let key = cipher.derive_master_key("AQIDBAUGBwgJCgsMDQ4PEA==").unwrap();
    assert_eq!(hex(&key), "0102030405060708090a0b0c0d0e0f10");
}

#[test]
fn ss2022_udp_packet_round_trip() {
    let cipher = CipherKind::Aes128Gcm2022;
    let master_key = cipher.derive_master_key("AQIDBAUGBwgJCgsMDQ4PEA==").unwrap();
    let client_session_id = 7u64;
    let server_session_id = 17u64;
    let server_packet_id = 19u64;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
