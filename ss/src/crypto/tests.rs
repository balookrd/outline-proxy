use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use ring::aead::{Aad, LessSafeKey, UnboundKey};

use super::{
    AeadStreamDecryptor, AeadStreamEncryptor, UdpSession, UserKey, decrypt_udp_packet,
    decrypt_udp_packet_with_hint, encrypt_udp_packet, encrypt_udp_packet_for_response,
};
use crate::{config::CipherKind, protocol::TargetAddr};

fn users(cipher: CipherKind, password_a: &str, password_b: &str) -> Arc<[UserKey]> {
    Arc::from(
        vec![
            UserKey::new("alice", password_a, Some(1001), cipher, "/tcp", "/udp").unwrap(),
            UserKey::new("bob", password_b, Some(1002), cipher, "/tcp", "/udp").unwrap(),
        ]
        .into_boxed_slice(),
    )
}

#[test]
fn roundtrip_chacha20_stream() {
    let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let ciphertext = encryptor.encrypt_chunk(b"hello over websocket").unwrap();

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.push(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(plaintext, b"hello over websocket");
}

#[test]
fn decryptor_handles_fragmented_frames() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let ciphertext = encryptor.encrypt_chunk(b"fragmented").unwrap();

    let mut decryptor = AeadStreamDecryptor::new(users);
    for chunk in ciphertext.chunks(3) {
        decryptor.push(chunk);
    }
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
    assert_eq!(plaintext, b"fragmented");
}

#[test]
fn roundtrip_aes128_stream() {
    let users = users(CipherKind::Aes128Gcm, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let ciphertext = encryptor.encrypt_chunk(b"aes128").unwrap();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.push(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
    assert_eq!(plaintext, b"aes128");
}

#[test]
fn legacy_stream_encryptor_splits_large_responses() {
    let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let plaintext = vec![0x5a; super::primitives::LEGACY_MAX_CHUNK_SIZE + 10_000];
    let ciphertext = encryptor.encrypt_chunk(&plaintext).unwrap();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.push(&ciphertext);
    let mut decrypted = Vec::new();
    decryptor.pull_plaintext(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn roundtrip_udp_packet() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
    let packet = decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();

    assert_eq!(packet.user.id(), "bob");
    assert_eq!(packet.payload, b"udp payload");
    assert_eq!(packet.session, UdpSession::Legacy);
}

#[test]
fn hinted_udp_packet_decrypt_falls_back_to_matching_user() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
    let (packet, user_index) =
        decrypt_udp_packet_with_hint(users.as_ref(), &ciphertext, Some(0)).unwrap();

    assert_eq!(user_index, 1);
    assert_eq!(packet.user.id(), "bob");
    assert_eq!(packet.payload, b"udp payload");
    assert_eq!(packet.session, UdpSession::Legacy);
}

#[test]
fn decryptor_matches_user_with_different_cipher() {
    let users: Arc<[UserKey]> = Arc::from(
        vec![
            UserKey::new(
                "alice",
                "secret-a",
                Some(1001),
                CipherKind::Aes256Gcm,
                "/alice",
                "/alice-udp",
            )
            .unwrap(),
            UserKey::new(
                "bob",
                "secret-b",
                Some(1002),
                CipherKind::Chacha20IetfPoly1305,
                "/bob",
                "/bob-udp",
            )
            .unwrap(),
        ]
        .into_boxed_slice(),
    );
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let ciphertext = encryptor.encrypt_chunk(b"mixed cipher").unwrap();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.push(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(plaintext, b"mixed cipher");
}

#[test]
fn roundtrip_ss2022_tcp_stream() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
    let users = users(CipherKind::Aes128Gcm2022, psk, psk);
    let request_salt = [7_u8; 16];
    let target = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)));
    let target_bytes = target.encode().unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&request_salt);

    let session_key = super::primitives::derive_subkey(
        CipherKind::Aes128Gcm2022,
        users[0].master_key(),
        &request_salt,
    )
    .unwrap();
    let key = LessSafeKey::new(
        UnboundKey::new(
            super::primitives::cipher_algorithm(CipherKind::Aes128Gcm2022),
            &session_key,
        )
        .unwrap(),
    );
    let mut nonce_counter = 0;

    let mut fixed_header = Vec::from([super::primitives::SS2022_TCP_REQUEST_TYPE]);
    fixed_header.extend_from_slice(&super::primitives::current_unix_secs().to_be_bytes());
    fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
    let mut fixed_ct = fixed_header.clone();
    key.seal_in_place_append_tag(
        super::primitives::next_stream_nonce(&mut nonce_counter),
        Aad::empty(),
        &mut fixed_ct,
    )
    .unwrap();
    request.extend_from_slice(&fixed_ct);

    let mut var_header = target_bytes.clone();
    var_header.extend_from_slice(&1_u16.to_be_bytes());
    var_header.push(0xaa);
    let mut var_ct = var_header.clone();
    key.seal_in_place_append_tag(
        super::primitives::next_stream_nonce(&mut nonce_counter),
        Aad::empty(),
        &mut var_ct,
    )
    .unwrap();
    request.extend_from_slice(&var_ct);

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.push(&request);
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();
    assert_eq!(plaintext, target_bytes);

    let context = decryptor.response_context();
    let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
    let response = encryptor.encrypt_chunk(b"pong").unwrap();
    assert!(!response.is_empty());
}

#[test]
fn roundtrip_ss2022_chacha_tcp_stream() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    let users = users(CipherKind::Chacha20Poly13052022, psk, psk);
    let request_salt = [9_u8; 32];
    let target = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 53)));
    let target_bytes = target.encode().unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&request_salt);

    let session_key = super::primitives::derive_subkey(
        CipherKind::Chacha20Poly13052022,
        users[0].master_key(),
        &request_salt,
    )
    .unwrap();
    let key = LessSafeKey::new(
        UnboundKey::new(
            super::primitives::cipher_algorithm(CipherKind::Chacha20Poly13052022),
            &session_key,
        )
        .unwrap(),
    );
    let mut nonce_counter = 0;

    let mut fixed_header = vec![super::primitives::SS2022_TCP_REQUEST_TYPE];
    fixed_header.extend_from_slice(&super::primitives::current_unix_secs().to_be_bytes());
    fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
    let mut fixed_ct = fixed_header.clone();
    key.seal_in_place_append_tag(
        super::primitives::next_stream_nonce(&mut nonce_counter),
        Aad::empty(),
        &mut fixed_ct,
    )
    .unwrap();
    request.extend_from_slice(&fixed_ct);

    let mut var_header = target_bytes.clone();
    var_header.extend_from_slice(&1_u16.to_be_bytes());
    var_header.push(0xbb);
    let mut var_ct = var_header.clone();
    key.seal_in_place_append_tag(
        super::primitives::next_stream_nonce(&mut nonce_counter),
        Aad::empty(),
        &mut var_ct,
    )
    .unwrap();
    request.extend_from_slice(&var_ct);

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.push(&request);
    let mut plaintext = Vec::new();
    decryptor.pull_plaintext(&mut plaintext).unwrap();
    assert_eq!(plaintext, target_bytes);

    let context = decryptor.response_context();
    let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
    let response = encryptor.encrypt_chunk(b"pong").unwrap();
    assert!(!response.is_empty());
}

#[test]
fn encrypts_ss2022_udp_response() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
    let user =
        UserKey::new("alice", psk, None, CipherKind::Aes128Gcm2022, "/tcp", "/udp").unwrap();
    let packet = encrypt_udp_packet_for_response(
        &user,
        &TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53))),
        b"dns",
        &UdpSession::Aes2022 { client_session_id: [1; 8] },
        Some([2; 8]),
        0,
    )
    .unwrap();
    assert!(packet.len() > 16);
}

#[test]
fn encrypts_ss2022_chacha_udp_response() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    let user =
        UserKey::new("alice", psk, None, CipherKind::Chacha20Poly13052022, "/tcp", "/udp")
            .unwrap();
    let packet = encrypt_udp_packet_for_response(
        &user,
        &TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 0, 0, 1), 5353))),
        b"mdns",
        &UdpSession::Chacha2022 { client_session_id: [3; 8] },
        Some([4; 8]),
        0,
    )
    .unwrap();
    assert!(packet.len() > super::primitives::XNONCE_LEN);
}

#[test]
fn rejects_bad_ss2022_psk_length() {
    let error =
        UserKey::new("alice", "c2hvcnQ=", None, CipherKind::Aes256Gcm2022, "/tcp", "/udp")
            .unwrap_err();
    assert!(matches!(error, super::CryptoError::InvalidPskLength { .. }));
}
