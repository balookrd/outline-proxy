use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::BytesMut;
use ring::aead::Aad;

use crate::config::CipherKind;
use crate::crypto::tests::users;
use crate::crypto::{AeadStreamDecryptor, AeadStreamEncryptor, UserKey, primitives, ss2022_header};
use crate::protocol::TargetAddr;

#[test]
fn roundtrip_chacha20_stream() {
    let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"hello over websocket", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(plaintext, b"hello over websocket");
}

#[test]
fn decryptor_handles_fragmented_frames() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"fragmented", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    for chunk in ciphertext.chunks(3) {
        decryptor.feed_ciphertext(chunk);
    }
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
    assert_eq!(plaintext, b"fragmented");
}

#[test]
fn roundtrip_aes128_stream() {
    let users = users(CipherKind::Aes128Gcm, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"aes128", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
    assert_eq!(plaintext, b"aes128");
}

#[test]
fn legacy_stream_encryptor_splits_large_responses() {
    let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let plaintext = vec![0x5a; primitives::LEGACY_MAX_CHUNK_SIZE + 10_000];
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.feed_ciphertext(&ciphertext);
    let mut decrypted = Vec::new();
    decryptor.drain_plaintext(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn decryptor_matches_user_with_different_cipher() {
    let users: Arc<[UserKey]> = Arc::from(
        vec![
            UserKey::new("alice", "secret-a", Some(1001), CipherKind::Aes256Gcm).unwrap(),
            UserKey::new("bob", "secret-b", Some(1002), CipherKind::Chacha20IetfPoly1305).unwrap(),
        ]
        .into_boxed_slice(),
    );
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"mixed cipher", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

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

    let key = primitives::build_session_key(
        CipherKind::Aes128Gcm2022,
        users[0].master_key(),
        &request_salt,
    )
    .unwrap();
    let mut nonce_counter = 0;

    let mut fixed_header = Vec::from([ss2022_header::SS2022_TCP_REQUEST_TYPE]);
    fixed_header.extend_from_slice(&crate::clock::current_unix_secs().to_be_bytes());
    fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
    let mut fixed_ct = fixed_header.clone();
    key.seal_in_place_append_tag(
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
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
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
        Aad::empty(),
        &mut var_ct,
    )
    .unwrap();
    request.extend_from_slice(&var_ct);

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.feed_ciphertext(&request);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();
    assert_eq!(plaintext, target_bytes);

    let context = decryptor.response_context();
    let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
    let mut response = BytesMut::new();
    encryptor.encrypt_chunk(b"pong", &mut response).unwrap();
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

    let key = primitives::build_session_key(
        CipherKind::Chacha20Poly13052022,
        users[0].master_key(),
        &request_salt,
    )
    .unwrap();
    let mut nonce_counter = 0;

    let mut fixed_header = vec![ss2022_header::SS2022_TCP_REQUEST_TYPE];
    fixed_header.extend_from_slice(&crate::clock::current_unix_secs().to_be_bytes());
    fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
    let mut fixed_ct = fixed_header.clone();
    key.seal_in_place_append_tag(
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
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
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
        Aad::empty(),
        &mut var_ct,
    )
    .unwrap();
    request.extend_from_slice(&var_ct);

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    decryptor.feed_ciphertext(&request);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();
    assert_eq!(plaintext, target_bytes);

    let context = decryptor.response_context();
    let mut encryptor = AeadStreamEncryptor::new(&users[0], context).unwrap();
    let mut response = BytesMut::new();
    encryptor.encrypt_chunk(b"pong", &mut response).unwrap();
    assert!(!response.is_empty());
}

#[test]
fn stream_user_hint_hit_authenticates_to_hinted_user() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"hint payload", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.set_user_hint(Some(1));
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(decryptor.user_index(), Some(1));
    assert_eq!(plaintext, b"hint payload");
}

#[test]
fn stream_stale_user_hint_falls_back_to_correct_user() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    // Encrypt as bob (index 1) but hint at alice (index 0). The hint must
    // fail AEAD verification, then the scan must locate bob anyway.
    let mut encryptor = AeadStreamEncryptor::new(&users[1], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"stale hint", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.set_user_hint(Some(0));
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(decryptor.user_index(), Some(1));
    assert_eq!(plaintext, b"stale hint");
}

#[test]
fn stream_out_of_bounds_user_hint_is_ignored() {
    let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
    let mut encryptor = AeadStreamEncryptor::new(&users[0], None).unwrap();
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(b"oob hint", &mut buf).unwrap();
    let ciphertext = buf.freeze();

    let mut decryptor = AeadStreamDecryptor::new(users);
    // Index 9 is out of bounds for a 2-user list. set_user_hint must
    // silently drop it so the scan still authenticates the right user.
    decryptor.set_user_hint(Some(9));
    decryptor.feed_ciphertext(&ciphertext);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("alice"));
    assert_eq!(decryptor.user_index(), Some(0));
    assert_eq!(plaintext, b"oob hint");
}

#[test]
fn stream_user_hint_hit_on_ss2022() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
    let users = users(CipherKind::Aes128Gcm2022, psk, psk);
    let request_salt = [9_u8; 16];
    let target = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)));
    let target_bytes = target.encode().unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&request_salt);

    let key = primitives::build_session_key(
        CipherKind::Aes128Gcm2022,
        users[1].master_key(),
        &request_salt,
    )
    .unwrap();
    let mut nonce_counter = 0;

    let mut fixed_header = Vec::from([ss2022_header::SS2022_TCP_REQUEST_TYPE]);
    fixed_header.extend_from_slice(&crate::clock::current_unix_secs().to_be_bytes());
    fixed_header.extend_from_slice(&(target_bytes.len() as u16 + 3).to_be_bytes());
    let mut fixed_ct = fixed_header.clone();
    key.seal_in_place_append_tag(
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
        Aad::empty(),
        &mut fixed_ct,
    )
    .unwrap();
    request.extend_from_slice(&fixed_ct);

    let mut var_header = target_bytes.clone();
    var_header.extend_from_slice(&1_u16.to_be_bytes());
    var_header.push(0xee);
    let mut var_ct = var_header.clone();
    key.seal_in_place_append_tag(
        primitives::next_stream_nonce(&mut nonce_counter).unwrap(),
        Aad::empty(),
        &mut var_ct,
    )
    .unwrap();
    request.extend_from_slice(&var_ct);

    let mut decryptor = AeadStreamDecryptor::new(users);
    decryptor.set_user_hint(Some(1));
    decryptor.feed_ciphertext(&request);
    let mut plaintext = Vec::new();
    decryptor.drain_plaintext(&mut plaintext).unwrap();

    assert_eq!(decryptor.user().map(UserKey::id), Some("bob"));
    assert_eq!(decryptor.user_index(), Some(1));
}

proptest::proptest! {
    // Feeding arbitrary bytes to the AEAD decryptor must never panic —
    // it must always either buffer silently or return Err.
    #[test]
    fn aead_decryptor_never_panics_on_random_bytes(input: Vec<u8>) {
        let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
        let mut decryptor = AeadStreamDecryptor::new(users);
        decryptor.feed_ciphertext(&input);
        let mut output = Vec::new();
        let _ = decryptor.drain_plaintext(&mut output);
    }

    // Fragmented feeding: split the input at an arbitrary boundary and feed
    // each half separately. Still must never panic.
    #[test]
    fn aead_decryptor_never_panics_on_fragmented_feed(
        input: Vec<u8>,
        split_at: usize,
    ) {
        let users = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
        let mut decryptor = AeadStreamDecryptor::new(users);
        let split = split_at.checked_rem(input.len().saturating_add(1)).unwrap_or(0);
        let (head, tail) = input.split_at(split);
        decryptor.feed_ciphertext(head);
        let mut output = Vec::new();
        let _ = decryptor.drain_plaintext(&mut output);
        decryptor.feed_ciphertext(tail);
        let _ = decryptor.drain_plaintext(&mut output);
    }
}
