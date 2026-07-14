use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::config::CipherKind;
use crate::crypto::tests::users;
use crate::crypto::{
    UdpCipherMode, UserKey, decrypt_udp_packet, decrypt_udp_packet_with_hint, encrypt_udp_packet,
    encrypt_udp_packet_for_response,
};
use crate::protocol::TargetAddr;

#[test]
fn roundtrip_udp_packet() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
    let packet = decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();

    assert_eq!(packet.user.id(), "bob");
    assert_eq!(packet.payload, b"udp payload");
    assert_eq!(packet.session, UdpCipherMode::Legacy);
}

#[test]
fn hinted_udp_packet_decrypt_falls_back_to_matching_user() {
    let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
    let ciphertext = encrypt_udp_packet(&users[1], b"udp payload").unwrap();
    let (packet, user_index) =
        decrypt_udp_packet_with_hint(users.as_ref(), &ciphertext, Some(0), None).unwrap();

    assert_eq!(user_index, 1);
    assert_eq!(packet.user.id(), "bob");
    assert_eq!(packet.payload, b"udp payload");
    assert_eq!(packet.session, UdpCipherMode::Legacy);
}

#[test]
fn encrypts_ss2022_udp_response() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZg==";
    let user = UserKey::new("alice", psk, None, CipherKind::Aes128Gcm2022, None).unwrap();
    let packet = encrypt_udp_packet_for_response(
        &user,
        &TargetAddr::from(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53))),
        b"dns",
        &UdpCipherMode::Aes2022 { client_session_id: [1; 8] },
        Some([2; 8]),
        0,
    )
    .unwrap();
    assert!(packet.len() > 16);
}

#[test]
fn encrypts_ss2022_chacha_udp_response() {
    let psk = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    let user = UserKey::new("alice", psk, None, CipherKind::Chacha20Poly13052022, None).unwrap();
    let packet = encrypt_udp_packet_for_response(
        &user,
        &TargetAddr::from(SocketAddr::from((Ipv4Addr::new(1, 0, 0, 1), 5353))),
        b"mdns",
        &UdpCipherMode::Chacha2022 { client_session_id: [3; 8] },
        Some([4; 8]),
        0,
    )
    .unwrap();
    assert!(packet.len() > super::super::primitives::XNONCE_LEN);
}

#[test]
fn legacy_decrypt_leaves_the_scratch_buffer_in_the_thread_local() {
    // Runs on a fresh thread so the thread-local scratch starts empty and the
    // assertion cannot be satisfied by an unrelated test that ran before us.
    // The legacy branch used to `mem::take` the scratch and hand it out as the
    // plaintext `Vec`, so every legacy datagram allocated a new one.
    std::thread::spawn(|| {
        let users = users(CipherKind::Aes256Gcm, "secret-a", "secret-b");
        assert_eq!(super::DECRYPT_SCRATCH.with(|cell| cell.borrow().capacity()), 0);

        let ciphertext = encrypt_udp_packet(&users[0], b"udp payload").unwrap();
        let packet = decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();
        assert_eq!(packet.session, UdpCipherMode::Legacy);
        assert_eq!(packet.payload, b"udp payload");

        let retained = super::DECRYPT_SCRATCH.with(|cell| cell.borrow().capacity());
        assert!(retained > 0, "legacy decrypt must leave the scratch buffer in the pool");

        // A second datagram reuses that same allocation rather than growing.
        let ciphertext = encrypt_udp_packet(&users[0], b"udp payload").unwrap();
        decrypt_udp_packet(users.as_ref(), &ciphertext).unwrap();
        assert_eq!(super::DECRYPT_SCRATCH.with(|cell| cell.borrow().capacity()), retained);
    })
    .join()
    .expect("scratch-reuse assertions");
}

proptest::proptest! {
    // decrypt_udp_packet on arbitrary bytes must never panic.
    #[test]
    fn decrypt_udp_packet_never_panics(input: Vec<u8>) {
        let users: Arc<[UserKey]> = users(CipherKind::Chacha20IetfPoly1305, "secret-a", "secret-b");
        let _ = decrypt_udp_packet(users.as_ref(), &input);
    }
}
