use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};

use super::{derive_initial_secrets, sniff_quic_sni};
use crate::sniff::SniffOutcome;

const VERSION_V1: u32 = 0x0000_0001;
const VERSION_V2: u32 = 0x6b33_43cf;

/// RFC 9001 Appendix A.1 client DCID.
const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

#[test]
fn derive_initial_secrets_matches_rfc9001_vector() {
    let keys = derive_initial_secrets(VERSION_V1, &RFC_DCID).unwrap();
    // Published client Initial key / iv / hp from RFC 9001 §A.1.
    assert_eq!(keys.key, hex16("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(keys.iv, hex12("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(keys.hp, hex16("9f50449e04a0e810283a1e9933adedd2"));
}

#[test]
fn round_trip_v1_initial_recovers_sni() {
    let packet = build_initial(VERSION_V1, &RFC_DCID, &client_hello("example.com"));
    assert_eq!(sniff_quic_sni(&packet), SniffOutcome::Found("example.com".to_string()));
}

#[test]
fn round_trip_v2_initial_recovers_sni() {
    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05];
    let packet = build_initial(VERSION_V2, &dcid, &client_hello("cdn.example.org"));
    assert_eq!(sniff_quic_sni(&packet), SniffOutcome::Found("cdn.example.org".to_string()));
}

#[test]
fn crypto_split_across_two_frames_is_reassembled() {
    let hs = client_hello("split.example.net");
    let (a, b) = hs.split_at(20);
    // Two CRYPTO frames, deliberately out of order, with the second offset.
    let mut frames = Vec::new();
    push_crypto_frame(&mut frames, 20, b);
    push_crypto_frame(&mut frames, 0, a);
    let packet = build_initial_from_frames(VERSION_V1, &RFC_DCID, &frames);
    assert_eq!(sniff_quic_sni(&packet), SniffOutcome::Found("split.example.net".to_string()));
}

#[test]
fn non_quic_datagram_is_not_matched() {
    assert_eq!(sniff_quic_sni(&[0u8; 0]), SniffOutcome::NotMatched);
    // Short-header (0x40 form, no long-header bit).
    assert_eq!(sniff_quic_sni(&[0x40, 1, 2, 3, 4, 5, 6, 7]), SniffOutcome::NotMatched);
    // Long header but unknown version.
    let mut pkt = vec![0xc0, 0xff, 0x00, 0x00, 0x1d];
    pkt.extend_from_slice(&[0x08]);
    pkt.extend_from_slice(&RFC_DCID);
    pkt.extend_from_slice(&[0x00, 0x00, 0x10]);
    pkt.extend_from_slice(&[0u8; 64]);
    assert_eq!(sniff_quic_sni(&pkt), SniffOutcome::NotMatched);
}

#[test]
fn handshake_packet_is_not_an_initial() {
    // Long header, v1, but type = Handshake (0b10 → bits 0x20).
    let packet = build_initial(VERSION_V1, &RFC_DCID, &client_hello("example.com"));
    let mut tampered = packet.clone();
    // Flip the protected first byte so the unprotected type is no longer
    // Initial is hard to do post-HP; instead assert a Handshake-typed packet
    // built from scratch is rejected.
    tampered[0] = 0xe0; // long+fixed, type 0b10
    assert_eq!(sniff_quic_sni(&tampered), SniffOutcome::NotMatched);
}

// --- helpers ---------------------------------------------------------------

fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    let entry_len = 1 + 2 + name.len();
    sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0x00);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // Handshake message: type(1) + length(3) + body. No TLS record layer —
    // QUIC CRYPTO carries the handshake messages directly.
    let mut hs = vec![0x01];
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);
    hs
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    // Smallest encoding for the small values used in tests (< 2^14).
    if value < 64 {
        out.push(value as u8);
    } else {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    }
}

fn push_crypto_frame(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    out.push(0x06);
    push_varint(out, offset);
    push_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn build_initial(version: u32, dcid: &[u8], handshake: &[u8]) -> Vec<u8> {
    let mut frames = Vec::new();
    push_crypto_frame(&mut frames, 0, handshake);
    build_initial_from_frames(version, dcid, &frames)
}

fn build_initial_from_frames(version: u32, dcid: &[u8], frames: &[u8]) -> Vec<u8> {
    let keys = derive_initial_secrets(version, dcid).unwrap();

    // Pad the plaintext so there is always a full 16-byte HP sample.
    let mut plaintext = frames.to_vec();
    if plaintext.len() < 64 {
        plaintext.resize(64, 0x00); // PADDING frames
    }

    let first: u8 = if version == VERSION_V2 { 0xd0 } else { 0xc0 };
    let mut header = vec![first];
    header.extend_from_slice(&version.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0x00); // SCID length
    header.push(0x00); // token length (varint 0)
    let length = 1 + plaintext.len() + 16; // pn(1) + plaintext + tag
    push_varint(&mut header, length as u64);
    let pn_offset = header.len();
    header.push(0x00); // packet number = 0 (1 byte)

    let aad = header.clone();
    let nonce = keys.iv; // pn = 0 → nonce = iv
    let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
        .unwrap();

    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    // Apply header protection (the inverse of what the sniffer removes).
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 4 + 16].try_into().unwrap();
    let aes = Aes128::new(GenericArray::from_slice(&keys.hp));
    let mut block = GenericArray::clone_from_slice(&sample);
    aes.encrypt_block(&mut block);
    packet[0] ^= block[0] & 0x0f;
    packet[pn_offset] ^= block[1];
    packet
}

fn hex16(s: &str) -> [u8; 16] {
    let v = hex(s);
    v.try_into().unwrap()
}

fn hex12(s: &str) -> [u8; 12] {
    let v = hex(s);
    v.try_into().unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
