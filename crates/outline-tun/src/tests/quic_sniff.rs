use super::test_vectors::{
    build_initial, build_initial_from_frames, client_hello, push_crypto_frame,
};
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
    let packet = build_initial(VERSION_V1, &RFC_DCID, &client_hello("example.com"));
    let mut tampered = packet.clone();
    tampered[0] = 0xe0; // long+fixed, type 0b10 (Handshake)
    assert_eq!(sniff_quic_sni(&tampered), SniffOutcome::NotMatched);
}

fn hex16(s: &str) -> [u8; 16] {
    hex(s).try_into().unwrap()
}

fn hex12(s: &str) -> [u8; 12] {
    hex(s).try_into().unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
