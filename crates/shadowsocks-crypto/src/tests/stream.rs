use bytes::BytesMut;

use crate::stream::{
    drain_chunk_from_bytes, open_length_block, open_payload_in_place, seal_legacy_chunks,
    seal_ss2022_response_first_frame,
};
use crate::{
    AeadCipher, CipherKind, CryptoError, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_TAG_LEN, StreamNonce,
};

#[test]
fn seal_legacy_chunks_and_drain_round_trip_across_vec_and_bytes_mut() {
    let cipher = AeadCipher::new(CipherKind::Aes128Gcm, &[0x24; 16]).unwrap();
    let salt = [0x99u8; 16];
    let payload = vec![0x5Au8; LEGACY_MAX_PAYLOAD_LEN * 2 + 123];

    let mut seal_nonce = StreamNonce::new();
    let mut sent_salt = false;
    let mut wire = BytesMut::new();
    seal_legacy_chunks(&cipher, &mut seal_nonce, &salt, &mut sent_salt, &payload, &mut wire)
        .unwrap();
    assert!(sent_salt);
    assert_eq!(&wire[..16], &salt);

    let mut body = wire.split_off(16);
    let mut open_nonce = StreamNonce::new();
    let mut pending = None;
    let mut out = Vec::new();
    while drain_chunk_from_bytes(
        &mut body,
        &cipher,
        &mut open_nonce,
        &mut pending,
        LEGACY_MAX_PAYLOAD_LEN,
        &mut out,
    )
    .unwrap()
    {}
    assert!(body.is_empty());
    assert_eq!(out, payload);
}

#[test]
fn open_length_block_rejects_bad_tag_and_oversized_chunk() {
    let cipher = AeadCipher::new(CipherKind::Chacha20IetfPoly1305, &[0x77; 32]).unwrap();
    let mut bad = [0u8; 2 + SHADOWSOCKS_TAG_LEN];
    let mut n = StreamNonce::new();
    assert!(matches!(
        open_length_block(&cipher, &mut n, LEGACY_MAX_PAYLOAD_LEN, &mut bad),
        Err(CryptoError::InvalidLengthHeader)
    ));

    // Encrypt an oversized length header (0x4000 > 0x3fff) manually.
    let mut seal_n = StreamNonce::new();
    let mut oversized = Vec::new();
    cipher
        .encrypt_into(&seal_n.next().unwrap(), &0x4000u16.to_be_bytes(), &mut oversized)
        .unwrap();
    let mut open_n = StreamNonce::new();
    assert!(matches!(
        open_length_block(&cipher, &mut open_n, LEGACY_MAX_PAYLOAD_LEN, &mut oversized),
        Err(CryptoError::InvalidChunkSize(0x4000))
    ));
}

#[test]
fn ss2022_response_first_frame_round_trips() {
    let cipher = AeadCipher::new(CipherKind::Aes128Gcm2022, &[0x33; 16]).unwrap();
    let resp_salt = [0xAA; 16];
    let req_salt = [0xBB; 16];
    let mut seal_n = StreamNonce::new();
    let mut wire = Vec::new();
    seal_ss2022_response_first_frame(
        &cipher,
        &mut seal_n,
        &resp_salt,
        &req_salt,
        1_700_000_000,
        b"first-bytes",
        &mut wire,
    )
    .unwrap();
    assert_eq!(&wire[..16], &resp_salt);

    let mut open_n = StreamNonce::new();
    let hdr_ct_len = 1 + 8 + 16 + 2 + SHADOWSOCKS_TAG_LEN;
    let mut hdr_buf = wire[16..16 + hdr_ct_len].to_vec();
    let hdr_pt = open_payload_in_place(&cipher, &mut open_n, &mut hdr_buf).unwrap();
    let len = outline_wire::ss2022::parse_response_header(
        CipherKind::Aes128Gcm2022,
        &req_salt,
        &hdr_buf[..hdr_pt],
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(len, b"first-bytes".len());

    let mut pay_buf = wire[16 + hdr_ct_len..].to_vec();
    let pay_pt = open_payload_in_place(&cipher, &mut open_n, &mut pay_buf).unwrap();
    assert_eq!(&pay_buf[..pay_pt], b"first-bytes");
}
