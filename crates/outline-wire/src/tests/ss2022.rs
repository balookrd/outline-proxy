use std::net::Ipv4Addr;

use super::*;

const NOW: u64 = 1_700_000_000;

fn target() -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(93, 184, 216, 34), 443)
}

#[test]
fn timestamp_window() {
    assert!(validate_timestamp(NOW, NOW).is_ok());
    assert!(validate_timestamp(NOW - SS2022_MAX_TIME_DIFF_SECS, NOW).is_ok());
    assert!(validate_timestamp(NOW + SS2022_MAX_TIME_DIFF_SECS, NOW).is_ok());
    assert_eq!(
        validate_timestamp(NOW - SS2022_MAX_TIME_DIFF_SECS - 1, NOW),
        Err(Ss2022HeaderError::TimestampSkew { skew_secs: SS2022_MAX_TIME_DIFF_SECS + 1 })
    );
}

#[test]
fn request_header_roundtrip() {
    let padding = [0xAB; 16];
    let (fixed, variable) = build_request_header(&target(), NOW, &padding).unwrap();

    assert_eq!(fixed.len(), SS2022_REQUEST_FIXED_HEADER_LEN);
    let variable_len = validate_request_fixed_header(&fixed, NOW).unwrap();
    assert_eq!(variable_len, variable.len());

    let parsed = parse_request_variable_header(&variable).unwrap();
    assert_eq!(parsed.target, target());
    assert!(parsed.payload.is_empty());
}

#[test]
fn request_variable_header_with_initial_payload() {
    let (_, mut variable) = build_request_header(&target(), NOW, &[0xCD; 4]).unwrap();
    variable.extend_from_slice(b"GET /");

    let parsed = parse_request_variable_header(&variable).unwrap();
    assert_eq!(parsed.target, target());
    assert_eq!(parsed.payload, b"GET /");
}

#[test]
fn fixed_header_rejects_bad_type_len_and_skew() {
    let (mut fixed, _) = build_request_header(&target(), NOW, &[0; 16]).unwrap();
    assert!(validate_request_fixed_header(&fixed[..10], NOW).is_err());

    fixed[0] = SS2022_TCP_RESPONSE_TYPE;
    assert_eq!(validate_request_fixed_header(&fixed, NOW), Err(Ss2022HeaderError::Invalid));
    fixed[0] = SS2022_TCP_REQUEST_TYPE;

    assert!(matches!(
        validate_request_fixed_header(&fixed, NOW + 31),
        Err(Ss2022HeaderError::TimestampSkew { .. })
    ));
}

#[test]
fn variable_header_requires_padding_or_payload() {
    let (_, variable) = build_request_header(&target(), NOW, &[]).unwrap();
    assert_eq!(
        parse_request_variable_header(&variable).unwrap_err(),
        Ss2022HeaderError::Invalid
    );
}

#[test]
fn variable_header_rejects_oversized_padding_claim() {
    let mut variable = target().to_wire_bytes().unwrap();
    variable.extend_from_slice(&(SS2022_MAX_PADDING_LEN as u16 + 1).to_be_bytes());
    variable.extend_from_slice(&[0; 32]);
    assert_eq!(
        parse_request_variable_header(&variable).unwrap_err(),
        Ss2022HeaderError::Invalid
    );
}

#[test]
fn build_rejects_oversized_padding() {
    let padding = vec![0_u8; SS2022_MAX_PADDING_LEN + 1];
    assert!(build_request_header(&target(), NOW, &padding).is_err());
}

fn response_plaintext(cipher: CipherKind, request_salt: &[u8], first_chunk_len: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(SS2022_TCP_RESPONSE_TYPE);
    out.extend_from_slice(&NOW.to_be_bytes());
    out.extend_from_slice(&request_salt[..cipher.salt_len()]);
    out.extend_from_slice(&first_chunk_len.to_be_bytes());
    out
}

#[test]
fn response_header_roundtrip_and_rejections() {
    let cipher = CipherKind::Aes256Gcm2022;
    let salt = [0x42; 32];
    let plaintext = response_plaintext(cipher, &salt, 1024);

    assert_eq!(parse_response_header(cipher, &salt, &plaintext, NOW).unwrap(), 1024);

    assert_eq!(
        parse_response_header(cipher, &salt, &plaintext[..plaintext.len() - 1], NOW),
        Err(Ss2022HeaderError::InvalidResponseLength(plaintext.len() - 1))
    );

    let mut wrong_type = plaintext.clone();
    wrong_type[0] = SS2022_TCP_REQUEST_TYPE;
    assert_eq!(
        parse_response_header(cipher, &salt, &wrong_type, NOW),
        Err(Ss2022HeaderError::InvalidResponseType(SS2022_TCP_REQUEST_TYPE))
    );

    let other_salt = [0x43; 32];
    assert_eq!(
        parse_response_header(cipher, &other_salt, &plaintext, NOW),
        Err(Ss2022HeaderError::RequestSaltMismatch)
    );
}

fn udp_request_body(padding_len: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(SS2022_UDP_CLIENT_TYPE);
    body.extend_from_slice(&NOW.to_be_bytes());
    body.extend_from_slice(&padding_len.to_be_bytes());
    body.extend_from_slice(&vec![0_u8; padding_len as usize]);
    body.extend_from_slice(&target().to_wire_bytes().unwrap());
    body.extend_from_slice(payload);
    body
}

#[test]
fn udp_request_body_roundtrip() {
    let body = udp_request_body(8, b"dns query");
    let parsed = parse_udp_request_body(&body, NOW).unwrap();
    assert_eq!(parsed.target, target());
    assert_eq!(parsed.payload, b"dns query");

    let mut wrong_type = body.clone();
    wrong_type[0] = SS2022_UDP_SERVER_TYPE;
    assert_eq!(parse_udp_request_body(&wrong_type, NOW), Err(Ss2022HeaderError::Invalid));
}

#[test]
fn chacha_udp_request_body_roundtrip() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x11; 8]);
    body.extend_from_slice(&7_u64.to_be_bytes());
    body.extend_from_slice(&udp_request_body(4, b"payload"));

    let parsed = parse_chacha_udp_request_body(&body, NOW).unwrap();
    assert_eq!(parsed.target, target());
    assert_eq!(parsed.payload, b"payload");
    assert_eq!(parsed.client_session_id, [0x11; 8]);
    assert_eq!(parsed.packet_id, 7);
}

#[test]
fn udp_nonce_is_low_twelve_bytes_of_separate_header() {
    let mut header = [0_u8; SS2022_UDP_SEPARATE_HEADER_LEN];
    for (i, byte) in header.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let nonce = udp_nonce_from_separate_header(&header);
    assert_eq!(nonce, [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn udp_separate_header_encodes_ids_in_order() {
    let header = encode_udp_separate_header(&[0xAA; 8], 0x0102_0304_0506_0708);
    assert_eq!(&header[..8], &[0xAA; 8]);
    assert_eq!(&header[8..], &0x0102_0304_0506_0708_u64.to_be_bytes());
}

#[test]
fn udp_request_builder_roundtrips_through_server_parser() {
    let mut addressed = target().to_wire_bytes().unwrap();
    addressed.extend_from_slice(b"dns query");

    let body = build_udp_request_body(None, NOW, &addressed);
    let parsed = parse_udp_request_body(&body, NOW).unwrap();
    assert_eq!(parsed.target, target());
    assert_eq!(parsed.payload, b"dns query");

    let chacha = build_udp_request_body(Some((&[0x11; 8], 7)), NOW, &addressed);
    let parsed = parse_chacha_udp_request_body(&chacha, NOW).unwrap();
    assert_eq!(parsed.target, target());
    assert_eq!(parsed.payload, b"dns query");
    assert_eq!(parsed.client_session_id, [0x11; 8]);
    assert_eq!(parsed.packet_id, 7);
}

#[test]
fn udp_response_builder_roundtrips_through_client_parser() {
    let target_wire = target().to_wire_bytes().unwrap();
    let mut body = Vec::new();
    write_udp_response_body(&mut body, NOW, &[0x22; 8], &target_wire, b"reply");

    let mut expected_tail = target_wire.clone();
    expected_tail.extend_from_slice(b"reply");
    assert_eq!(parse_udp_response_body(&body, Some(&[0x22; 8]), NOW).unwrap(), expected_tail);
    assert_eq!(parse_udp_response_body(&body, None, NOW).unwrap(), expected_tail);

    assert_eq!(
        parse_udp_response_body(&body, Some(&[0x23; 8]), NOW),
        Err(Ss2022HeaderError::ClientSessionMismatch)
    );
    let mut wrong_type = body.clone();
    wrong_type[0] = SS2022_UDP_CLIENT_TYPE;
    assert_eq!(
        parse_udp_response_body(&wrong_type, None, NOW),
        Err(Ss2022HeaderError::InvalidResponseType(SS2022_UDP_CLIENT_TYPE))
    );
    assert!(matches!(
        parse_udp_response_body(&body, None, NOW + SS2022_MAX_TIME_DIFF_SECS + 1),
        Err(Ss2022HeaderError::TimestampSkew { .. })
    ));
}

#[test]
fn chacha_udp_response_builder_roundtrips_through_client_parser() {
    let target_wire = target().to_wire_bytes().unwrap();
    let mut body = Vec::new();
    write_chacha_udp_response_body(
        &mut body,
        &[0x33; 8],
        42,
        NOW,
        &[0x22; 8],
        &target_wire,
        b"reply",
    );

    let parsed = parse_chacha_udp_response_body(&body, Some(&[0x22; 8]), NOW).unwrap();
    assert_eq!(parsed.server_session_id, [0x33; 8]);
    assert_eq!(parsed.packet_id, 42);
    let mut expected_tail = target_wire.clone();
    expected_tail.extend_from_slice(b"reply");
    assert_eq!(parsed.addressed_payload, expected_tail);
}

#[test]
fn session_subkey_matches_one_shot_derive_key() {
    // The server historically derived via a streaming hasher and the client
    // via one-shot `blake3::derive_key` over `master_key || salt`; the shared
    // helper must equal both formulations.
    let master_key = [0x42_u8; 32];
    let salt = [0x07_u8; 8];

    let mut streamed = [0_u8; 32];
    ss2022_session_subkey_into(&master_key, &salt, &mut streamed);

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&master_key);
    concatenated.extend_from_slice(&salt);
    let one_shot = blake3::derive_key(SS2022_SUBKEY_CONTEXT, &concatenated);
    assert_eq!(streamed, one_shot);

    let mut sixteen = [0_u8; 16];
    ss2022_session_subkey_into(&master_key, &salt, &mut sixteen);
    assert_eq!(sixteen, one_shot[..16]);
}
