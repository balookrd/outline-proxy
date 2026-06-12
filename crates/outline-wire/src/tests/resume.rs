//! Wire-format tests for the Ack-Prefix Protocol v1 control frame.
//!
//! Serializer and parser live side by side here, so the round-trip
//! below exercises the exact pair the server emits and the client
//! consumes (previously each side tested against a private copy).

use super::{FLAGS_NONE, FRAME_LEN_V1, MAGIC, ParseResult, VERSION_V1, build_v1_payload, parse_v1};

#[test]
fn payload_layout_matches_spec() {
    let payload = build_v1_payload(0x0102030405060708);
    assert_eq!(payload.len(), FRAME_LEN_V1);
    assert_eq!(&payload[0..4], &MAGIC);
    assert_eq!(payload[4], VERSION_V1);
    assert_eq!(payload[5], FLAGS_NONE);
    assert_eq!(&payload[6..14], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

#[test]
fn magic_is_ascii_orsm() {
    let payload = build_v1_payload(42);
    let magic_str = std::str::from_utf8(&payload[0..4]).unwrap();
    assert_eq!(magic_str, "ORSM");
}

#[test]
fn round_trips_through_parse() {
    for up_acked in [0, 1, 42, 0x0102030405060708, u64::MAX] {
        let payload = build_v1_payload(up_acked);
        assert_eq!(parse_v1(&payload), ParseResult::Valid { up_acked });
    }
}

#[test]
fn too_short_buffer_signalled_for_partial_decrypt() {
    let buf = build_v1_payload(42);
    for short_len in 0..FRAME_LEN_V1 {
        assert_eq!(
            parse_v1(&buf[..short_len]),
            ParseResult::TooShort,
            "len={short_len} must be reported as TooShort",
        );
    }
}

#[test]
fn bad_magic_rejected() {
    let mut buf = build_v1_payload(0);
    buf[0] = b'X';
    assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
}

#[test]
fn unsupported_version_rejected() {
    let mut buf = build_v1_payload(0);
    buf[4] = 0x02;
    assert_eq!(parse_v1(&buf), ParseResult::UnsupportedVersion(0x02));
}

#[test]
fn reserved_flags_rejected() {
    let mut buf = build_v1_payload(0);
    buf[5] = 0x01;
    assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x01));
}

#[test]
fn extra_trailing_bytes_ignored() {
    // The server is required to send exactly FRAME_LEN_V1 bytes per
    // spec, but the parser must not break if the caller hands us a
    // slice that contains the frame plus subsequent relay bytes (a
    // defensive guarantee — receivers may decrypt larger AEAD chunks
    // in some configurations).
    let mut buf = build_v1_payload(7).to_vec();
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { up_acked: 7 });
}

#[test]
fn header_names_are_lowercase_and_distinct() {
    let headers = [
        super::RESUME_REQUEST_HEADER,
        super::RESUME_CAPABLE_HEADER,
        super::SESSION_RESPONSE_HEADER,
        super::ACK_PREFIX_HEADER,
        super::SYMMETRIC_REPLAY_HEADER,
        super::DOWN_ACKED_HEADER,
    ];
    for name in headers {
        assert_eq!(name, name.to_ascii_lowercase(), "{name} must be lower-cased");
    }
    let unique: std::collections::BTreeSet<_> = headers.into_iter().collect();
    assert_eq!(unique.len(), headers.len());
}
