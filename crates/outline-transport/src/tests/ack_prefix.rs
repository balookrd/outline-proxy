//! Round-trip and validation tests for the Ack-Prefix Protocol parser.
//!
//! Pairs with the server-side serializer in
//! `outline-ss-rust::server::resumption::ack_prefix`. The byte layout
//! is shared between the two repos via
//! `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1).

use super::super::ack_prefix::{FRAME_LEN_V1, MAGIC, ParseResult, VERSION_V1, parse_v1};

/// Mirror of the server-side `build_v1_payload`, copied here so the
/// client-side tests can exercise round-trip without depending on the
/// server crate. Kept private to `tests/` so production code does not
/// gain a parallel serializer.
fn synth_v1_payload(up_acked: u64) -> [u8; FRAME_LEN_V1] {
    let mut buf = [0u8; FRAME_LEN_V1];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION_V1;
    buf[5] = 0;
    buf[6..14].copy_from_slice(&up_acked.to_be_bytes());
    buf
}

#[test]
fn parses_valid_v1_payload() {
    let buf = synth_v1_payload(0x0102030405060708);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { up_acked: 0x0102030405060708 });
}

#[test]
fn parses_zero_up_acked() {
    let buf = synth_v1_payload(0);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { up_acked: 0 });
}

#[test]
fn parses_max_up_acked() {
    let buf = synth_v1_payload(u64::MAX);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { up_acked: u64::MAX });
}

#[test]
fn too_short_buffer_signalled_for_partial_decrypt() {
    let buf = synth_v1_payload(42);
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
    let mut buf = synth_v1_payload(0);
    buf[0] = b'X';
    assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
}

#[test]
fn unsupported_version_rejected() {
    let mut buf = synth_v1_payload(0);
    buf[4] = 0x02;
    assert_eq!(parse_v1(&buf), ParseResult::UnsupportedVersion(0x02));
}

#[test]
fn reserved_flags_rejected() {
    let mut buf = synth_v1_payload(0);
    buf[5] = 0x01;
    assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x01));
}

#[test]
fn extra_trailing_bytes_ignored() {
    // Server is required to send exactly FRAME_LEN_V1 bytes per spec,
    // but the parser must not break if the caller hands us a slice that
    // contains the frame plus subsequent relay bytes (a defensive
    // guarantee — receivers may decrypt larger AEAD chunks in some
    // configurations).
    let mut buf = synth_v1_payload(7).to_vec();
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { up_acked: 7 });
}
