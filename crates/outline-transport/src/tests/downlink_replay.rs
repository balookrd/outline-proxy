//! Round-trip and validation tests for the Symmetric Downlink Replay
//! (v2) parser.
//!
//! Pairs with the server-side ring buffer + emit logic in
//! `outline-ss-rust::server::resumption::downlink_ring`. The byte
//! layout is shared via `docs/SESSION-RESUMPTION.md` § Symmetric
//! Downlink Replay (v2).

use super::super::downlink_replay::{
    FLAG_KNOWN_MASK, FLAG_REPLAY_TRUNCATED, FRAME_HEADER_LEN_V1, MAGIC, ParseResult, VERSION_V1,
    parse_v1,
};

/// Mirror of the server-side header builder. Kept private to the test
/// module so production code does not gain a parallel serializer.
fn synth_v1_header(flags: u8, replay_len: u64) -> [u8; FRAME_HEADER_LEN_V1] {
    let mut buf = [0u8; FRAME_HEADER_LEN_V1];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION_V1;
    buf[5] = flags;
    buf[6..14].copy_from_slice(&replay_len.to_be_bytes());
    buf
}

#[test]
fn parses_valid_v1_header_with_no_flags() {
    let buf = synth_v1_header(0, 0x0102030405060708);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { flags: 0, replay_len: 0x0102030405060708 });
}

#[test]
fn parses_zero_replay_len() {
    let buf = synth_v1_header(0, 0);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { flags: 0, replay_len: 0 });
}

#[test]
fn parses_max_replay_len() {
    let buf = synth_v1_header(0, u64::MAX);
    assert_eq!(parse_v1(&buf), ParseResult::Valid { flags: 0, replay_len: u64::MAX });
}

#[test]
fn parses_replay_truncated_flag() {
    let buf = synth_v1_header(FLAG_REPLAY_TRUNCATED, 0);
    assert_eq!(
        parse_v1(&buf),
        ParseResult::Valid {
            flags: FLAG_REPLAY_TRUNCATED,
            replay_len: 0,
        }
    );
}

#[test]
fn too_short_buffer_signalled_for_partial_decrypt() {
    let buf = synth_v1_header(0, 42);
    for short_len in 0..FRAME_HEADER_LEN_V1 {
        assert_eq!(
            parse_v1(&buf[..short_len]),
            ParseResult::TooShort,
            "len={short_len} must be reported as TooShort",
        );
    }
}

#[test]
fn bad_magic_rejected() {
    let mut buf = synth_v1_header(0, 0);
    buf[0] = b'X';
    assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
}

#[test]
fn bad_magic_caught_when_first_three_bytes_match_orsm() {
    // `"ORSM"` is the v1 magic — easy mistake for a buggy server to
    // emit it instead of `"ORDR"`. Make sure the parser rejects it
    // with `BadMagic`, not as a partial v2 success.
    let mut buf = synth_v1_header(0, 0);
    buf[0..4].copy_from_slice(b"ORSM");
    assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
}

#[test]
fn unsupported_version_rejected() {
    let mut buf = synth_v1_header(0, 0);
    buf[4] = 0x02;
    assert_eq!(parse_v1(&buf), ParseResult::UnsupportedVersion(0x02));
}

#[test]
fn reserved_flag_bits_rejected() {
    // bit 1 is reserved in v1; setting it must be a hard reject so a
    // future flag extension does not silently get absorbed by an old
    // client that does not know what the bit means.
    let buf = synth_v1_header(0x02, 0);
    assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x02));
}

#[test]
fn high_reserved_flag_bit_rejected() {
    let buf = synth_v1_header(0x80, 0);
    assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x80));
}

#[test]
fn extra_trailing_bytes_ignored_for_header_parse() {
    // The parser is responsible only for the 14-byte header. Trailing
    // bytes are the replay payload, which the reader handles
    // separately. The parser MUST not error when the slice contains
    // header + payload concatenated (the realistic happy path).
    let header = synth_v1_header(0, 5);
    let mut buf = header.to_vec();
    buf.extend_from_slice(b"hello");
    assert_eq!(parse_v1(&buf), ParseResult::Valid { flags: 0, replay_len: 5 });
}

#[test]
fn flag_known_mask_includes_replay_truncated_only_in_v1() {
    // Belt-and-braces sanity check: a future revision adding a new
    // flag bit needs to update FLAG_KNOWN_MASK in lockstep, and this
    // test fails loudly when someone bumps one without the other.
    assert_eq!(FLAG_KNOWN_MASK, FLAG_REPLAY_TRUNCATED);
}
