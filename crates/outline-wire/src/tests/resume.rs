//! Wire-format tests for the Ack-Prefix Protocol control frames — v1
//! (`"ORSM"`) at module level, v2 Symmetric Downlink Replay (`"ORDR"`)
//! in the nested `downlink_replay` module.
//!
//! Serializer and parser live side by side here, so the round-trips
//! below exercise the exact pairs the server emits and the client
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

mod downlink_replay {
    use crate::resume::downlink_replay::{
        FLAG_KNOWN_MASK, FLAG_REPLAY_TRUNCATED, FLAGS_NONE, FRAME_HEADER_LEN_V1, MAGIC,
        ParseResult, VERSION_V1, build_v1_header, parse_v1,
    };

    #[test]
    fn header_layout_matches_spec() {
        let header = build_v1_header(FLAG_REPLAY_TRUNCATED, 0x0102030405060708);
        assert_eq!(header.len(), FRAME_HEADER_LEN_V1);
        assert_eq!(&header[0..4], &MAGIC);
        assert_eq!(header[4], VERSION_V1);
        assert_eq!(header[5], FLAG_REPLAY_TRUNCATED);
        assert_eq!(&header[6..14], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn magic_is_ascii_ordr() {
        let header = build_v1_header(FLAGS_NONE, 42);
        let magic_str = std::str::from_utf8(&header[0..4]).unwrap();
        assert_eq!(magic_str, "ORDR");
    }

    #[test]
    fn round_trips_through_parse() {
        for flags in [FLAGS_NONE, FLAG_REPLAY_TRUNCATED] {
            for replay_len in [0, 1, 42, 0x0102030405060708, u64::MAX] {
                let header = build_v1_header(flags, replay_len);
                assert_eq!(parse_v1(&header), ParseResult::Valid { flags, replay_len });
            }
        }
    }

    #[test]
    fn too_short_buffer_signalled_for_partial_decrypt() {
        let buf = build_v1_header(FLAGS_NONE, 42);
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
        let mut buf = build_v1_header(FLAGS_NONE, 0);
        buf[0] = b'X';
        assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
    }

    #[test]
    fn bad_magic_caught_when_first_three_bytes_match_orsm() {
        // `"ORSM"` is the v1 magic — easy mistake for a buggy server to
        // emit it instead of `"ORDR"`. Make sure the parser rejects it
        // with `BadMagic`, not as a partial v2 success.
        let mut buf = build_v1_header(FLAGS_NONE, 0);
        buf[0..4].copy_from_slice(b"ORSM");
        assert_eq!(parse_v1(&buf), ParseResult::BadMagic);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut buf = build_v1_header(FLAGS_NONE, 0);
        buf[4] = 0x02;
        assert_eq!(parse_v1(&buf), ParseResult::UnsupportedVersion(0x02));
    }

    #[test]
    fn reserved_flag_bits_rejected() {
        // bit 1 is reserved in v1; setting it must be a hard reject so a
        // future flag extension does not silently get absorbed by an old
        // client that does not know what the bit means.
        let buf = build_v1_header(0x02, 0);
        assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x02));
    }

    #[test]
    fn high_reserved_flag_bit_rejected() {
        let buf = build_v1_header(0x80, 0);
        assert_eq!(parse_v1(&buf), ParseResult::ReservedFlagsSet(0x80));
    }

    #[test]
    fn extra_trailing_bytes_ignored_for_header_parse() {
        // The parser is responsible only for the 14-byte header. Trailing
        // bytes are the replay payload, which the reader handles
        // separately. The parser MUST not error when the slice contains
        // header + payload concatenated (the realistic happy path).
        let header = build_v1_header(FLAGS_NONE, 5);
        let mut buf = header.to_vec();
        buf.extend_from_slice(b"hello");
        assert_eq!(parse_v1(&buf), ParseResult::Valid { flags: FLAGS_NONE, replay_len: 5 });
    }

    #[test]
    fn flag_known_mask_includes_replay_truncated_only_in_v1() {
        // Belt-and-braces sanity check: a future revision adding a new
        // flag bit needs to update FLAG_KNOWN_MASK in lockstep, and this
        // test fails loudly when someone bumps one without the other.
        assert_eq!(FLAG_KNOWN_MASK, FLAG_REPLAY_TRUNCATED);
    }

    #[test]
    fn v1_and_v2_magics_are_distinct() {
        assert_ne!(MAGIC, crate::resume::MAGIC, "ORSM and ORDR frames must be distinguishable");
    }
}
