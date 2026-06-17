use super::{MAX_PADDING_SEGMENT, PaddingDecoder, PaddingError, PaddingScheme, encode_frame_into};

/// Deterministic, position-dependent bytes so a misordered or truncated
/// decode is caught, not just a length mismatch.
fn ramp(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_add(seed)).collect()
}

/// Decode `wire` one byte at a time — the worst-case fragmentation a
/// stream transport (h2/h3 DATA frames) can impose on our frame edges.
fn decode_byte_by_byte(wire: &[u8]) -> Vec<u8> {
    let mut decoder = PaddingDecoder::new();
    let mut out = Vec::new();
    for byte in wire {
        decoder.push(std::slice::from_ref(byte), &mut out);
    }
    out
}

#[test]
fn frame_round_trips_over_a_range_of_sizes() {
    let real_lens = [0usize, 1, 2, 4, 100, 16383, MAX_PADDING_SEGMENT];
    let pad_lens = [0usize, 1, 7, 100, MAX_PADDING_SEGMENT];
    for &real_len in &real_lens {
        for &pad_len in &pad_lens {
            let real = ramp(real_len, 0x11);
            let pad = ramp(pad_len, 0xA0);
            let mut wire = Vec::new();
            encode_frame_into(&mut wire, &real, &pad).unwrap();

            let mut out = Vec::new();
            PaddingDecoder::new().push(&wire, &mut out);
            assert_eq!(out, real, "whole-buffer decode (real={real_len}, pad={pad_len})");

            assert_eq!(
                decode_byte_by_byte(&wire),
                real,
                "byte-by-byte decode (real={real_len}, pad={pad_len})"
            );
        }
    }
}

#[test]
fn dummy_frame_yields_no_payload() {
    // real_len = 0, pad only: a cover/keepalive write.
    let pad = ramp(64, 0x5C);
    let mut wire = Vec::new();
    encode_frame_into(&mut wire, &[], &pad).unwrap();

    let mut out = Vec::new();
    let mut decoder = PaddingDecoder::new();
    decoder.push(&wire, &mut out);
    assert!(out.is_empty());
    assert!(decoder.is_at_frame_boundary());
}

#[test]
fn empty_frame_is_skipped() {
    // real_len = 0 and pad_len = 0: degenerate, yields nothing, leaves the
    // decoder cleanly on a boundary ready for the next frame.
    let mut wire = Vec::new();
    encode_frame_into(&mut wire, &[], &[]).unwrap();
    assert_eq!(wire.len(), 4);

    let mut out = Vec::new();
    let mut decoder = PaddingDecoder::new();
    decoder.push(&wire, &mut out);
    assert!(out.is_empty());
    assert!(decoder.is_at_frame_boundary());
}

#[test]
fn multiple_frames_concatenate_in_payload_order() {
    let chunks = [ramp(10, 1), ramp(0, 2), ramp(300, 3), ramp(1, 4)];
    let mut wire = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let pad = ramp(i * 13, 0x70);
        encode_frame_into(&mut wire, chunk, &pad).unwrap();
    }
    let expected: Vec<u8> = chunks.concat();

    let mut whole = Vec::new();
    PaddingDecoder::new().push(&wire, &mut whole);
    assert_eq!(whole, expected, "frames in one push");

    assert_eq!(decode_byte_by_byte(&wire), expected, "frames byte-by-byte");
}

#[test]
fn decoder_tracks_frame_boundary() {
    let real = ramp(20, 9);
    let pad = ramp(5, 0x33);
    let mut wire = Vec::new();
    encode_frame_into(&mut wire, &real, &pad).unwrap();

    let mut decoder = PaddingDecoder::new();
    let mut out = Vec::new();

    // Stop mid-real: not on a boundary.
    decoder.push(&wire[..6], &mut out);
    assert!(!decoder.is_at_frame_boundary());

    // Feed the rest: back on a boundary, payload recovered, pad dropped.
    decoder.push(&wire[6..], &mut out);
    assert!(decoder.is_at_frame_boundary());
    assert_eq!(out, real);
}

#[test]
fn fresh_decoder_is_on_a_boundary() {
    assert!(PaddingDecoder::new().is_at_frame_boundary());
}

#[test]
fn pad_len_stays_within_range_for_every_draw() {
    let scheme = PaddingScheme::new(16, 1024);
    for rand in 0..=u16::MAX {
        let n = scheme.pad_len(rand);
        assert!((16..=1024).contains(&n), "rand={rand} -> {n}");
    }
}

#[test]
fn pad_len_reaches_both_ends_of_the_range() {
    let scheme = PaddingScheme::new(16, 1024);
    let mut seen_min = false;
    let mut seen_max = false;
    for rand in 0..=u16::MAX {
        match scheme.pad_len(rand) {
            16 => seen_min = true,
            1024 => seen_max = true,
            _ => {},
        }
    }
    assert!(seen_min && seen_max, "range endpoints both reachable");
}

#[test]
fn fixed_scheme_always_returns_its_single_value() {
    let scheme = PaddingScheme::new(256, 256);
    assert!(scheme.is_enabled());
    for rand in [0u16, 1, 12345, u16::MAX] {
        assert_eq!(scheme.pad_len(rand), 256);
    }
}

#[test]
fn max_below_min_clamps_up_to_min() {
    let scheme = PaddingScheme::new(500, 100);
    assert_eq!(scheme.pad_len(0), 500);
    assert_eq!(scheme.pad_len(u16::MAX), 500);
}

#[test]
fn disabled_scheme_reports_disabled() {
    assert!(!PaddingScheme::disabled().is_enabled());
    assert!(!PaddingScheme::new(0, 0).is_enabled());
    assert!(PaddingScheme::new(0, 1).is_enabled());
}

#[test]
fn encode_rejects_oversized_segments() {
    let oversized = vec![0u8; MAX_PADDING_SEGMENT + 1];
    let ok = vec![0u8; 8];

    let mut wire = Vec::new();
    assert_eq!(
        encode_frame_into(&mut wire, &oversized, &ok),
        Err(PaddingError::RealTooLarge(MAX_PADDING_SEGMENT + 1))
    );
    assert_eq!(
        encode_frame_into(&mut wire, &ok, &oversized),
        Err(PaddingError::PadTooLarge(MAX_PADDING_SEGMENT + 1))
    );
    // A rejected encode must not have written a partial frame.
    assert!(wire.is_empty());
}

#[test]
fn max_size_segment_is_accepted() {
    let real = ramp(MAX_PADDING_SEGMENT, 0x01);
    let mut wire = Vec::new();
    encode_frame_into(&mut wire, &real, &[]).unwrap();
    let mut out = Vec::new();
    PaddingDecoder::new().push(&wire, &mut out);
    assert_eq!(out, real);
}
