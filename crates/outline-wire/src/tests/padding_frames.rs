use std::time::Duration;

use rand::{SeedableRng, rngs::StdRng};

use super::*;
use crate::early_shape::ShapeDirection;
use crate::padding::PaddingDecoder;

const SCHEME: PaddingScheme = PaddingScheme::new(16, 96);

/// Decodes a stream of padding frames back to the real payload.
fn decode(framed: &[u8]) -> Vec<u8> {
    let mut decoder = PaddingDecoder::new();
    let mut out = Vec::new();
    decoder.push(framed, &mut out);
    assert!(decoder.is_at_frame_boundary(), "framed stream ends mid-frame");
    out
}

#[test]
fn frame_payload_round_trips_and_pads_within_the_scheme() {
    let mut rng = StdRng::seed_from_u64(7);
    for len in [0usize, 1, 500, MAX_PADDING_SEGMENT, MAX_PADDING_SEGMENT + 1, 200_000] {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut framed = Vec::new();
        frame_payload_into(SCHEME, &data, &mut rng, &mut framed);
        assert_eq!(decode(&framed), data, "len = {len}");
        // One 4-byte header per segment, pad on the last segment only.
        let segments = len.div_ceil(MAX_PADDING_SEGMENT).max(1);
        let pad = framed.len() - len - 4 * segments;
        assert!((16..=96).contains(&pad), "len = {len}: pad {pad} outside the scheme");
    }
}

#[test]
fn shaped_messages_with_an_h2_cap_keep_every_piece_within_it() {
    let mut rng = StdRng::seed_from_u64(11);
    let data = vec![0xa5u8; 100_000];
    let cap = 8_000;
    // The write is far larger than the shaping window's byte budget, so the
    // plan ends in one big piece; the cap is what cuts that piece.
    let mut shaper = EarlyShaper::new(ShapeDirection::ServerToClient, false, &mut |lo, _| lo);
    let msgs = shaped_messages(SCHEME, &mut shaper, &data, Some(cap), &mut rng);
    assert!(msgs.len() >= data.len() / cap, "{} messages", msgs.len());
    let mut joined = Vec::new();
    for msg in &msgs {
        let real = decode(msg);
        assert!(real.len() <= cap, "piece of {} B exceeds the cap", real.len());
        joined.extend_from_slice(&real);
    }
    assert_eq!(joined, data);
}

#[test]
fn draw_jitter_stays_in_range_and_tolerates_an_inverted_range() {
    for _ in 0..256 {
        let gap = draw_jitter(100, 250);
        assert!((Duration::from_millis(100)..=Duration::from_millis(250)).contains(&gap));
    }
    assert_eq!(draw_jitter(300, 100), Duration::from_millis(300));
}

proptest::proptest! {
    // The fewest pieces of at most `cap` bytes, differing by at most one byte,
    // and no small remainder piece.
    #[test]
    fn even_piece_lens_cuts_evenly(len in 0usize..2_000_000, cap in 1usize..70_000) {
        let pieces: Vec<usize> = even_piece_lens(len, cap).collect();
        proptest::prop_assert_eq!(pieces.iter().sum::<usize>(), len);
        proptest::prop_assert_eq!(pieces.len(), len.div_ceil(cap).max(1));
        let (min, max) = (pieces.iter().min().unwrap(), pieces.iter().max().unwrap());
        proptest::prop_assert!(*max <= cap);
        proptest::prop_assert!(max - min <= 1);
    }
}

#[test]
fn h2_record_payload_cap_accounts_for_ws_header_padding_and_overhead() {
    assert_eq!(
        h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, PaddingScheme::disabled(), 0),
        Some(16375 - 8),
    );
    assert_eq!(
        h2_record_payload_cap(H2_WS_SERVER_HEADER_LEN, PaddingScheme::new(0, 256), 34),
        Some(16375 - 4 - 4 - 256 - 34),
    );
    assert_eq!(
        h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, PaddingScheme::new(0, 16_000), 0),
        None,
    );
}

#[test]
fn h2_capped_messages_cuts_evenly_and_round_trips() {
    let scheme = PaddingScheme::new(0, 128);
    let cap = h2_record_payload_cap(H2_WS_CLIENT_HEADER_LEN, scheme, 0).unwrap();
    let payload = bytes::Bytes::from(vec![0x5A; cap * 2 + 17]);
    let msgs = h2_capped_messages(scheme, Some(cap), payload.clone(), &mut rand::rng());
    assert_eq!(msgs.len(), 3);
    let mut decoder = PaddingDecoder::new();
    let mut out = Vec::new();
    for m in msgs {
        assert!(m.len() + H2_WS_CLIENT_HEADER_LEN <= H2_DATA_PAYLOAD_MAX);
        decoder.push(&m, &mut out);
    }
    assert!(decoder.is_at_frame_boundary());
    assert_eq!(out, payload.as_ref());
}

#[test]
fn try_frame_datagram_respects_room_budget() {
    let scheme = PaddingScheme::new(16, 64);
    let record = bytes::Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(try_frame_datagram(scheme, &record, 11, &mut rand::rng()).is_none());
    let framed = try_frame_datagram(scheme, &record, 24, &mut rand::rng()).unwrap();
    assert!(framed.len() <= 24);
}
