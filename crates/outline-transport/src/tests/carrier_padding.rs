use super::*;

use outline_wire::padding::PaddingDecoder;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn seeded() -> StdRng {
    StdRng::seed_from_u64(0xC0FFEE)
}

/// Whatever `frame_payload_into` writes, a fresh `PaddingDecoder` must
/// recover byte-for-byte — that is the contract the WS reader relies on.
#[test]
fn frame_then_decode_round_trips() {
    let scheme = PaddingScheme::new(8, 64);
    let mut rng = seeded();
    let data = b"the quick brown fox jumps over the lazy dog".to_vec();

    let mut framed = Vec::new();
    frame_payload_into(scheme, &data, &mut rng, &mut framed);
    assert!(framed.len() > data.len(), "framing must add header + pad bytes");

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    dec.push(&framed, &mut decoded);
    assert_eq!(decoded, data);
    assert!(dec.is_at_frame_boundary(), "a whole framed write decodes to a clean boundary");
}

/// A payload larger than the `u16` segment ceiling is split across several
/// frames; the decoder still reassembles the original stream, and only the
/// last frame carries pad.
#[test]
fn oversize_payload_is_chunked_and_recovered() {
    let scheme = PaddingScheme::new(0, 32);
    let mut rng = seeded();
    // Two-and-a-bit segments so we exercise the multi-frame path.
    let data = vec![0xABu8; MAX_PADDING_SEGMENT * 2 + 100];

    let mut framed = Vec::new();
    frame_payload_into(scheme, &data, &mut rng, &mut framed);

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    dec.push(&framed, &mut decoded);
    assert_eq!(decoded.len(), data.len());
    assert_eq!(decoded, data);
}

/// The decoder must tolerate input split at arbitrary byte boundaries — h2/h3
/// DATA frames carry no relation to our frame edges.
#[test]
fn decode_survives_byte_by_byte_fragmentation() {
    let scheme = PaddingScheme::new(4, 40);
    let mut rng = seeded();
    let data = b"fragmentation-tolerance-matters".to_vec();

    let mut framed = Vec::new();
    frame_payload_into(scheme, &data, &mut rng, &mut framed);

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    for byte in &framed {
        dec.push(std::slice::from_ref(byte), &mut decoded);
    }
    assert_eq!(decoded, data);
    assert!(dec.is_at_frame_boundary());
}

/// An empty payload still emits one pad-only frame; the decoder yields no
/// real bytes and lands on a clean boundary (this is the cover-frame shape).
#[test]
fn empty_payload_emits_pad_only_frame() {
    let scheme = PaddingScheme::new(16, 16);
    let mut rng = seeded();

    let mut framed = Vec::new();
    frame_payload_into(scheme, &[], &mut rng, &mut framed);
    // 4-byte header + exactly 16 pad bytes (fixed-size scheme).
    assert_eq!(framed.len(), 4 + 16);

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    dec.push(&framed, &mut decoded);
    assert!(decoded.is_empty());
    assert!(dec.is_at_frame_boundary());
}

/// Pad length always lands in `[min, max]` across many draws.
#[test]
fn pad_length_stays_in_range() {
    let scheme = PaddingScheme::new(10, 20);
    let mut rng = seeded();
    for _ in 0..1000 {
        let pad = draw_pad(scheme, &mut rng);
        assert!((10..=20).contains(&pad.len()), "pad len {} out of range", pad.len());
    }
}

#[test]
fn disabled_carrier_padding_is_inert() {
    let p = CarrierPadding::disabled();
    assert!(!p.is_enabled());
    assert!(!p.cover_enabled());
    assert_eq!(p, CarrierPadding::default());
}

#[test]
fn cover_requires_enabled_scheme() {
    // cover requested but scheme disabled → no cover (nothing to frame).
    let p = CarrierPadding {
        scheme: PaddingScheme::disabled(),
        cover: true,
        cover_jitter_min_ms: 250,
        cover_jitter_max_ms: 1500,
    };
    assert!(!p.cover_enabled());

    let p = CarrierPadding { scheme: PaddingScheme::new(0, 256), ..p };
    assert!(p.cover_enabled());
}
