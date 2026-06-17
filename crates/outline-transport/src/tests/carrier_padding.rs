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

/// SS-UDP and VLESS-UDP both frame each datagram independently: one
/// `frame_payload_into` call per packet, one `Message::Binary` on the wire.
/// The receiver decodes each datagram on its own and must recover the exact
/// bytes — packet boundaries survive because the sender never splits a record
/// across datagrams. A single shared streaming decoder (`UdpWsTransport` and
/// `VlessUdpTransport` on the client, `run_udp_relay` / `run_vless_relay` on
/// the server) lands on a clean frame boundary after every datagram, so the
/// next datagram starts a fresh frame. SS-UDP wraps an opaque AEAD packet
/// (no inner length prefix); VLESS-UDP wraps a `len||payload` record — the
/// codec treats both as raw bytes.
#[test]
fn per_datagram_framing_round_trips() {
    let scheme = PaddingScheme::new(0, 64);
    let mut rng = seeded();
    let datagrams: Vec<Vec<u8>> = vec![
        b"\x00\x05hello".to_vec(), // len-prefixed VLESS-UDP record
        b"\x00\x03abc".to_vec(),
        vec![0xAB; 91],   // an opaque SS-AEAD UDP packet (no inner prefix)
        vec![0x42; 1400], // a full-size packet
    ];
    let mut dec = PaddingDecoder::new();
    for dg in &datagrams {
        let mut framed = Vec::new();
        frame_payload_into(scheme, dg, &mut rng, &mut framed);
        let mut decoded = Vec::new();
        dec.push(&framed, &mut decoded);
        assert_eq!(&decoded, dg, "each datagram round-trips on its own");
        assert!(dec.is_at_frame_boundary(), "one whole frame per datagram → clean boundary");
    }
}

/// A pad-only cover frame interleaved between real datagrams decodes to
/// nothing; the surrounding read loop skips it. `UdpWsTransport` and
/// `VlessUdpTransport` (`read_packet`) and the WS frame source all treat an
/// empty decode as "read the next datagram", so a cover frame never surfaces
/// as a spurious empty packet.
#[test]
fn cover_datagram_decodes_to_nothing() {
    let scheme = PaddingScheme::new(8, 8);
    let mut rng = seeded();
    let mut dec = PaddingDecoder::new();

    // Real record decodes back verbatim.
    let real = b"\x00\x04data".to_vec();
    let mut framed = Vec::new();
    frame_payload_into(scheme, &real, &mut rng, &mut framed);
    let mut decoded = Vec::new();
    dec.push(&framed, &mut decoded);
    assert_eq!(decoded, real);

    // Cover frame (empty payload → real_len = 0) yields no real bytes.
    let mut cover = Vec::new();
    frame_payload_into(scheme, &[], &mut rng, &mut cover);
    let mut cover_decoded = Vec::new();
    dec.push(&cover, &mut cover_decoded);
    assert!(cover_decoded.is_empty(), "cover frame yields no real bytes");
    assert!(dec.is_at_frame_boundary());
}
