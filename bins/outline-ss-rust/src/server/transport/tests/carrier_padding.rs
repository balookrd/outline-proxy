use super::*;

use outline_wire::padding::PaddingDecoder;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn seeded() -> StdRng {
    StdRng::seed_from_u64(0x5EED)
}

/// What the server frames, a `PaddingDecoder` (the client's read path) must
/// recover byte-for-byte — and vice versa. This is the round-trip the
/// config-synchronised gate relies on.
#[test]
fn frame_then_decode_round_trips() {
    let scheme = PaddingScheme::new(0, 128);
    let mut rng = seeded();
    let data = b"shadowsocks downlink ciphertext bytes".to_vec();

    let mut framed = Vec::new();
    frame_payload_into(scheme, &data, &mut rng, &mut framed);

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    dec.push(&framed, &mut decoded);
    assert_eq!(decoded, data);
    assert!(dec.is_at_frame_boundary());
}

/// A coalesced downlink larger than the u16 segment ceiling is split across
/// frames and still reassembles.
#[test]
fn oversize_payload_is_chunked_and_recovered() {
    let scheme = PaddingScheme::new(16, 64);
    let mut rng = seeded();
    let data = vec![0x5Au8; MAX_PADDING_SEGMENT + 4096];

    let mut framed = Vec::new();
    frame_payload_into(scheme, &data, &mut rng, &mut framed);

    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    dec.push(&framed, &mut decoded);
    assert_eq!(decoded, data);
}
