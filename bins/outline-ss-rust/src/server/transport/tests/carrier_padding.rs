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

#[test]
fn datagram_message_fits_or_declines() {
    let scheme = PaddingScheme::new(0, 256);
    let record = Bytes::from(vec![0x33; 1352]);
    for _ in 0..500 {
        let framed = frame_datagram_message(scheme, &record, 1396).expect("fits unpadded");
        assert!(framed.len() <= 1396);
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&framed, &mut decoded);
        assert_eq!(decoded, record);
    }
    assert!(frame_datagram_message(scheme, &record, 1355).is_none());
    // Unpadded path: the record itself, when it fits.
    assert_eq!(
        frame_datagram_message(PaddingScheme::disabled(), &record, 1352).as_ref(),
        Some(&record)
    );
    assert!(frame_datagram_message(PaddingScheme::disabled(), &record, 1351).is_none());
}

#[test]
fn shape_eligible_only_on_padded_h1_h2_carriers() {
    use crate::metrics::Protocol;
    let on = PaddingScheme::new(0, 64);
    for p in [Protocol::Http1, Protocol::Http2, Protocol::XhttpH1, Protocol::XhttpH2] {
        assert!(shape_eligible(p, on), "{p:?}");
        assert!(!shape_eligible(p, PaddingScheme::disabled()), "{p:?} unpadded");
    }
    for p in [Protocol::Http3, Protocol::XhttpH3, Protocol::Socket] {
        assert!(!shape_eligible(p, on), "{p:?}");
    }
}

/// A certificate-sized downlink frame is cut into >= 2 messages, the server
/// plan has no lead-in covers, and the decoder recovers the original bytes.
#[test]
fn shaped_messages_cut_a_server_flight_and_round_trip() {
    use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
    let scheme = PaddingScheme::new(0, 64);
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper = EarlyShaper::new(ShapeDirection::ServerToClient, &mut draw_in(&mut rng));
        let frame: Vec<u8> = (0..4499u32).map(|i| (i % 251) as u8).collect();
        let msgs = shaped_messages(scheme, &mut shaper, &frame, &mut rng);
        assert!(msgs.len() >= 2, "seed {seed}: got {} messages", msgs.len());
        let mut decoded = Vec::new();
        let mut dec = PaddingDecoder::new();
        for m in &msgs {
            let before = decoded.len();
            dec.push(m, &mut decoded);
            assert!(decoded.len() > before, "seed {seed}: pad-only message (cover) emitted");
        }
        assert_eq!(decoded, frame, "seed {seed}");
        assert!(dec.is_at_frame_boundary());
    }
}
