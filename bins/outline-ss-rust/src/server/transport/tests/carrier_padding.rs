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
