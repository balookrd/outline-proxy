use super::*;

use outline_wire::padding::{MAX_PADDING_SEGMENT, PaddingDecoder};
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

/// A certificate-sized downlink frame is cut into >= 2 messages, the server
/// plan has no lead-in covers, and the decoder recovers the original bytes.
#[test]
fn shaped_messages_cut_a_server_flight_and_round_trip() {
    use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
    let scheme = PaddingScheme::new(0, 64);
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper =
            EarlyShaper::new(ShapeDirection::ServerToClient, false, &mut draw_in(&mut rng));
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

/// Shaping depends on the carrier only: an h1 session is eligible with no
/// padding on its path; h3 and socket carriers are not.
#[test]
fn shape_eligible_depends_on_protocol_only() {
    use crate::metrics::Protocol;
    assert!(shape_eligible(Protocol::Http1));
    assert!(shape_eligible(Protocol::Http2));
    assert!(shape_eligible(Protocol::XhttpH1));
    assert!(shape_eligible(Protocol::XhttpH2));
    assert!(!shape_eligible(Protocol::Http3));
    assert!(!shape_eligible(Protocol::XhttpH3));
    assert!(!shape_eligible(Protocol::Socket));
    assert!(new_server_shaper(Protocol::Http1).is_some());
    assert!(new_server_shaper(Protocol::Http3).is_none());
}

/// Unpadded path: the pieces are plain slices of the buffer.
#[test]
fn shaped_messages_disabled_scheme_returns_plain_pieces() {
    use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper =
            EarlyShaper::new(ShapeDirection::ServerToClient, false, &mut draw_in(&mut rng));
        let frame: Vec<u8> = (0..4499u32).map(|i| (i % 251) as u8).collect();
        let msgs = shaped_messages(PaddingScheme::disabled(), &mut shaper, &frame, &mut rng);
        assert!(msgs.len() >= 2, "seed {seed}");
        assert_eq!(msgs.concat(), frame, "seed {seed}");
    }
}

/// Bytes one capped downlink message can take on an h2 carrier, counted the
/// way `h2_plaintext_cap` budgets it: WS header + padding framing + inner
/// framing + data.
fn h2_budget_used(cap: usize, scheme: PaddingScheme, inner: usize) -> usize {
    let pad = if scheme.is_enabled() {
        PADDING_FRAME_HEADER_LEN + usize::from(scheme.max_pad())
    } else {
        0
    };
    cap + H2_WS_HEADER_LEN + pad + inner
}

/// Only h2 carriers are capped: h1 never sees h2 DATA framing and h3 / socket
/// carriers keep their wire.
#[test]
fn h2_plaintext_cap_is_none_off_h2() {
    use crate::metrics::Protocol;
    for protocol in
        [Protocol::Http1, Protocol::XhttpH1, Protocol::Http3, Protocol::XhttpH3, Protocol::Socket]
    {
        for scheme in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            assert_eq!(h2_plaintext_cap(protocol, scheme, 34), None, "{protocol:?}");
            assert_eq!(h2_plaintext_cap(protocol, scheme, 0), None, "{protocol:?}");
        }
    }
}

/// On h2 the cap spends the whole one-record DATA budget exactly: a capped
/// message plus its WS header, worst-case padding and inner framing is 16375 B.
#[test]
fn h2_plaintext_cap_fills_one_data_frame_exactly() {
    use crate::metrics::Protocol;
    assert_eq!(H2_DATA_PAYLOAD_MAX, 16375);
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for scheme in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            for inner in [0, 8, 34] {
                let cap = h2_plaintext_cap(protocol, scheme, inner).expect("h2 is capped");
                assert_eq!(
                    h2_budget_used(cap, scheme, inner),
                    H2_DATA_PAYLOAD_MAX,
                    "{protocol:?} {scheme:?} inner {inner}"
                );
            }
        }
    }
    // Spot values the brief and the report quote.
    let ss = h2_plaintext_cap(Protocol::Http2, PaddingScheme::disabled(), 34);
    assert_eq!(ss, Some(16337));
    let ss_padded = h2_plaintext_cap(Protocol::Http2, PaddingScheme::new(0, 256), 34);
    assert_eq!(ss_padded, Some(16077));
    assert_eq!(h2_plaintext_cap(Protocol::XhttpH2, PaddingScheme::disabled(), 0), Some(16371));
}

/// A pad range that leaves no sensible room in one record disables the cap
/// instead of collapsing messages to a few bytes.
#[test]
fn h2_plaintext_cap_gives_up_when_padding_eats_the_record() {
    use crate::metrics::Protocol;
    let huge = PaddingScheme::new(0, 16_000);
    assert_eq!(h2_plaintext_cap(Protocol::Http2, huge, 34), None);
}

/// Cutting a capped piece through the early shaper never grows it: every
/// message the shaper emits for a piece is within the piece's framed size.
#[test]
fn shaped_capped_pieces_stay_within_the_h2_budget() {
    use crate::metrics::Protocol;
    use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
    let scheme = PaddingScheme::new(0, 256);
    let cap = h2_plaintext_cap(Protocol::Http2, scheme, 0).unwrap();
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper =
            EarlyShaper::new(ShapeDirection::ServerToClient, false, &mut draw_in(&mut rng));
        let data: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
        let mut decoder = PaddingDecoder::new();
        let mut out = Vec::new();
        for piece in data.chunks(cap) {
            for m in shaped_messages(scheme, &mut shaper, piece, &mut rng) {
                assert!(m.len() + H2_WS_HEADER_LEN <= H2_DATA_PAYLOAD_MAX, "seed {seed}");
                decoder.push(&m, &mut out);
            }
        }
        assert_eq!(out, data, "seed {seed}");
    }
}

/// Even cuts: fewest pieces of at most `cap`, sizes within one byte of each
/// other, so no small remainder piece.
#[test]
fn even_piece_lens_cut_evenly_without_a_small_remainder() {
    assert_eq!(even_piece_lens(0, 100).collect::<Vec<_>>(), vec![0]);
    assert_eq!(even_piece_lens(100, 100).collect::<Vec<_>>(), vec![100]);
    assert_eq!(even_piece_lens(101, 100).collect::<Vec<_>>(), vec![51, 50]);
    assert_eq!(even_piece_lens(16_383, 16_371).collect::<Vec<_>>(), vec![8192, 8191]);
    for len in [1usize, 999, 16_372, 65_550, 200_000] {
        let pieces: Vec<_> = even_piece_lens(len, 16_371).collect();
        assert_eq!(pieces.len(), len.div_ceil(16_371));
        assert_eq!(pieces.iter().sum::<usize>(), len);
        let (min, max) = (pieces.iter().min().unwrap(), pieces.iter().max().unwrap());
        assert!(*max <= 16_371 && max - min <= 1, "{len}: {pieces:?}");
    }
}

/// A resume replay frame on h2 goes out as messages that each fit one h2 DATA
/// frame and decode back to the frame; off h2 it stays one message.
#[test]
fn capped_downlink_messages_fit_h2_and_round_trip() {
    use crate::metrics::Protocol;
    let frame: Bytes = (0..65_550u32).map(|i| (i % 251) as u8).collect::<Vec<_>>().into();
    for scheme in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
        for protocol in [Protocol::Http2, Protocol::XhttpH2] {
            let msgs = capped_downlink_messages(protocol, scheme, frame.clone());
            assert!(msgs.len() >= 5, "{protocol:?} {scheme:?}");
            let mut decoder = PaddingDecoder::new();
            let mut out = Vec::new();
            for m in &msgs {
                assert!(m.len() + H2_WS_HEADER_LEN <= H2_DATA_PAYLOAD_MAX);
                assert!(m.len() >= 256, "no small piece: {} B", m.len());
                if scheme.is_enabled() {
                    decoder.push(m, &mut out);
                } else {
                    out.extend_from_slice(m);
                }
            }
            assert_eq!(out, frame, "{protocol:?} {scheme:?}");
        }
        let msgs = capped_downlink_messages(Protocol::Http1, scheme, frame.clone());
        assert_eq!(msgs.len(), 1, "off h2 the frame is one message");
    }
}
