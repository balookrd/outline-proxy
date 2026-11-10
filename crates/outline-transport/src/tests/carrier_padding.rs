use super::*;

use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
use outline_wire::padding::{MAX_PADDING_SEGMENT, PaddingDecoder};
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

#[test]
fn datagram_frame_fits_the_room_whatever_pad_is_drawn() {
    let scheme = PaddingScheme::new(0, 256);
    let data = vec![0x11; 1352];
    let room = 1396;
    let mut rng = rand::rng();
    for _ in 0..500 {
        let mut out = Vec::new();
        frame_datagram_into(scheme, &data, Some(room), &mut rng, &mut out);
        assert!(out.len() <= room, "frame {} over room {room}", out.len());
        let mut decoded = Vec::new();
        PaddingDecoder::new().push(&out, &mut decoded);
        assert_eq!(decoded, data);
    }
}

#[test]
fn datagram_frame_without_room_is_the_stream_frame() {
    let scheme = PaddingScheme::new(200, 256);
    let data = vec![0x22; 1352];
    let mut rng = rand::rng();
    for room in [None, Some(1355)] {
        let mut out = Vec::new();
        frame_datagram_into(scheme, &data, room, &mut rng, &mut out);
        let pad = u16::from_be_bytes([out[2], out[3]]) as usize;
        assert!((200..=256).contains(&pad), "full-range pad when it cannot fit, got {pad}");
    }
}

fn shaper_with(rng: &mut StdRng) -> EarlyShaper {
    EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut draw_in(rng))
}

/// A ClientHello-sized frame is cut into >= 2 messages (after any lead-in
/// covers) and the decoder recovers exactly the original bytes in order.
#[test]
fn shaped_messages_split_a_large_frame_and_round_trip() {
    let scheme = PaddingScheme::new(0, 64);
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper = shaper_with(&mut rng);
        let frame: Vec<u8> = (0..1964u32).map(|i| (i % 251) as u8).collect();
        let msgs = shaped_messages(scheme, &mut shaper, &frame, None, &mut rng);

        let mut decoded = Vec::new();
        let mut dec = PaddingDecoder::new();
        let mut data_msgs = 0;
        for m in &msgs {
            let before = decoded.len();
            dec.push(m, &mut decoded);
            if decoded.len() > before {
                data_msgs += 1;
            }
        }
        assert!(data_msgs >= 2, "seed {seed}: expected >= 2 data messages, got {data_msgs}");
        assert_eq!(decoded, frame, "seed {seed}");
        assert!(dec.is_at_frame_boundary());
    }
}

/// Once the window is spent, a frame is one ordinary padded message.
#[test]
fn shaped_messages_pass_through_after_window() {
    let scheme = PaddingScheme::new(0, 64);
    let mut rng = StdRng::seed_from_u64(7);
    let mut shaper = shaper_with(&mut rng);
    let big = vec![0xAB; 1964];
    for _ in 0..64 {
        let _ = shaped_messages(scheme, &mut shaper, &big, None, &mut rng);
    }
    assert!(!shaper.is_active());
    let msgs = shaped_messages(scheme, &mut shaper, &big, None, &mut rng);
    assert_eq!(msgs.len(), 1);
    let mut decoded = Vec::new();
    PaddingDecoder::new().push(&msgs[0], &mut decoded);
    assert_eq!(decoded, big);
}

/// With a disabled scheme the pieces are plain slices of the frame: no
/// framing, no covers.
#[test]
fn shaped_messages_disabled_scheme_returns_plain_pieces() {
    for seed in 0..32u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut shaper =
            EarlyShaper::new(ShapeDirection::ClientToServer, false, &mut draw_in(&mut rng));
        let frame: Vec<u8> = (0..1964u32).map(|i| (i % 251) as u8).collect();
        let msgs = shaped_messages(PaddingScheme::disabled(), &mut shaper, &frame, None, &mut rng);
        assert!(msgs.len() >= 2, "seed {seed}");
        assert_eq!(msgs.concat(), frame, "seed {seed}");
    }
}

/// `WsFrameSink::send_frame` hands the first write straight to
/// `shaped_messages` (a `TransportStream` cannot be built in a unit test), so
/// this exercises the VLESS path. With no held header in front, every lead-in
/// cover is a standalone pad-only message that precedes the first data piece,
/// and the 1/2 draw must show on about half of the sessions. A capture that
/// shows far fewer is an analyzer artifact, not a missing cover.
#[test]
fn vless_first_write_has_lead_in_covers_on_about_half_of_sessions() {
    let scheme = PaddingScheme::new(0, 64);
    let frame = vec![5u8; 1964];
    let mut rng = StdRng::seed_from_u64(0xFEED);
    let mut with_cover = 0;
    for _ in 0..200 {
        let mut shaper = shaper_with(&mut rng);
        let msgs = shaped_messages(scheme, &mut shaper, &frame, None, &mut rng);
        let mut dec = PaddingDecoder::new();
        let mut decoded = Vec::new();
        let mut covers_before_data = false;
        for m in &msgs {
            let before = decoded.len();
            dec.push(m, &mut decoded);
            if decoded.len() > before {
                break;
            }
            covers_before_data = true;
        }
        if covers_before_data {
            with_cover += 1;
        }
    }
    assert!(
        (70..=130).contains(&with_cover),
        "sessions with a lead-in cover: {with_cover}/200"
    );
}

/// The h2 cap leaves room for the client WS header and the padding framing at
/// the scheme's largest pad, and gives up below its floor.
#[test]
fn h2_uplink_cap_budgets_ws_header_and_padding() {
    assert_eq!(h2_uplink_cap(PaddingScheme::disabled()), Some(16375 - 8));
    assert_eq!(h2_uplink_cap(PaddingScheme::new(0, 256)), Some(16375 - 8 - 4 - 256));
    assert_eq!(h2_uplink_cap(PaddingScheme::new(0, 16_000)), None);
}

/// Capped messages decode back to the frame, each within the DATA budget, the
/// pieces even; unpadded pieces are plain slices.
#[test]
fn h2_capped_messages_round_trip_within_the_budget() {
    let frame: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    for scheme in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
        let cap = h2_uplink_cap(scheme).unwrap();
        let msgs = h2_capped_messages(scheme, cap, Bytes::from(frame.clone()), &mut seeded());
        assert_eq!(msgs.len(), 70_000usize.div_ceil(cap), "{scheme:?}");
        let mut decoded = Vec::new();
        let mut dec = PaddingDecoder::new();
        for m in &msgs {
            assert!(m.len() + H2_WS_CLIENT_HEADER_LEN <= H2_DATA_PAYLOAD_MAX, "{scheme:?}");
            if scheme.is_enabled() {
                dec.push(m, &mut decoded);
            } else {
                decoded.extend_from_slice(m);
            }
        }
        assert_eq!(decoded, frame, "{scheme:?}");
    }
}

/// With a cap, the planned piece past the window's byte budget is cut further;
/// the window's own pieces stay as planned.
#[test]
fn shaped_messages_cap_the_tail_past_the_window_budget() {
    let scheme = PaddingScheme::new(0, 64);
    let cap = h2_uplink_cap(scheme).unwrap();
    let frame: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let mut rng = seeded();
    let mut shaper = shaper_with(&mut rng);
    let msgs = shaped_messages(scheme, &mut shaper, &frame, Some(cap), &mut rng);
    let mut decoded = Vec::new();
    let mut dec = PaddingDecoder::new();
    for m in &msgs {
        assert!(m.len() + H2_WS_CLIENT_HEADER_LEN <= H2_DATA_PAYLOAD_MAX, "{}", m.len());
        dec.push(m, &mut decoded);
    }
    assert_eq!(decoded, frame);
}
