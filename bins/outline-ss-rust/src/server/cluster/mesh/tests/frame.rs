use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

fn sample(peer_addr: Option<SocketAddr>) -> OpenHeader {
    OpenHeader {
        carrier: CarrierKind::VlessTcp,
        session_id: [0xAB; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 123_456,
        path: "/vless".to_string(),
        peer_addr,
    }
}

#[test]
fn round_trip_without_peer_addr() {
    let h = sample(None);
    assert_eq!(OpenHeader::parse(&h.encode()).unwrap(), h);
}

#[test]
fn round_trip_with_ipv4_peer() {
    let h = sample(Some(SocketAddr::new(Ipv4Addr::new(203, 0, 113, 7).into(), 51820)));
    assert_eq!(OpenHeader::parse(&h.encode()).unwrap(), h);
}

#[test]
fn round_trip_with_ipv6_peer() {
    let h = sample(Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443)));
    assert_eq!(OpenHeader::parse(&h.encode()).unwrap(), h);
}

#[test]
fn round_trip_all_carrier_kinds() {
    for carrier in [
        CarrierKind::SsTcp,
        CarrierKind::SsUdp,
        CarrierKind::VlessTcp,
        CarrierKind::VlessUdp,
        CarrierKind::SsXhttp,
        CarrierKind::VlessXhttp,
        CarrierKind::SsUdpXhttp,
    ] {
        let mut h = sample(None);
        h.carrier = carrier;
        assert_eq!(OpenHeader::parse(&h.encode()).unwrap().carrier, carrier);
    }
}

#[test]
fn round_trip_empty_path() {
    let mut h = sample(None);
    h.path = String::new();
    assert_eq!(OpenHeader::parse(&h.encode()).unwrap(), h);
}

#[test]
fn parse_rejects_truncated() {
    let bytes = sample(None).encode();
    // Every proper prefix shorter than the whole header must be rejected, not
    // panic.
    for cut in 0..bytes.len() {
        assert!(OpenHeader::parse(&bytes[..cut]).is_err(), "prefix len {cut} must error");
    }
}

#[test]
fn parse_rejects_bad_version() {
    let mut bytes = sample(None).encode();
    bytes[0] = 0xFF;
    assert!(OpenHeader::parse(&bytes).is_err());
}

#[test]
fn parse_rejects_overlong_path() {
    // Hand-build a header claiming a path far past the cap.
    let mut bytes = sample(None).encode();
    // path_len is the u16 right after version(1)+carrier(1)+flags(1)+
    // down_acked(8)+session_id(16) = offset 27.
    bytes[27] = 0xFF;
    bytes[28] = 0xFF;
    assert!(OpenHeader::parse(&bytes).is_err());
}

#[test]
fn close_reason_code_round_trips() {
    for reason in [
        CloseReason::Fin,
        CloseReason::Abort,
        CloseReason::Budget,
        CloseReason::Capacity,
        CloseReason::NoRoute,
    ] {
        assert_eq!(CloseReason::from_code(reason.code()), reason);
    }
    // Unknown codes collapse to Abort.
    assert_eq!(CloseReason::from_code(999), CloseReason::Abort);
}

#[test]
fn user_frame_roundtrips() {
    let frame = UserFrame { user: "beerloga".to_string() };
    let parsed = UserFrame::parse(&frame.encode()).expect("user frame parses");
    assert_eq!(parsed.user, "beerloga");
}

#[test]
fn user_frame_roundtrips_at_the_length_ceiling() {
    let frame = UserFrame { user: "u".repeat(MAX_USER_LEN) };
    let parsed = UserFrame::parse(&frame.encode()).expect("a max-length name is valid");
    assert_eq!(parsed.user.len(), MAX_USER_LEN);
}

#[test]
fn user_frame_rejects_empty_name() {
    let encoded = vec![0u8]; // len = 0
    let err = UserFrame::parse(&encoded).expect_err("an empty user must be refused");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[test]
fn user_frame_rejects_over_long_name() {
    let frame = UserFrame { user: "u".repeat(MAX_USER_LEN + 1) };
    let err = UserFrame::parse(&frame.encode()).expect_err("an over-long user must be refused");
    assert!(err.to_string().contains("too long"), "got: {err}");
}

#[test]
fn user_frame_rejects_invalid_utf8() {
    let encoded = vec![2u8, 0xff, 0xfe];
    let err = UserFrame::parse(&encoded).expect_err("invalid UTF-8 must be refused");
    assert!(err.to_string().contains("UTF-8"), "got: {err}");
}

#[test]
fn user_frame_rejects_a_truncated_buffer() {
    let encoded = vec![8u8, b'a', b'b']; // claims 8 bytes, carries 2
    UserFrame::parse(&encoded).expect_err("a truncated frame must be refused");
}

#[test]
fn no_session_close_reason_roundtrips_on_the_wire() {
    assert_eq!(CloseReason::NoSession.code(), 5);
    assert_eq!(CloseReason::from_code(5), CloseReason::NoSession);
}

#[test]
fn v5_header_roundtrips_without_peer_addr() {
    let header = OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: [7u8; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 4096,
        peer_addr: None,
    };
    let parsed = OpenHeaderV5::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn v5_header_roundtrips_with_peer_addr() {
    let header = OpenHeaderV5 {
        framing: MeshFraming::Udp,
        session_id: [9u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: true,
        client_down_acked: u64::MAX,
        peer_addr: Some("198.51.100.7:443".parse().unwrap()),
    };
    let parsed = OpenHeaderV5::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn v5_parser_refuses_a_v4_frame_and_vice_versa() {
    let v5 = OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: [1u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let mut encoded = v5.encode();
    encoded[0] = 4;
    OpenHeaderV5::parse(&encoded).expect_err("a v4 frame is not a v5 frame");
    // ...and the v4 parser refuses a v5 frame, which is what makes a mixed
    // cluster degrade to a lost resume rather than a misparsed stream.
    OpenHeader::parse(&v5.encode()).expect_err("a v5 frame is not a v4 frame");
}

#[test]
fn peek_open_version_reads_the_leading_byte_without_consuming() {
    let v5 = OpenHeaderV5 {
        framing: MeshFraming::Udp,
        session_id: [2u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let encoded = v5.encode();
    assert_eq!(peek_open_version(&encoded).unwrap(), 5);
    // The frame is still fully parseable afterwards.
    assert_eq!(OpenHeaderV5::parse(&encoded).unwrap(), v5);
    assert!(peek_open_version(&[]).is_err(), "an empty buffer has no version");
}

#[test]
fn mesh_framing_covers_only_the_two_shapes() {
    assert_eq!(MeshFraming::from_u8(0).unwrap(), MeshFraming::Tcp);
    assert_eq!(MeshFraming::from_u8(1).unwrap(), MeshFraming::Udp);
    assert!(MeshFraming::from_u8(2).is_err());
}

#[test]
fn upstream_ack_frame_roundtrips() {
    for acked in [0u64, 1, 12, 65_536, u64::MAX] {
        let frame = UpstreamAckFrame { upstream_acked: acked };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), UPSTREAM_ACK_FRAME_LEN, "the frame is fixed-size");
        assert_eq!(UpstreamAckFrame::parse(&encoded).unwrap(), frame);
    }
}

#[test]
fn upstream_ack_frame_refuses_a_truncated_buffer() {
    let encoded = UpstreamAckFrame { upstream_acked: 42 }.encode();
    UpstreamAckFrame::parse(&encoded[..7]).expect_err("a short frame must be refused");
}

#[test]
fn close_intent_roundtrips_on_the_wire() {
    for intent in [CloseIntent::CarrierEnded, CloseIntent::ClientDone] {
        assert_eq!(CloseIntent::from_code(u64::from(intent.code())), intent);
    }
}

#[test]
fn an_unknown_close_intent_reads_as_a_carrier_switch() {
    // The conservative reading: re-park and let the TTL decide. Code 0 matters
    // in particular — that is what an ordinary quinn `RecvStream` drop sends.
    for code in [0u64, 1, 5, 0x5000, 0x5003, u64::from(u32::MAX), u64::MAX] {
        assert_eq!(CloseIntent::from_code(code), CloseIntent::CarrierEnded, "code {code}");
    }
}

/// Calls `visit` once for every [`CloseReason`] variant, in declaration order.
///
/// Exhaustive by construction, which is the whole point: the `match` hands back
/// each variant's successor, so a variant added later stops this file compiling
/// until it is linked into the chain — where a hand-written list would have let
/// it slip past the checks below in silence.
fn for_each_close_reason(mut visit: impl FnMut(CloseReason)) {
    let mut next = Some(CloseReason::Fin);
    while let Some(reason) = next {
        visit(reason);
        next = match reason {
            CloseReason::Fin => Some(CloseReason::Abort),
            CloseReason::Abort => Some(CloseReason::Budget),
            CloseReason::Budget => Some(CloseReason::Capacity),
            CloseReason::Capacity => Some(CloseReason::NoRoute),
            CloseReason::NoRoute => Some(CloseReason::NoSession),
            CloseReason::NoSession => None,
        };
    }
}

/// The [`CloseIntent`] twin of [`for_each_close_reason`], exhaustive the same
/// way.
fn for_each_close_intent(mut visit: impl FnMut(CloseIntent)) {
    let mut next = Some(CloseIntent::CarrierEnded);
    while let Some(intent) = next {
        visit(intent);
        next = match intent {
            CloseIntent::CarrierEnded => Some(CloseIntent::ClientDone),
            CloseIntent::ClientDone => None,
        };
    }
}

#[test]
fn close_intent_codes_never_collide_with_a_close_reason() {
    // They ride different QUIC frames on the same stream (STOP_SENDING vs
    // RESET_STREAM), so an overlap would only ever confuse a reader — but a
    // disjoint range is what makes a stray code obviously one or the other.
    let mut reasons = 0;
    for_each_close_reason(|reason| {
        reasons += 1;
        for_each_close_intent(|intent| {
            assert_ne!(reason.code(), intent.code(), "{reason:?} collides with {intent:?}");
        });
    });
    // Guards the chain itself: an arm rewired to skip a variant shows up here
    // rather than as a silently narrower sweep above.
    assert_eq!(reasons, 6, "every CloseReason variant must be swept");
}

#[test]
fn every_close_intent_has_its_own_metric_label() {
    // The `close` label on `outline_ss_mesh_relay_outcome_total` is only a
    // usable ratio if the two intents never render as the same string.
    let mut labels = Vec::new();
    for_each_close_intent(|intent| labels.push(intent.metric_label()));
    labels.sort_unstable();
    let count = labels.len();
    labels.dedup();
    assert_eq!(labels.len(), count, "two intents share a metric label: {labels:?}");
}
