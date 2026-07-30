use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

fn sample(peer_addr: Option<SocketAddr>) -> OpenHeader {
    OpenHeader {
        framing: MeshFraming::Tcp,
        protocol: MeshProtocol::Ss,
        session_id: [0xAB; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 123_456,
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
fn close_reason_code_round_trips() {
    for reason in [
        CloseReason::Fin,
        CloseReason::Abort,
        CloseReason::Budget,
        CloseReason::Capacity,
        CloseReason::NoSession,
    ] {
        assert_eq!(CloseReason::from_code(reason.code()), reason);
    }
    // Unknown codes collapse to Abort.
    assert_eq!(CloseReason::from_code(999), CloseReason::Abort);
    // Code 4 is the retired `NoRoute`: no home performs that route lookup any
    // more, so a straggler still sending it must read as a plain abort rather
    // than as some other reason that happened to inherit the number.
    assert_eq!(CloseReason::from_code(4), CloseReason::Abort);
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
fn a_udp_vless_header_roundtrips_at_the_field_extremes() {
    let header = OpenHeader {
        framing: MeshFraming::Udp,
        protocol: MeshProtocol::Vless,
        session_id: [9u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: true,
        client_down_acked: u64::MAX,
        peer_addr: Some("198.51.100.7:443".parse().unwrap()),
    };
    let parsed = OpenHeader::parse(&header.encode()).expect("the header parses");
    assert_eq!(parsed, header);
}

/// v4 is retired: every edge in a cluster running this build speaks v5. A
/// straggler still sending a v4 OPEN gets a clean refusal — never a misparse —
/// so it serves its client locally, which is the documented "version skew costs
/// continuity, not traffic" behaviour.
#[test]
fn a_v4_frame_is_refused_outright() {
    let header = sample(None);
    let mut encoded = header.encode();
    encoded[0] = 4;
    let err = OpenHeader::parse(&encoded).expect_err("a v4 frame must be refused");
    assert!(err.to_string().contains("version"), "got: {err}");
    // The very same bytes under the current version still parse, so the refusal
    // is about the version byte and nothing else.
    assert_eq!(OpenHeader::parse(&header.encode()).unwrap(), header);
}

#[test]
fn mesh_framing_covers_only_the_two_shapes() {
    assert_eq!(MeshFraming::from_u8(0).unwrap(), MeshFraming::Tcp);
    assert_eq!(MeshFraming::from_u8(1).unwrap(), MeshFraming::Udp);
    assert!(MeshFraming::from_u8(2).is_err());
}

/// An SS OPEN names its own shape, so the ack has nothing left to say: it must
/// stay the byte every build has always sent, or an edge on an older build stops
/// understanding a home on this one.
#[test]
fn a_committed_open_keeps_the_plain_ack_byte() {
    for shape in [MeshShape::Stream, MeshShape::Datagram] {
        let committed = Some(shape);
        assert_eq!(open_ack_byte(committed, shape), OPEN_ACK_ACCEPTED);
        assert_eq!(parse_open_ack(OPEN_ACK_ACCEPTED, committed).unwrap(), shape);
        // Anything else is a home this edge does not understand; degrading to a
        // local session is the only safe reading.
        assert!(parse_open_ack(3, committed).is_err());
    }
}

/// A VLESS OPEN commits to no shape, so the ack carries the park's — the whole
/// point of the field, and the thing a third shape extends without a wire change.
#[test]
fn an_uncommitted_open_carries_the_parks_shape_in_the_ack() {
    for shape in
        [MeshShape::Stream, MeshShape::Datagram, MeshShape::VlessUdpSingle, MeshShape::VlessMux]
    {
        let byte = open_ack_byte(None, shape);
        assert_eq!(parse_open_ack(byte, None).unwrap(), shape, "{}", shape.label());
    }
    // `Stream` is deliberately the byte an older home sends: it splices nothing
    // else, so reading its plain accept as a byte-stream park is exactly right.
    assert_eq!(open_ack_byte(None, MeshShape::Stream), OPEN_ACK_ACCEPTED);
    assert!(parse_open_ack(0, None).is_err(), "zero is not a shape");
    assert!(
        parse_open_ack(9, None).is_err(),
        "a shape from a newer peer is refused, not guessed"
    );
}

/// The shape is also the body framing, and the two datagram shapes must agree on
/// it or a VLESS-UDP relay would be spliced as a byte stream.
#[test]
fn a_shapes_framing_follows_from_the_shape() {
    assert_eq!(MeshShape::Stream.framing(), Some(MeshFraming::Tcp));
    assert_eq!(MeshShape::Datagram.framing(), Some(MeshFraming::Udp));
    assert_eq!(MeshShape::VlessUdpSingle.framing(), Some(MeshFraming::Udp));
    // No splice carries a mux bundle yet, so no body ever flows under it.
    assert_eq!(MeshShape::VlessMux.framing(), None);
}

/// Which OPENs commit to a shape and which defer is what both peers read the ack
/// byte by, so it must follow from the header alone.
#[test]
fn only_a_shadowsocks_open_commits_to_a_shape() {
    let mut header = sample(None);
    assert_eq!(header.committed_shape(), Some(MeshShape::Stream));
    header.framing = MeshFraming::Udp;
    assert_eq!(header.committed_shape(), Some(MeshShape::Datagram));
    header.protocol = MeshProtocol::Vless;
    assert_eq!(header.committed_shape(), None, "a VLESS OPEN cannot know its command yet");
    header.framing = MeshFraming::Tcp;
    assert_eq!(header.committed_shape(), None);
}

/// The protocol rides a spare flag bit, so a peer built before the bit existed —
/// necessarily an SS edge — must still parse, and its cleared bit must read as
/// Shadowsocks rather than as "unknown".
#[test]
fn a_header_without_the_vless_flag_reads_as_shadowsocks() {
    let vless = OpenHeader {
        framing: MeshFraming::Tcp,
        protocol: MeshProtocol::Vless,
        session_id: [3u8; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let mut encoded = vless.encode();
    // Byte 2 is the flag byte; clearing FLAG_VLESS is exactly what an older
    // edge's encoder produces.
    encoded[2] &= !FLAG_VLESS;
    let parsed = OpenHeader::parse(&encoded).expect("an older header still parses");
    assert_eq!(parsed.protocol, MeshProtocol::Ss);
    assert_eq!(parsed.session_id, vless.session_id, "the rest of the header is unaffected");
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
            CloseReason::Capacity => Some(CloseReason::NoSession),
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
    assert_eq!(reasons, 5, "every CloseReason variant must be swept");
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
