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
