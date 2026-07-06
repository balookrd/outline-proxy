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
    for carrier in
        [CarrierKind::SsTcp, CarrierKind::SsUdp, CarrierKind::VlessTcp, CarrierKind::VlessUdp]
    {
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
    for reason in [CloseReason::Fin, CloseReason::Abort, CloseReason::Budget] {
        assert_eq!(CloseReason::from_code(reason.code()), reason);
    }
    // Unknown codes collapse to Abort.
    assert_eq!(CloseReason::from_code(999), CloseReason::Abort);
}
