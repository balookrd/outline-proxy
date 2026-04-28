use std::net::Ipv4Addr;

use crate::udp::parse_udp_request;

use super::*;

#[test]
fn udp_fragment_reassembly_round_trip() {
    let mut reassembler = UdpFragmentReassembler::default();
    let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 53);

    let first = vec![0, 0, 1];
    let second = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 2];

    let mut packet = first;
    packet.extend_from_slice(&target.to_wire_bytes().unwrap());
    packet.extend_from_slice(b"hel");
    let parsed = parse_udp_request(&packet).unwrap();
    assert!(reassembler.push_fragment(parsed).unwrap().is_none());

    let mut packet = second;
    packet.extend_from_slice(&target.to_wire_bytes().unwrap());
    packet.extend_from_slice(b"lo");
    let parsed = parse_udp_request(&packet).unwrap();
    let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

    assert_eq!(reassembled.target, target);
    assert_eq!(reassembled.payload, b"hello");
}

#[test]
fn udp_fragment_reassembly_rejects_oversized_sequence() {
    let mut reassembler = UdpFragmentReassembler::default();
    let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 53);
    let target_wire = target.to_wire_bytes().unwrap();

    let chunk = vec![0u8; 64 * 1024];
    let fragments_to_exceed_cap = SOCKS5_UDP_REASSEMBLY_MAX_BYTES / chunk.len() + 2;

    let mut rejected = false;
    for i in 1..=fragments_to_exceed_cap {
        let mut packet = vec![0, 0, i as u8];
        packet.extend_from_slice(&target_wire);
        packet.extend_from_slice(&chunk);
        let parsed = parse_udp_request(&packet).unwrap();
        match reassembler.push_fragment(parsed) {
            Ok(_) => {}
            Err(_) => {
                rejected = true;
                break;
            }
        }
    }
    assert!(rejected, "expected reassembler to bail once byte cap was crossed");

    let mut packet = vec![0, 0, 0];
    packet.extend_from_slice(&target_wire);
    packet.extend_from_slice(b"ok");
    let parsed = parse_udp_request(&packet).unwrap();
    let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();
    assert_eq!(reassembled.payload, b"ok");
}

#[test]
fn udp_fragment_reassembly_resets_on_lower_fragment_number() {
    let mut reassembler = UdpFragmentReassembler::default();
    let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 4, 4), 53);

    let mut packet = vec![0, 0, 2];
    packet.extend_from_slice(&target.to_wire_bytes().unwrap());
    packet.extend_from_slice(b"stale");
    let parsed = parse_udp_request(&packet).unwrap();
    assert!(reassembler.push_fragment(parsed).unwrap().is_none());

    let mut packet = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 1];
    packet.extend_from_slice(&target.to_wire_bytes().unwrap());
    packet.extend_from_slice(b"fresh");
    let parsed = parse_udp_request(&packet).unwrap();
    let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

    assert_eq!(reassembled.payload, b"fresh");
}
