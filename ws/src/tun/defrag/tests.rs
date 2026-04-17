use super::{DefragmentedPacket, TunDefragmenter};
use crate::tun::build_icmp_echo_reply;
use crate::tun::tcp::parse_tcp_packet_for_tests as parse_tcp_packet;
use crate::tun::udp::{build_ipv4_udp_packet, parse_udp_packet};
use crate::tun::wire::test_utils::{assert_transport_checksum_valid, transport_offset};
use crate::tun::wire::{
    IPV6_HEADER_LEN, IPV6_NEXT_HEADER_DESTINATION_OPTIONS, IPV6_NEXT_HEADER_FRAGMENT,
    IPV6_NEXT_HEADER_ICMPV6, IPV6_NEXT_HEADER_UDP, checksum16, ipv6_payload_checksum,
    locate_ipv6_payload, locate_ipv6_upper_layer,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[test]
fn passes_through_non_fragmented_ipv4_packets() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        53,
        40000,
        b"hello",
    )
    .unwrap();
    let mut defrag = TunDefragmenter::default();
    match defrag.push(&packet).unwrap() {
        DefragmentedPacket::ReadyBorrowed => {},
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn reassembles_ipv4_udp_fragments() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        53,
        40000,
        b"hello fragmented udp",
    )
    .unwrap();
    let fragments =
        fragment_ipv4_packet(&packet, &[16, packet.len() - transport_offset(&packet) - 16]);
    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[1]).unwrap(), DefragmentedPacket::Pending));
    let reassembled = match defrag.push(&fragments[0]).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(reassembled, packet);
    let parsed = parse_udp_packet(&reassembled).unwrap();
    assert_eq!(parsed.payload, b"hello fragmented udp");
}

#[test]
fn drops_overlapping_ipv4_fragments() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        53,
        40000,
        b"hello fragmented udp",
    )
    .unwrap();
    let fragments =
        fragment_ipv4_packet(&packet, &[16, packet.len() - transport_offset(&packet) - 16]);
    let mut overlapping = fragments[1].clone();
    let offset_units = 1u16.to_be_bytes();
    overlapping[6] = offset_units[0];
    overlapping[7] = offset_units[1];

    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[0]).unwrap(), DefragmentedPacket::Pending));
    assert!(matches!(defrag.push(&overlapping).unwrap(), DefragmentedPacket::Dropped(_)));
}

#[test]
fn reassembles_ipv6_udp_fragments_with_extension_headers() {
    let packet = build_ipv6_udp_packet_with_destination_options(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        5353,
        41000,
        b"hello over ipv6 fragments",
    );
    let fragments = fragment_ipv6_packet(&packet, 16);
    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[1]).unwrap(), DefragmentedPacket::Pending));
    let reassembled = match defrag.push(&fragments[0]).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };
    let parsed = parse_udp_packet(&reassembled).unwrap();
    assert_eq!(parsed.payload, b"hello over ipv6 fragments");
    let (next_header, _, _) = locate_ipv6_upper_layer(&reassembled).unwrap();
    assert_eq!(next_header, IPV6_NEXT_HEADER_UDP);
    assert_transport_checksum_valid(&reassembled, IPV6_NEXT_HEADER_UDP);
}

#[test]
fn reassembles_ipv6_atomic_fragment_for_icmpv6() {
    let packet = build_ipv6_icmp_echo_request_with_fragment_header(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        0x1234,
        0x0007,
        b"ping",
        false,
    );
    let mut defrag = TunDefragmenter::default();
    let reassembled = match defrag.push(&packet).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };
    let reply = build_icmp_echo_reply(&reassembled).unwrap();
    assert_eq!(reply[transport_offset(&reply)], 129);
}

#[test]
fn reassembles_ipv6_icmp_fragments_and_builds_local_reply() {
    let packet = build_ipv6_icmp_echo_request(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        0x3701,
        0x0044,
        &[0x5a; 1452],
    );
    let fragments = fragment_ipv6_packet(&packet, 1368);

    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[0].len(), IPV6_HEADER_LEN + 8 + 1368);
    assert_eq!(fragments[1].len(), IPV6_HEADER_LEN + 8 + 92);

    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[0]).unwrap(), DefragmentedPacket::Pending));
    let reassembled = match defrag.push(&fragments[1]).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };

    let reply = build_icmp_echo_reply(&reassembled).unwrap();
    let (_, payload_offset, total_len) = locate_ipv6_upper_layer(&reply).unwrap();

    assert_eq!(reply[payload_offset], 129);
    assert_eq!(reply[payload_offset + 4..payload_offset + 8], [0x37, 0x01, 0x00, 0x44]);
    assert_eq!(total_len, IPV6_HEADER_LEN + 1460);
    assert_transport_checksum_valid(&reply, IPV6_NEXT_HEADER_ICMPV6);
}

#[test]
fn maintenance_sweeps_expired_fragment_sets_without_new_fragments() {
    let packet = build_ipv6_icmp_echo_request(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        0x3701,
        0x0044,
        &[0x5a; 1452],
    );
    let fragments = fragment_ipv6_packet(&packet, 1368);

    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[0]).unwrap(), DefragmentedPacket::Pending));
    assert_eq!(defrag.ipv6_sets.len(), 1);
    assert!(defrag.total_buffered_bytes > 0);

    let key = *defrag.ipv6_sets.keys().next().expect("fragment set");
    defrag.ipv6_sets.get_mut(&key).expect("fragment set").deadline =
        Instant::now() - Duration::from_secs(1);
    defrag.next_cleanup_at = Instant::now() - Duration::from_secs(1);

    defrag.run_maintenance();

    assert!(defrag.ipv6_sets.is_empty());
    assert_eq!(defrag.total_buffered_bytes, 0);
}

#[test]
fn reassembles_ipv6_tcp_fragments() {
    let packet = build_ipv6_tcp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        40000,
        443,
        b"hello",
    );
    let fragments = fragment_ipv6_packet(&packet, 24);
    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[0]).unwrap(), DefragmentedPacket::Pending));
    let reassembled = match defrag.push(&fragments[1]).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };
    let _ = parse_tcp_packet(&reassembled).unwrap();
    let tcp_offset = transport_offset(&reassembled);
    assert_eq!(&reassembled[tcp_offset + 20..], b"hello");
}

fn fragment_ipv4_packet(packet: &[u8], payload_sizes: &[usize]) -> Vec<Vec<u8>> {
    let header_len = transport_offset(packet);
    let payload = &packet[header_len..];
    let identification = [packet[4], packet[5]];
    let protocol = packet[9];
    let mut fragments = Vec::new();
    let mut cursor = 0usize;
    for (index, &size) in payload_sizes.iter().enumerate() {
        let end = cursor + size;
        let more = end < payload.len();
        let total_len = header_len + size;
        let mut fragment = vec![0u8; total_len];
        fragment[..header_len].copy_from_slice(&packet[..header_len]);
        fragment[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        fragment[4..6].copy_from_slice(&identification);
        let mut fragment_field = ((cursor / 8) as u16) & 0x1fff;
        if more {
            fragment_field |= 0x2000;
        }
        fragment[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        fragment[10..12].copy_from_slice(&0u16.to_be_bytes());
        fragment[header_len..].copy_from_slice(&payload[cursor..end]);
        let checksum = checksum16(&fragment[..header_len]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(fragment[9], protocol);
        fragments.push(fragment);
        cursor = end;
        let _ = index;
    }
    fragments
}

fn fragment_ipv6_packet(packet: &[u8], first_payload_len: usize) -> Vec<Vec<u8>> {
    let info = locate_ipv6_payload(packet).unwrap();
    let transport_offset = info.payload_offset;
    let previous_next_header_offset = info.next_header_field_offset;
    let upper_layer_header = info.next_header;
    let unfragmentable = &packet[..transport_offset];
    let fragmentable = &packet[transport_offset..];
    let first_len = first_payload_len.min(fragmentable.len());
    let split = first_len - (first_len % 8);
    let second_offset = split;
    let first_payload = &fragmentable[..split];
    let second_payload = &fragmentable[split..];
    let identification = 0x0102_0304u32;

    let mut fragments = Vec::new();
    for (offset, payload, more) in [
        (0usize, first_payload, !second_payload.is_empty()),
        (second_offset, second_payload, false),
    ] {
        if payload.is_empty() {
            continue;
        }
        let total_len = unfragmentable.len() + 8 + payload.len();
        let mut fragment = vec![0u8; total_len];
        fragment[..unfragmentable.len()].copy_from_slice(unfragmentable);
        fragment[4..6].copy_from_slice(&((total_len - IPV6_HEADER_LEN) as u16).to_be_bytes());
        fragment[previous_next_header_offset] = IPV6_NEXT_HEADER_FRAGMENT;
        fragment[transport_offset] = upper_layer_header;
        fragment[transport_offset + 1] = 0;
        let fragment_offset_field = (((offset / 8) as u16) << 3) | u16::from(more);
        fragment[transport_offset + 2..transport_offset + 4]
            .copy_from_slice(&fragment_offset_field.to_be_bytes());
        fragment[transport_offset + 4..transport_offset + 8]
            .copy_from_slice(&identification.to_be_bytes());
        fragment[transport_offset + 8..].copy_from_slice(payload);
        fragments.push(fragment);
    }
    fragments
}

fn build_ipv6_udp_packet_with_destination_options(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let extension_len = 8usize;
    let total_len = IPV6_HEADER_LEN + extension_len + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
    packet[6] = IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = IPV6_NEXT_HEADER_UDP;
    packet[48..50].copy_from_slice(&source_port.to_be_bytes());
    packet[50..52].copy_from_slice(&destination_port.to_be_bytes());
    packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[56..].copy_from_slice(payload);
    let checksum =
        ipv6_payload_checksum(source_ip, destination_ip, IPV6_NEXT_HEADER_UDP, &packet[48..]);
    packet[54..56].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_icmp_echo_request_with_fragment_header(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    more_fragments: bool,
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = IPV6_HEADER_LEN + 8 + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((8 + icmp_len) as u16).to_be_bytes());
    packet[6] = IPV6_NEXT_HEADER_FRAGMENT;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = IPV6_NEXT_HEADER_ICMPV6;
    packet[42..44].copy_from_slice(&(u16::from(more_fragments)).to_be_bytes());
    packet[44..48].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    packet[48] = 128;
    packet[52..54].copy_from_slice(&identifier.to_be_bytes());
    packet[54..56].copy_from_slice(&sequence.to_be_bytes());
    packet[56..].copy_from_slice(payload);
    let checksum =
        ipv6_payload_checksum(source_ip, destination_ip, IPV6_NEXT_HEADER_ICMPV6, &packet[48..]);
    packet[50..52].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_icmp_echo_request(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = IPV6_HEADER_LEN + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = IPV6_NEXT_HEADER_ICMPV6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = 128;
    packet[44..46].copy_from_slice(&identifier.to_be_bytes());
    packet[46..48].copy_from_slice(&sequence.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let checksum =
        ipv6_payload_checksum(source_ip, destination_ip, IPV6_NEXT_HEADER_ICMPV6, &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_tcp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = IPV6_HEADER_LEN + tcp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[52] = 0x50;
    packet[53] = 0x18;
    packet[54..56].copy_from_slice(&4096u16.to_be_bytes());
    packet[60..].copy_from_slice(payload);
    let checksum = ipv6_payload_checksum(source_ip, destination_ip, 6, &packet[40..]);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());
    packet
}
