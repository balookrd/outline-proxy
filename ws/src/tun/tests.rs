use super::{
    EBUSY_OS_ERROR, IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_MIN_PATH_MTU, IPV6_NEXT_HEADER_FRAGMENT,
    PacketDisposition, build_icmp_echo_reply, build_icmp_echo_reply_packets, checksum16,
    classify_packet, icmpv6_checksum, is_tun_device_busy_error,
};
use crate::tun::defrag::{DefragmentedPacket, TunDefragmenter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn tcp_packets_are_classified_for_tun_tcp_path() {
    let packet = [
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
}

#[test]
fn ipv6_tcp_packets_with_destination_options_are_classified_for_tun_tcp_path() {
    let packet = build_ipv6_tcp_packet_with_extension_header(60, 6);
    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
}

#[test]
fn ipv6_udp_packets_with_destination_options_are_classified_for_tun_udp_path() {
    let packet = build_ipv6_udp_packet_with_extension_header();
    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
}

#[test]
fn ipv6_fragmented_packets_are_reported_as_unsupported() {
    let packet = build_ipv6_tcp_packet_with_extension_header(44, 6);
    assert_eq!(
        classify_packet(&packet).unwrap(),
        PacketDisposition::Unsupported("IPv6 fragments are not supported on TUN")
    );
}

#[test]
fn ipv4_icmp_echo_request_gets_local_reply() {
    let packet = build_ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        0x1234,
        0x0007,
        b"ping",
    );

    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::IcmpEchoRequest);
    let reply = build_icmp_echo_reply(&packet).unwrap();

    assert_eq!(reply[9], 1);
    assert_eq!(reply[12..16], [8, 8, 8, 8]);
    assert_eq!(reply[16..20], [10, 0, 0, 2]);
    assert_eq!(reply[IPV4_HEADER_LEN], 0);
    assert_eq!(reply[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 8], [0x12, 0x34, 0x00, 0x07]);
    assert_eq!(&reply[IPV4_HEADER_LEN + 8..], b"ping");
    assert_eq!(
        checksum16(&reply[IPV4_HEADER_LEN..usize::from(u16::from_be_bytes([reply[2], reply[3]]))]),
        0
    );
}

#[test]
fn ipv6_icmp_echo_request_gets_local_reply() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let packet = build_ipv6_icmp_echo_request(source, destination, 0xabcd, 0x0002, b"pong");

    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::IcmpEchoRequest);
    let reply = build_icmp_echo_reply(&packet).unwrap();

    assert_eq!(reply[6], 58);
    assert_eq!(reply[8..24], destination.octets());
    assert_eq!(reply[24..40], source.octets());
    assert_eq!(reply[IPV6_HEADER_LEN], 129);
    assert_eq!(reply[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 8], [0xab, 0xcd, 0x00, 0x02]);
    assert_eq!(&reply[IPV6_HEADER_LEN + 8..], b"pong");
    let checksum = icmpv6_checksum(destination, source, &reply[IPV6_HEADER_LEN..]);
    assert_eq!(checksum, 0);
}

#[test]
fn ipv6_icmp_echo_request_with_destination_options_gets_local_reply() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let packet = build_ipv6_icmp_echo_request_with_extension_header(
        source,
        destination,
        0xabcd,
        0x0002,
        b"pong",
    );

    assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::IcmpEchoRequest);
    let reply = build_icmp_echo_reply(&packet).unwrap();
    let (_, payload_offset, total_len) = crate::tun::wire::locate_ipv6_upper_layer(&reply).unwrap();

    assert_eq!(reply[8..24], destination.octets());
    assert_eq!(reply[24..40], source.octets());
    assert_eq!(reply[payload_offset], 129);
    assert_eq!(reply[payload_offset + 4..payload_offset + 8], [0xab, 0xcd, 0x00, 0x02]);
    assert_eq!(&reply[payload_offset + 8..total_len], b"pong");
    let checksum = icmpv6_checksum(destination, source, &reply[payload_offset..total_len]);
    assert_eq!(checksum, 0);
}

#[test]
fn large_ipv6_icmp_echo_replies_are_fragmented_to_minimum_mtu() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let payload = vec![0x5a; 1452];
    let packet = build_ipv6_icmp_echo_request(source, destination, 0xabcd, 0x0002, &payload);

    let fragments = build_icmp_echo_reply_packets(&packet).unwrap();
    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[0].len(), IPV6_MIN_PATH_MTU);
    assert!(fragments.iter().all(|fragment| fragment.len() <= IPV6_MIN_PATH_MTU));
    assert_eq!(fragments[0][6], IPV6_NEXT_HEADER_FRAGMENT);

    let mut defrag = TunDefragmenter::default();
    assert!(matches!(defrag.push(&fragments[0]).unwrap(), DefragmentedPacket::Pending));
    let reassembled = match defrag.push(&fragments[1]).unwrap() {
        DefragmentedPacket::ReadyOwned(packet) => packet,
        other => panic!("unexpected result: {other:?}"),
    };
    let (_, payload_offset, total_len) =
        crate::tun::wire::locate_ipv6_upper_layer(&reassembled).unwrap();
    assert_eq!(reassembled[8..24], destination.octets());
    assert_eq!(reassembled[24..40], source.octets());
    assert_eq!(reassembled[payload_offset], 129);
    assert_eq!(reassembled[payload_offset + 4..payload_offset + 8], [0xab, 0xcd, 0x00, 0x02]);
    assert_eq!(&reassembled[payload_offset + 8..total_len], payload.as_slice());
    let checksum = icmpv6_checksum(destination, source, &reassembled[payload_offset..total_len]);
    assert_eq!(checksum, 0);
}

#[test]
fn detects_busy_tun_attach_errors_from_context_chain() {
    let error = anyhow::Error::from(std::io::Error::from_raw_os_error(EBUSY_OS_ERROR))
        .context("TUNSETIFF failed");
    assert!(is_tun_device_busy_error(&error));
}

fn build_ipv4_icmp_echo_request(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = IPV4_HEADER_LEN + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    let icmp_offset = IPV4_HEADER_LEN;
    packet[icmp_offset] = 8;
    packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
    packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[icmp_offset + 8..].copy_from_slice(payload);
    let icmp_checksum = checksum16(&packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
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
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    let icmp_offset = IPV6_HEADER_LEN;
    packet[icmp_offset] = 128;
    packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
    packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[icmp_offset + 8..].copy_from_slice(payload);
    let checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_tcp_packet_with_extension_header(next_header: u8, terminal_header: u8) -> Vec<u8> {
    let extension_len = 8usize;
    let tcp_len = 20usize;
    let total_len = IPV6_HEADER_LEN + extension_len + tcp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + tcp_len) as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
    packet[IPV6_HEADER_LEN] = terminal_header;
    if next_header == 44 {
        packet[IPV6_HEADER_LEN + 1] = 0;
    } else {
        packet[IPV6_HEADER_LEN + 1] = 0;
    }
    packet[IPV6_HEADER_LEN + extension_len + 12] = 0x50;
    packet[IPV6_HEADER_LEN + extension_len + 13] = 0x10;
    packet
}

fn build_ipv6_udp_packet_with_extension_header() -> Vec<u8> {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let udp_len = 8usize;
    let extension_len = 8usize;
    let total_len = IPV6_HEADER_LEN + extension_len + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40] = 17;
    packet[48..50].copy_from_slice(&53u16.to_be_bytes());
    packet[50..52].copy_from_slice(&40000u16.to_be_bytes());
    packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let checksum = crate::tun::wire::ipv6_payload_checksum(source, destination, 17, &packet[48..]);
    packet[54..56].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn build_ipv6_icmp_echo_request_with_extension_header(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let extension_len = 8usize;
    let total_len = IPV6_HEADER_LEN + extension_len + icmp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + icmp_len) as u16).to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = 58;
    let icmp_offset = IPV6_HEADER_LEN + extension_len;
    packet[icmp_offset] = 128;
    packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
    packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[icmp_offset + 8..].copy_from_slice(payload);
    let checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    packet
}
