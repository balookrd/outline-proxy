use super::wire::{build_ipv4_udp_packet, build_ipv6_udp_packet};
use super::{IpVersion, parse_udp_packet};
use crate::tun_wire::test_utils::{
    IP_PROTOCOL_UDP, assert_ipv4_header_checksum_valid, assert_transport_checksum_valid,
    corrupt_ip_length_field, corrupt_udp_length_field, random_payload, seeded_rng,
};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn ipv4_udp_roundtrip() {
    let packet = build_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 2),
        53,
        40000,
        b"hello",
    )
    .unwrap();

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V4);
    assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        parsed.destination_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(parsed.source_port, 53);
    assert_eq!(parsed.destination_port, 40000);
    assert_eq!(parsed.payload, b"hello");
}

#[test]
fn ipv6_udp_roundtrip() {
    let packet = build_ipv6_udp_packet(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
        5353,
        41000,
        b"world",
    )
    .unwrap();

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V6);
    assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(
        parsed.destination_ip,
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
    );
    assert_eq!(parsed.source_port, 5353);
    assert_eq!(parsed.destination_port, 41000);
    assert_eq!(parsed.payload, b"world");
}

#[test]
fn ipv6_udp_roundtrip_with_destination_options() {
    let source_ip = Ipv6Addr::LOCALHOST;
    let destination_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let payload = b"world";
    let udp_len = 8 + payload.len();
    let extension_len = 8usize;
    let total_len = crate::tun_wire::IPV6_HEADER_LEN + extension_len + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
    packet[6] = crate::tun_wire::IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    packet[40] = IP_PROTOCOL_UDP;
    packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
    packet[50..52].copy_from_slice(&41000u16.to_be_bytes());
    packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[56..].copy_from_slice(payload);
    let checksum = crate::tun_wire::ipv6_payload_checksum(
        source_ip,
        destination_ip,
        IP_PROTOCOL_UDP,
        &packet[48..],
    );
    packet[54..56].copy_from_slice(&checksum.to_be_bytes());

    let parsed = parse_udp_packet(&packet).unwrap();
    assert_eq!(parsed.version, IpVersion::V6);
    assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
    assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
    assert_eq!(parsed.source_port, 5353);
    assert_eq!(parsed.destination_port, 41000);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn randomized_udp_packet_roundtrip_and_mutation_smoke() {
    let mut rng = seeded_rng(0x5eed_4eed);
    for _ in 0..128 {
        let payload = random_payload(&mut rng, 63);
        let source_port = rng.gen_range(1..=65000);
        let destination_port = rng.gen_range(1..=65000);

        if rng.gen_bool(0.5) {
            let source_ip = Ipv4Addr::new(8, 8, 4, rng.gen_range(1..=250));
            let destination_ip = Ipv4Addr::new(10, 0, 0, rng.gen_range(2..=250));
            let packet = build_ipv4_udp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                &payload,
            )
            .unwrap();

            assert_ipv4_header_checksum_valid(&packet);
            assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

            let parsed = parse_udp_packet(&packet).unwrap();
            assert_eq!(parsed.version, IpVersion::V4);
            assert_eq!(parsed.source_ip, IpAddr::V4(source_ip));
            assert_eq!(parsed.destination_ip, IpAddr::V4(destination_ip));
            assert_eq!(parsed.source_port, source_port);
            assert_eq!(parsed.destination_port, destination_port);
            assert_eq!(parsed.payload, payload);

            assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
            assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
        } else {
            let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
            let destination_ip =
                Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
            let packet = build_ipv6_udp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                &payload,
            )
            .unwrap();

            assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

            let parsed = parse_udp_packet(&packet).unwrap();
            assert_eq!(parsed.version, IpVersion::V6);
            assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
            assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
            assert_eq!(parsed.source_port, source_port);
            assert_eq!(parsed.destination_port, destination_port);
            assert_eq!(parsed.payload, payload);

            assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
            assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
        }
    }
}
