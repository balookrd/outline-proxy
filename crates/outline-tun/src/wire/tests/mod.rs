use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socks5_proto::TargetAddr;

use super::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_TCP, IPV6_NEXT_HEADER_UDP, checksum16,
    checksum16_parts, ipv4_payload_checksum, ipv6_payload_checksum, recompute_transport_checksum,
    target_socket_addr,
};

#[test]
fn checksum16_parts_matches_flat_buffer_for_odd_boundaries() {
    let parts = [b"\x12".as_slice(), b"\x34\x56".as_slice(), b"\x78\x9a\xbc".as_slice()];
    let flat = b"\x12\x34\x56\x78\x9a\xbc";
    assert_eq!(checksum16_parts(&parts), checksum16(flat));
}

/// The pre-vectorization scalar internet-checksum, kept as an independent
/// reference so the wide u64 implementation is cross-checked against it.
fn checksum16_reference(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut pending = None;
    for part in parts {
        for &byte in *part {
            match pending.take() {
                Some(high) => sum = sum.wrapping_add(u32::from(u16::from_be_bytes([high, byte]))),
                None => pending = Some(byte),
            }
        }
    }
    if let Some(high) = pending {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([high, 0])));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn checksum16_parts_wide_matches_scalar_reference_across_layouts() {
    // Deterministic pseudo-random data long enough to span several 8-byte
    // chunks plus an odd remainder.
    let mut data = vec![0u8; 71];
    let mut state = 0x1234_5678u32;
    for byte in data.iter_mut() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8;
    }

    for total in 0..=data.len() {
        let d = &data[..total];
        assert_eq!(checksum16_parts(&[d]), checksum16_reference(&[d]), "whole len {total}");
        // Split at every offset — odd splits exercise the cross-part word
        // straddle; an empty middle part exercises the pending-byte carry.
        for split in 0..=total {
            let two = [&d[..split], &d[split..]];
            assert_eq!(checksum16_parts(&two), checksum16_reference(&two), "split {split}/{total}");
            let with_empty = [&d[..split], b"".as_slice(), &d[split..]];
            assert_eq!(
                checksum16_parts(&with_empty),
                checksum16_reference(&with_empty),
                "empty-middle {split}/{total}"
            );
        }
    }
}

#[test]
fn target_socket_addr_maps_ipv4_literal_without_resolution() {
    let target = TargetAddr::IpV4(Ipv4Addr::new(87, 250, 247, 181), 443);
    assert_eq!(
        target_socket_addr(&target),
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(87, 250, 247, 181)), 443)),
    );
}

#[test]
fn target_socket_addr_maps_ipv6_literal_without_resolution() {
    let ip = Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 0x1);
    let target = TargetAddr::IpV6(ip, 8443);
    assert_eq!(target_socket_addr(&target), Some(SocketAddr::new(IpAddr::V6(ip), 8443)));
}

#[test]
fn target_socket_addr_rejects_domain_targets() {
    // The TUN path never produces a domain target; mapping one yields `None`
    // so the direct egress aborts instead of issuing a DNS lookup.
    let target = TargetAddr::Domain("example.com".to_string(), 443);
    assert_eq!(target_socket_addr(&target), None);
}

// Checksum-offload simulation: build a valid packet, blank the L4 checksum (as
// the kernel does when it hands us a CHECKSUM_PARTIAL read under IFF_VNET_HDR),
// and confirm `recompute_transport_checksum` restores exactly the valid value
// and the segment then validates to 0.

fn build_ipv4(protocol: u8, l4: &[u8]) -> (Vec<u8>, Ipv4Addr, Ipv4Addr) {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    let total = IPV4_HEADER_LEN + l4.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = protocol;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[IPV4_HEADER_LEN..].copy_from_slice(l4);
    let ip_csum = checksum16(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    (pkt, src, dst)
}

#[test]
fn recompute_restores_ipv4_udp_checksum() {
    let payload = b"quic-ish udp payload of some length";
    let mut udp = vec![0u8; 8 + payload.len()];
    let udp_len = udp.len() as u16;
    udp[0..2].copy_from_slice(&443u16.to_be_bytes());
    udp[2..4].copy_from_slice(&50000u16.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let (mut pkt, src, dst) = build_ipv4(IPV6_NEXT_HEADER_UDP, &udp);
    let valid = ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_UDP, &pkt[IPV4_HEADER_LEN..]);
    pkt[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].fill(0);

    recompute_transport_checksum(&mut pkt);

    let u = IPV4_HEADER_LEN;
    assert_eq!(u16::from_be_bytes([pkt[u + 6], pkt[u + 7]]), valid);
    assert_eq!(ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_UDP, &pkt[u..]), 0);
}

#[test]
fn recompute_restores_ipv4_tcp_checksum() {
    let mut tcp = vec![0u8; 20 + 12];
    tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 5 << 4; // data offset 5 words
    tcp[13] = 0x10; // ACK
    tcp[20..].copy_from_slice(b"tcp-payload!");
    let (mut pkt, src, dst) = build_ipv4(IPV6_NEXT_HEADER_TCP, &tcp);
    let valid = ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &pkt[IPV4_HEADER_LEN..]);
    pkt[IPV4_HEADER_LEN + 16..IPV4_HEADER_LEN + 18].fill(0);

    recompute_transport_checksum(&mut pkt);

    let u = IPV4_HEADER_LEN;
    assert_eq!(u16::from_be_bytes([pkt[u + 16], pkt[u + 17]]), valid);
    assert_eq!(ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &pkt[u..]), 0);
}

#[test]
fn recompute_restores_ipv6_tcp_checksum() {
    let src = Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let mut tcp = vec![0u8; 20 + 8];
    tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x10;
    tcp[20..].copy_from_slice(b"v6tcpxxx");
    let total = IPV6_HEADER_LEN + tcp.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    pkt[6] = IPV6_NEXT_HEADER_TCP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[IPV6_HEADER_LEN..].copy_from_slice(&tcp);
    let valid = ipv6_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &pkt[IPV6_HEADER_LEN..]);
    pkt[IPV6_HEADER_LEN + 16..IPV6_HEADER_LEN + 18].fill(0);

    recompute_transport_checksum(&mut pkt);

    let u = IPV6_HEADER_LEN;
    assert_eq!(u16::from_be_bytes([pkt[u + 16], pkt[u + 17]]), valid);
    assert_eq!(ipv6_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &pkt[u..]), 0);
}
