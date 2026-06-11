use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socks5_proto::TargetAddr;

use super::{checksum16, checksum16_parts, target_socket_addr};

#[test]
fn checksum16_parts_matches_flat_buffer_for_odd_boundaries() {
    let parts = [b"\x12".as_slice(), b"\x34\x56".as_slice(), b"\x78\x9a\xbc".as_slice()];
    let flat = b"\x12\x34\x56\x78\x9a\xbc";
    assert_eq!(checksum16_parts(&parts), checksum16(flat));
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
