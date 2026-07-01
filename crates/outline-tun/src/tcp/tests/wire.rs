use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

// The kernel finalises a TSO super-segment's L4 checksum per MSS segment by
// summing the L4 bytes from `csum_start` (where we stored the partial
// pseudo-header sum) and complementing. For a single (un-split) segment that
// finalisation is exactly `checksum16` over the TCP bytes, and it must equal
// the full checksum the normal path computes for the same segment.

#[test]
fn gso_partial_ipv4_checksum_finalizes_to_full() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    let payload = b"the quick brown fox jumps over the lazy dog, twice over for length";

    let full = build_ipv4_tcp_packet(
        src,
        dst,
        443,
        50000,
        0x1122_3344,
        0x5566_7788,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        payload,
        TcpChecksumMode::Full,
    )
    .unwrap();
    let full_csum = {
        let tcp = &full[IPV4_HEADER_LEN..];
        u16::from_be_bytes([tcp[16], tcp[17]])
    };

    let (gso, l3, _l4) = build_gso_tcp_packet(
        IpVersion::V4,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        443,
        50000,
        0x1122_3344,
        0x5566_7788,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        payload,
    )
    .unwrap();
    assert_eq!(l3 as usize, IPV4_HEADER_LEN);

    let tcp = &gso[l3 as usize..];
    let partial = u16::from_be_bytes([tcp[16], tcp[17]]);
    assert_ne!(partial, full_csum, "partial must differ from the full checksum");
    // Kernel finalisation of a single (un-split) segment == checksum16 over TCP.
    assert_eq!(
        checksum16(tcp),
        full_csum,
        "kernel-finalised partial checksum must equal the full checksum"
    );
    // IPv4 header checksum stays valid (kernel recomputes per segment anyway).
    assert_eq!(checksum16(&gso[..IPV4_HEADER_LEN]), 0);
}

#[test]
fn gso_partial_ipv6_checksum_finalizes_to_full() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let payload = b"another payload of odd length to exercise the checksum folding path!";

    let full = build_ipv6_tcp_packet(
        src,
        dst,
        443,
        50000,
        0x0a0b_0c0d,
        0x0102_0304,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        payload,
        TcpChecksumMode::Full,
    )
    .unwrap();
    let full_csum = {
        let tcp = &full[IPV6_HEADER_LEN..];
        u16::from_be_bytes([tcp[16], tcp[17]])
    };

    let (gso, l3, _l4) = build_gso_tcp_packet(
        IpVersion::V6,
        IpAddr::V6(src),
        IpAddr::V6(dst),
        443,
        50000,
        0x0a0b_0c0d,
        0x0102_0304,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        payload,
    )
    .unwrap();
    assert_eq!(l3 as usize, IPV6_HEADER_LEN);

    let tcp = &gso[l3 as usize..];
    assert_eq!(
        checksum16(tcp),
        full_csum,
        "kernel-finalised partial checksum must equal the full checksum (v6)"
    );
}
