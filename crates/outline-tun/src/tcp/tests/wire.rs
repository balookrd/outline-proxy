use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

// A downlink data packet is built as a bare IP/TCP header (no payload copy) plus
// the payload written vectored. The TCP checksum is summed over the payload as a
// separate `checksum16_parts` slice. A receiver, however, validates the
// *contiguous* segment: pseudo-header + TCP header + payload must checksum to
// zero. These tests reconstruct that contiguous segment and prove the header's
// checksum is byte-correct for the payload it was never copied next to.

fn ipv4_header_validates(src: Ipv4Addr, dst: Ipv4Addr, options: &[u8], payload: &[u8]) {
    let header = build_ipv4_tcp_header(
        src,
        dst,
        443,
        50000,
        0x1122_3344,
        0x5566_7788,
        TCP_FLAG_ACK,
        0xffff,
        options,
        payload.len(),
        &[payload],
        TcpChecksumMode::Full,
    )
    .unwrap();
    // IPv4 header checksum is valid on its own.
    assert_eq!(checksum16(&header[..IPV4_HEADER_LEN]), 0);
    // TCP checksum validates over the contiguous L4 segment (header + payload).
    let mut segment = header[IPV4_HEADER_LEN..].to_vec();
    segment.extend_from_slice(payload);
    assert_eq!(
        ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &segment),
        0,
        "reconstructed segment must validate to zero"
    );
    // The full contiguous builder must yield exactly header ++ payload.
    let contiguous = build_ipv4_tcp_packet(
        src,
        dst,
        443,
        50000,
        0x1122_3344,
        0x5566_7788,
        TCP_FLAG_ACK,
        0xffff,
        options,
        payload,
        TcpChecksumMode::Full,
    )
    .unwrap();
    let mut reconstructed = header.clone();
    reconstructed.extend_from_slice(payload);
    assert_eq!(reconstructed, contiguous);
}

fn ipv6_header_validates(src: Ipv6Addr, dst: Ipv6Addr, options: &[u8], payload: &[u8]) {
    let header = build_ipv6_tcp_header(
        src,
        dst,
        443,
        50000,
        0x0a0b_0c0d,
        0x0102_0304,
        TCP_FLAG_ACK,
        0xffff,
        options,
        payload.len(),
        &[payload],
        TcpChecksumMode::Full,
    )
    .unwrap();
    let mut segment = header[IPV6_HEADER_LEN..].to_vec();
    segment.extend_from_slice(payload);
    assert_eq!(
        ipv6_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &segment),
        0,
        "reconstructed segment must validate to zero (v6)"
    );
    let contiguous = build_ipv6_tcp_packet(
        src,
        dst,
        443,
        50000,
        0x0a0b_0c0d,
        0x0102_0304,
        TCP_FLAG_ACK,
        0xffff,
        options,
        payload,
        TcpChecksumMode::Full,
    )
    .unwrap();
    let mut reconstructed = header.clone();
    reconstructed.extend_from_slice(payload);
    assert_eq!(reconstructed, contiguous);
}

#[test]
fn split_checksum_validates_ipv4() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    // A 12-byte timestamp option block keeps the TCP header 32-aligned; odd and
    // even payload lengths exercise the trailing-byte fold across the part
    // boundary between the TCP header and the payload.
    let ts_option = [8u8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1];
    for options in [&[][..], &ts_option[..]] {
        for len in [0usize, 1, 2, 63, 64, 1460] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            ipv4_header_validates(src, dst, options, &payload);
        }
    }
}

#[test]
fn split_checksum_validates_ipv6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let ts_option = [8u8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1];
    for options in [&[][..], &ts_option[..]] {
        for len in [0usize, 1, 2, 63, 64, 1440] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 5 + 11) as u8).collect();
            ipv6_header_validates(src, dst, options, &payload);
        }
    }
}

// The non-GSO data path folds a payload split across several `Bytes` chunks
// into the Full checksum as separate parts (no coalescing). The result must be
// byte-identical to the checksum of the same payload as one contiguous slice,
// and the reconstructed segment must validate to zero. Chunk sizes include an
// odd length so a chunk boundary lands mid-16-bit-word.
#[test]
fn split_checksum_validates_multichunk_ipv4() {
    let src = Ipv4Addr::new(10, 0, 0, 7);
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let chunks: [Vec<u8>; 3] = [
        (0..333u32).map(|i| i as u8).collect(),
        vec![0xAB],
        (0..512u32).map(|i| (i * 3) as u8).collect(),
    ];
    let parts: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let payload_len: usize = parts.iter().map(|p| p.len()).sum();

    let header = build_ipv4_tcp_header(
        src,
        dst,
        443,
        50000,
        1,
        2,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        payload_len,
        &parts,
        TcpChecksumMode::Full,
    )
    .unwrap();

    let mut segment = header[IPV4_HEADER_LEN..].to_vec();
    for chunk in &chunks {
        segment.extend_from_slice(chunk);
    }
    assert_eq!(
        ipv4_payload_checksum(src, dst, IPV6_NEXT_HEADER_TCP, &segment),
        0,
        "reconstructed multi-chunk segment must validate to zero"
    );

    // Identical to the single-part (contiguous) checksum of the same bytes.
    let flat: Vec<u8> = chunks.iter().flatten().copied().collect();
    let single = build_ipv4_tcp_header(
        src,
        dst,
        443,
        50000,
        1,
        2,
        TCP_FLAG_ACK,
        0xffff,
        &[],
        flat.len(),
        &[&flat],
        TcpChecksumMode::Full,
    )
    .unwrap();
    assert_eq!(header, single, "multi-part checksum must equal single-part");
}

// The kernel finalises a TSO super-segment's L4 checksum per MSS segment by
// summing the L4 bytes from `csum_start` (where we stored the partial
// pseudo-header sum) and complementing. For a single (un-split) segment that
// finalisation is exactly `checksum16` over the TCP header + payload, and it
// must equal the full checksum the normal path computes for the same segment.

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

    let (gso, l3, _l4) = build_gso_tcp_header(
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
        payload.len(),
    )
    .unwrap();
    assert_eq!(l3 as usize, IPV4_HEADER_LEN);

    // The GSO builder returns the header only; the kernel finalises over the
    // header's L4 bytes followed by the (vectored) payload.
    let mut segment = gso[l3 as usize..].to_vec();
    let partial = u16::from_be_bytes([segment[16], segment[17]]);
    assert_ne!(partial, full_csum, "partial must differ from the full checksum");
    segment.extend_from_slice(payload);
    // Kernel finalisation of a single (un-split) segment == checksum16 over TCP.
    assert_eq!(
        checksum16(&segment),
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

    let (gso, l3, _l4) = build_gso_tcp_header(
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
        payload.len(),
    )
    .unwrap();
    assert_eq!(l3 as usize, IPV6_HEADER_LEN);

    let mut segment = gso[l3 as usize..].to_vec();
    segment.extend_from_slice(payload);
    assert_eq!(
        checksum16(&segment),
        full_csum,
        "kernel-finalised partial checksum must equal the full checksum (v6)"
    );
}
