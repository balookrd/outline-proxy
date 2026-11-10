use super::*;

const NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;

/// IPv6 header + one 8-byte Destination Options header (next = UDP) followed
/// by `l4`, with `payload_len` covering exactly the extension header and `l4`.
fn ipv6_with_destination_options(l4: &[u8]) -> Vec<u8> {
    let payload_len = u16::try_from(8 + l4.len()).unwrap();
    let mut packet = vec![0u8; IPV6_HEADER_LEN];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = NEXT_HEADER_DESTINATION_OPTIONS;
    packet[7] = 64;
    packet[23] = 1;
    packet[39] = 2;
    // Extension header: next header, hdr ext len (0 => 8 bytes), PadN(4).
    packet.extend_from_slice(&[IPV6_NEXT_HEADER_UDP, 0, 1, 4, 0, 0, 0, 0]);
    packet.extend_from_slice(l4);
    packet
}

#[test]
fn ipv6_extension_header_with_empty_udp_is_rejected_not_panicking() {
    // 48 bytes total: passes the whole-buffer length check, but the UDP slice
    // behind the extension header is empty.
    let packet = ipv6_with_destination_options(&[]);
    assert_eq!(packet.len(), IPV6_HEADER_LEN + UDP_HEADER_LEN);
    assert!(parse_udp_packet(&packet).is_err());
}

#[test]
fn ipv6_extension_header_with_truncated_udp_header_is_rejected() {
    for l4_len in 1..UDP_HEADER_LEN {
        let packet = ipv6_with_destination_options(&vec![0u8; l4_len]);
        assert!(parse_udp_packet(&packet).is_err(), "l4_len = {l4_len}");
    }
}

#[test]
fn ipv6_extension_header_with_full_udp_is_parsed() {
    let mut udp = Vec::new();
    udp.extend_from_slice(&5000u16.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&11u16.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(b"abc");
    let parsed = parse_udp_packet(&ipv6_with_destination_options(&udp)).unwrap();
    assert_eq!(parsed.source_port, 5000);
    assert_eq!(parsed.destination_port, 53);
    assert_eq!(parsed.payload, b"abc");
}
