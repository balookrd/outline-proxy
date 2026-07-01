use super::*;

#[test]
fn none_header_round_trips_as_all_zero() {
    let encoded = VirtioNetHdr::NONE.encode();
    assert_eq!(encoded, [0u8; VIRTIO_NET_HDR_LEN]);
    let decoded = VirtioNetHdr::decode(&encoded).unwrap();
    assert_eq!(decoded, VirtioNetHdr::NONE);
    assert!(!decoded.is_gso());
}

#[test]
fn tcpv4_gso_header_round_trips() {
    let header = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
        hdr_len: 40,
        gso_size: 1200,
        csum_start: 20,
        csum_offset: 16,
    };
    let decoded = VirtioNetHdr::decode(&header.encode()).unwrap();
    assert_eq!(decoded, header);
    assert!(decoded.is_gso());
}

#[test]
fn decode_ignores_trailing_packet_bytes() {
    // A real read is [vnet_hdr | ip packet]; decode must read only the header.
    let mut buf = VirtioNetHdr::NONE.encode().to_vec();
    buf.extend_from_slice(&[0x45, 0x00, 0xff, 0xff]); // start of an IPv4 packet
    let decoded = VirtioNetHdr::decode(&buf).unwrap();
    assert_eq!(decoded, VirtioNetHdr::NONE);
}

#[test]
fn decode_rejects_short_buffer() {
    assert!(VirtioNetHdr::decode(&[0u8; VIRTIO_NET_HDR_LEN - 1]).is_none());
}

#[test]
fn tcpv6_gso_type_is_recognised_as_gso() {
    let header = VirtioNetHdr {
        gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
        ..VirtioNetHdr::NONE
    };
    assert!(header.is_gso());
}
