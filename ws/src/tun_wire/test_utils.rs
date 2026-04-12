use std::net::{Ipv4Addr, Ipv6Addr};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::tun_wire::{
    checksum16, ipv4_payload_checksum, ipv6_payload_checksum, locate_ipv6_upper_layer,
};

pub(crate) const IP_PROTOCOL_TCP: u8 = 6;
pub(crate) const IP_PROTOCOL_UDP: u8 = 17;

pub(crate) fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub(crate) fn random_payload(rng: &mut StdRng, max_len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; rng.gen_range(0..=max_len)];
    rng.fill(payload.as_mut_slice());
    payload
}

pub(crate) fn flip_packet_byte(packet: &[u8], offset: usize) -> Vec<u8> {
    assert!(offset < packet.len(), "mutation offset out of bounds");
    let mut mutated = packet.to_vec();
    mutated[offset] ^= 0x01;
    mutated
}

pub(crate) fn transport_offset(packet: &[u8]) -> usize {
    match packet.first().copied().unwrap_or_default() >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => {
            locate_ipv6_upper_layer(packet)
                .expect("valid IPv6 packet in test harness")
                .1
        }
        other => panic!("unsupported IP version in test harness: {other}"),
    }
}

pub(crate) fn assert_ipv4_header_checksum_valid(packet: &[u8]) {
    assert_eq!(packet[0] >> 4, 4, "expected IPv4 packet");
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    assert_eq!(
        checksum16(&packet[..header_len]),
        0,
        "invalid IPv4 header checksum"
    );
}

pub(crate) fn assert_transport_checksum_valid(packet: &[u8], protocol: u8) {
    match packet.first().copied().unwrap_or_default() >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            assert_eq!(packet[9], protocol, "unexpected IPv4 transport protocol");
            assert_eq!(
                ipv4_payload_checksum(
                    source,
                    destination,
                    protocol,
                    &packet[header_len..total_len]
                ),
                0,
                "invalid IPv4 transport checksum",
            );
        }
        6 => {
            let (next_header, offset, total_len) =
                locate_ipv6_upper_layer(packet).expect("valid IPv6 packet in test harness");
            let mut source = [0u8; 16];
            source.copy_from_slice(&packet[8..24]);
            let mut destination = [0u8; 16];
            destination.copy_from_slice(&packet[24..40]);
            assert_eq!(next_header, protocol, "unexpected IPv6 next header");
            assert_eq!(
                ipv6_payload_checksum(
                    Ipv6Addr::from(source),
                    Ipv6Addr::from(destination),
                    protocol,
                    &packet[offset..total_len],
                ),
                0,
                "invalid IPv6 transport checksum",
            );
        }
        other => panic!("unsupported IP version in test harness: {other}"),
    }
}

pub(crate) fn corrupt_ip_length_field(packet: &[u8]) -> Vec<u8> {
    let mut mutated = packet.to_vec();
    match packet.first().copied().unwrap_or_default() >> 4 {
        4 => {
            let invalid_total_len = (transport_offset(packet) + 7) as u16;
            mutated[2..4].copy_from_slice(&invalid_total_len.to_be_bytes());
        }
        6 => {
            mutated[4..6].copy_from_slice(&7u16.to_be_bytes());
        }
        other => panic!("unsupported IP version in test harness: {other}"),
    }
    mutated
}

pub(crate) fn corrupt_udp_length_field(packet: &[u8]) -> Vec<u8> {
    let mut mutated = packet.to_vec();
    let offset = transport_offset(packet);
    mutated[offset + 4..offset + 6].copy_from_slice(&7u16.to_be_bytes());
    mutated
}
