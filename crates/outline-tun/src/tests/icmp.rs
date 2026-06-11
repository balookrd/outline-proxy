use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::icmp_echo_destination;
use crate::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};

#[test]
fn extracts_ipv4_echo_destination() {
    let mut packet = vec![0u8; IPV4_HEADER_LEN + 8];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    packet[IPV4_HEADER_LEN] = 8;

    assert_eq!(icmp_echo_destination(&packet), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn extracts_ipv6_echo_destination() {
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let mut packet = vec![0u8; IPV6_HEADER_LEN + 8];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 58;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER_LEN] = 128;

    assert_eq!(icmp_echo_destination(&packet), Some(IpAddr::V6(destination)));
}

#[test]
fn short_or_non_ip_packets_yield_no_destination() {
    assert_eq!(icmp_echo_destination(&[]), None);
    assert_eq!(icmp_echo_destination(&[0x45; IPV4_HEADER_LEN - 1]), None);
    assert_eq!(icmp_echo_destination(&[0x60; IPV6_HEADER_LEN - 1]), None);
    assert_eq!(icmp_echo_destination(&[0x00; IPV6_HEADER_LEN]), None);
}
