//! Local ICMP / ICMPv6 echo reply synthesis.
//!
//! When the classifier sees an echo request destined for the tunnel, the
//! TUN engine answers it locally instead of forwarding upstream — we don't
//! have a remote side for raw ICMP. This module builds the reply packet
//! (and fragments oversized IPv6 replies down to the minimum path MTU).

use std::net::Ipv6Addr;

use anyhow::{Result, anyhow, bail};

use crate::frag::fragment_ipv6_packet;
use crate::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_ICMPV6, checksum16, ipv6_payload_checksum,
    locate_ipv6_upper_layer,
};

pub(crate) const IPV6_MIN_PATH_MTU: usize = 1280;

pub(crate) fn build_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => build_ipv4_icmp_echo_reply(packet),
        6 => build_ipv6_icmp_echo_reply(packet),
        other => bail!("unsupported IP version in ICMP packet: {other}"),
    }
}

pub(crate) fn build_icmp_echo_reply_packets(packet: &[u8]) -> Result<Vec<Vec<u8>>> {
    let reply = build_icmp_echo_reply(packet)?;
    if packet.first().copied().unwrap_or_default() >> 4 != 6 || reply.len() <= IPV6_MIN_PATH_MTU {
        return Ok(vec![reply]);
    }
    fragment_ipv6_packet(reply, IPV6_MIN_PATH_MTU)
}

fn build_ipv4_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < IPV4_HEADER_LEN + 8 {
        bail!("short IPv4 ICMP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + 8 || packet.len() < total_len {
        bail!("invalid IPv4 ICMP packet lengths");
    }
    if packet[9] != 1 {
        bail!("expected IPv4 ICMP packet");
    }
    if packet[header_len] != 8 {
        bail!("expected IPv4 ICMP echo request");
    }

    let mut reply = packet[..total_len].to_vec();
    let source = [packet[12], packet[13], packet[14], packet[15]];
    let destination = [packet[16], packet[17], packet[18], packet[19]];
    reply[8] = 64;
    reply[12..16].copy_from_slice(&destination);
    reply[16..20].copy_from_slice(&source);
    reply[header_len] = 0;
    reply[header_len + 2] = 0;
    reply[header_len + 3] = 0;
    let icmp_checksum = checksum16(&reply[header_len..total_len]);
    reply[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    reply[10] = 0;
    reply[11] = 0;
    let header_checksum = checksum16(&reply[..header_len]);
    reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(reply)
}

fn build_ipv6_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < IPV6_HEADER_LEN + 8 {
        bail!("short IPv6 ICMP packet");
    }
    let (next_header, payload_offset, total_len) = locate_ipv6_upper_layer(packet)?;
    if total_len < payload_offset + 8 || packet.len() < total_len {
        bail!("invalid IPv6 ICMP packet lengths");
    }
    if next_header != IPV6_NEXT_HEADER_ICMPV6 {
        bail!("expected IPv6 ICMP packet");
    }
    if packet[payload_offset] != 128 {
        bail!("expected IPv6 ICMP echo request");
    }

    let mut reply = packet[..total_len].to_vec();
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    reply[7] = 64;
    reply[8..24].copy_from_slice(&destination);
    reply[24..40].copy_from_slice(&source);
    reply[payload_offset] = 129;
    reply[payload_offset + 2] = 0;
    reply[payload_offset + 3] = 0;
    let icmp_checksum = icmpv6_checksum(
        Ipv6Addr::from(destination),
        Ipv6Addr::from(source),
        &reply[payload_offset..total_len],
    );
    reply[payload_offset + 2..payload_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(reply)
}

pub(crate) fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp_packet: &[u8]) -> u16 {
    ipv6_payload_checksum(source, destination, IPV6_NEXT_HEADER_ICMPV6, icmp_packet)
}
