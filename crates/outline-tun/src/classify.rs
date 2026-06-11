//! Packet classification for the TUN read loop.
//!
//! Maps a raw IP packet to a coarse [`PacketDisposition`] the dispatcher
//! uses to route it to the UDP engine, TCP engine, local ICMP-reply path,
//! or silently drop it as unsupported.

use anyhow::{Result, anyhow, bail};

use crate::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, IPV6_NEXT_HEADER_ICMPV6,
    IPV6_NEXT_HEADER_NONE, IPV6_NEXT_HEADER_TCP, IPV6_NEXT_HEADER_UDP, locate_ipv6_upper_layer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketDisposition {
    Udp,
    Tcp,
    IcmpEchoRequest,
    Unsupported(&'static str),
}

pub(crate) fn classify_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => classify_ipv4_packet(packet),
        6 => classify_ipv6_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn classify_ipv4_packet(packet: &[u8]) -> Result<PacketDisposition> {
    if packet.len() < IPV4_HEADER_LEN {
        bail!("short IPv4 packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN || packet.len() < header_len {
        bail!("invalid IPv4 header length");
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        return Ok(PacketDisposition::Unsupported("IPv4 fragments are not supported on TUN"));
    }
    Ok(match packet[9] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        1 => classify_ipv4_icmp_packet(packet, header_len)?,
        _ => PacketDisposition::Unsupported("unsupported IPv4 protocol on TUN"),
    })
}

fn classify_ipv6_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let (next_header, payload_offset, _) = locate_ipv6_upper_layer(packet)?;
    Ok(match next_header {
        IPV6_NEXT_HEADER_UDP => PacketDisposition::Udp,
        IPV6_NEXT_HEADER_TCP => PacketDisposition::Tcp,
        IPV6_NEXT_HEADER_ICMPV6 => classify_ipv6_icmp_packet(packet, payload_offset)?,
        IPV6_NEXT_HEADER_FRAGMENT => {
            PacketDisposition::Unsupported("IPv6 fragments are not supported on TUN")
        },
        IPV6_NEXT_HEADER_NONE => {
            PacketDisposition::Unsupported("IPv6 no-next-header packets are not supported on TUN")
        },
        _ => PacketDisposition::Unsupported(
            "unsupported IPv6 payload protocol or extension header path on TUN",
        ),
    })
}

fn classify_ipv4_icmp_packet(packet: &[u8], header_len: usize) -> Result<PacketDisposition> {
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        bail!("truncated IPv4 ICMP packet");
    }
    Ok(match packet[header_len] {
        8 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMP is not supported on TUN"),
    })
}

fn classify_ipv6_icmp_packet(packet: &[u8], payload_offset: usize) -> Result<PacketDisposition> {
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if total_len < payload_offset + 8 || packet.len() < total_len {
        bail!("truncated IPv6 ICMP packet");
    }
    Ok(match packet[payload_offset] {
        128 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMPv6 is not supported on TUN"),
    })
}
