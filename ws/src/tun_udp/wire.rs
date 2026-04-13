use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};

use crate::tun_wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_UDP, checksum16, ipv4_payload_checksum,
    ipv6_payload_checksum, locate_ipv6_upper_layer,
};
use crate::types::TargetAddr;

const UDP_HEADER_LEN: usize = 8;
pub(super) use crate::tun_wire::IpVersion;

#[derive(Debug, Clone)]
pub(crate) struct ParsedUdpPacket {
    pub(crate) version: IpVersion,
    pub(crate) source_ip: IpAddr,
    pub(crate) destination_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn parse_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv4 UDP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + UDP_HEADER_LEN {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 packet");
    }
    if packet[9] != IPV6_NEXT_HEADER_UDP {
        bail!("expected IPv4 UDP packet");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V4,
        source_ip: IpAddr::V4(src),
        destination_ip: IpAddr::V4(dst),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv6 UDP packet");
    }
    let (next_header, udp_offset, total_len) = locate_ipv6_upper_layer(packet)?;
    if next_header != IPV6_NEXT_HEADER_UDP {
        bail!("expected IPv6 UDP packet");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let udp = &packet[udp_offset..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated IPv6 UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V6,
        source_ip: IpAddr::V6(Ipv6Addr::from(src)),
        destination_ip: IpAddr::V6(Ipv6Addr::from(dst)),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

pub(super) fn build_response_packet(
    version: IpVersion,
    target: &TargetAddr,
    local_ip: IpAddr,
    local_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (version, target, local_ip) {
        (IpVersion::V4, TargetAddr::IpV4(remote_ip, remote_port), IpAddr::V4(local_ip)) => {
            build_ipv4_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        },
        (IpVersion::V6, TargetAddr::IpV6(remote_ip, remote_port), IpAddr::V6(local_ip)) => {
            build_ipv6_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        },
        _ => bail!("unexpected response address family for TUN UDP flow"),
    }
}

pub(crate) fn build_ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = IPV6_NEXT_HEADER_UDP;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV4_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = ipv4_payload_checksum(
        source_ip,
        destination_ip,
        IPV6_NEXT_HEADER_UDP,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

pub(crate) fn build_ipv6_udp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = IPV6_NEXT_HEADER_UDP;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV6_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = ipv6_payload_checksum(
        source_ip,
        destination_ip,
        IPV6_NEXT_HEADER_UDP,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}
