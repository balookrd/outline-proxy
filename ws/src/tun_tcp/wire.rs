use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};

use super::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};

pub(crate) const IPV4_HEADER_LEN: usize = 20;
pub(crate) const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub(super) const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub(super) const IPV6_NEXT_HEADER_TCP: u8 = 6;
pub(super) const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
pub(super) const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
pub(super) const IPV6_NEXT_HEADER_AUTH: u8 = 51;
pub(super) const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;
pub(super) const IPV6_NEXT_HEADER_NONE: u8 = 59;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedTcpPacket {
    pub(super) version: IpVersion,
    pub(super) source_ip: IpAddr,
    pub(super) destination_ip: IpAddr,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) sequence_number: u32,
    pub(super) acknowledgement_number: u32,
    pub(super) window_size: u16,
    pub(super) max_segment_size: Option<u16>,
    pub(super) window_scale: Option<u8>,
    pub(super) sack_permitted: bool,
    pub(super) sack_blocks: Vec<(u32, u32)>,
    pub(super) timestamp_value: Option<u32>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) timestamp_echo_reply: Option<u32>,
    pub(super) flags: u8,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct ParsedTcpOptions {
    max_segment_size: Option<u16>,
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
    timestamp_value: Option<u32>,
    timestamp_echo_reply: Option<u32>,
}

pub(super) fn parse_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    let version = packet
        .first()
        .ok_or_else(|| anyhow!("empty TUN TCP packet"))?
        >> 4;
    match version {
        4 => parse_ipv4_tcp_packet(packet),
        6 => parse_ipv6_tcp_packet(packet),
        other => bail!("unsupported IP version in TUN TCP packet: {other}"),
    }
}

fn parse_ipv4_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    if packet.len() < IPV4_HEADER_LEN + TCP_HEADER_LEN {
        bail!("short IPv4 TCP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + TCP_HEADER_LEN {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 TCP packet");
    }
    if checksum16(&packet[..header_len]) != 0 {
        bail!("invalid IPv4 header checksum");
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        bail!("IPv4 fragments are not supported on TUN TCP path");
    }
    if packet[9] != IPV6_NEXT_HEADER_TCP {
        bail!("expected IPv4 TCP packet");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    parse_tcp_segment(
        IpVersion::V4,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        &packet[header_len..total_len],
    )
}

fn parse_ipv6_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    if packet.len() < IPV6_HEADER_LEN + TCP_HEADER_LEN {
        bail!("short IPv6 TCP packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() < total_len {
        bail!("truncated IPv6 TCP packet");
    }
    let (next_header, segment_offset) = locate_ipv6_tcp_segment(packet, total_len)?;
    if next_header != IPV6_NEXT_HEADER_TCP {
        bail!("expected IPv6 TCP packet");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    parse_tcp_segment(
        IpVersion::V6,
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        &packet[segment_offset..total_len],
    )
}

fn locate_ipv6_tcp_segment(packet: &[u8], total_len: usize) -> Result<(u8, usize)> {
    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;

    loop {
        match next_header {
            IPV6_NEXT_HEADER_TCP => return Ok((next_header, offset)),
            IPV6_NEXT_HEADER_HOP_BY_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_DESTINATION_OPTIONS => {
                if offset + 2 > total_len {
                    bail!("truncated IPv6 extension header");
                }
                let header_len = (usize::from(packet[offset + 1]) + 1) * 8;
                if header_len < 8 || offset + header_len > total_len {
                    bail!("invalid IPv6 extension header length");
                }
                next_header = packet[offset];
                offset += header_len;
            }
            IPV6_NEXT_HEADER_AUTH => {
                if offset + 2 > total_len {
                    bail!("truncated IPv6 authentication header");
                }
                let header_len = (usize::from(packet[offset + 1]) + 2) * 4;
                if header_len < 8 || offset + header_len > total_len {
                    bail!("invalid IPv6 authentication header length");
                }
                next_header = packet[offset];
                offset += header_len;
            }
            IPV6_NEXT_HEADER_FRAGMENT => {
                bail!("IPv6 fragments are not supported on TUN TCP path");
            }
            IPV6_NEXT_HEADER_NONE => {
                bail!("expected IPv6 TCP packet");
            }
            _ => {
                bail!("IPv6 extension headers are not supported on TUN TCP path");
            }
        }
    }
}

fn parse_tcp_segment(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<ParsedTcpPacket> {
    if segment.len() < TCP_HEADER_LEN {
        bail!("short TCP segment");
    }
    validate_tcp_checksum(version, source_ip, destination_ip, segment)?;
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < TCP_HEADER_LEN || segment.len() < header_len {
        bail!("invalid TCP header length");
    }
    let options = parse_tcp_options(&segment[TCP_HEADER_LEN..header_len])?;

    Ok(ParsedTcpPacket {
        version,
        source_ip,
        destination_ip,
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        sequence_number: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        acknowledgement_number: u32::from_be_bytes([
            segment[8],
            segment[9],
            segment[10],
            segment[11],
        ]),
        window_size: u16::from_be_bytes([segment[14], segment[15]]),
        max_segment_size: options.max_segment_size,
        window_scale: options.window_scale,
        sack_permitted: options.sack_permitted,
        sack_blocks: options.sack_blocks,
        timestamp_value: options.timestamp_value,
        timestamp_echo_reply: options.timestamp_echo_reply,
        flags: segment[13],
        payload: segment[header_len..].to_vec(),
    })
}

fn validate_tcp_checksum(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<()> {
    let checksum_valid = match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            tcp_checksum_ipv4(source_ip, destination_ip, segment) == 0
        }
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            tcp_checksum_ipv6(source_ip, destination_ip, segment) == 0
        }
        _ => bail!("unexpected address family while validating TCP checksum"),
    };
    if !checksum_valid {
        bail!("invalid TCP checksum");
    }
    Ok(())
}

fn parse_tcp_options(options: &[u8]) -> Result<ParsedTcpOptions> {
    let mut parsed = ParsedTcpOptions::default();
    let mut index = 0usize;
    while index < options.len() {
        match options[index] {
            0 => break,
            1 => index += 1,
            kind => {
                if index + 1 >= options.len() {
                    bail!("truncated TCP option header");
                }
                let len = usize::from(options[index + 1]);
                if len < 2 || index + len > options.len() {
                    bail!("invalid TCP option length");
                }
                let body = &options[index + 2..index + len];
                match kind {
                    2 if body.len() == 2 => {
                        parsed.max_segment_size =
                            Some(u16::from_be_bytes([body[0], body[1]]).max(1));
                    }
                    3 if body.len() == 1 => {
                        parsed.window_scale = Some(body[0].min(14));
                    }
                    4 if body.is_empty() => {
                        parsed.sack_permitted = true;
                    }
                    5 if body.len() >= 8 && body.len() % 8 == 0 => {
                        for block in body.chunks_exact(8) {
                            let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                            let right =
                                u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
                            if seq_lt(left, right) {
                                parsed.sack_blocks.push((left, right));
                            }
                        }
                    }
                    8 if body.len() == 8 => {
                        parsed.timestamp_value =
                            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                        parsed.timestamp_echo_reply =
                            Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
                    }
                    _ => {}
                }
                index += len;
            }
        }
    }
    Ok(parsed)
}

pub(super) fn build_reset_response(packet: &ParsedTcpPacket) -> Result<Vec<u8>> {
    let response_seq = if (packet.flags & TCP_FLAG_ACK) != 0 {
        packet.acknowledgement_number
    } else {
        0
    };
    let response_ack = if (packet.flags & TCP_FLAG_ACK) != 0 {
        0
    } else {
        packet
            .sequence_number
            .wrapping_add(packet.payload.len() as u32)
            .wrapping_add(u32::from((packet.flags & TCP_FLAG_SYN) != 0))
            .wrapping_add(u32::from((packet.flags & TCP_FLAG_FIN) != 0))
    };
    let response_flags = if (packet.flags & TCP_FLAG_ACK) != 0 {
        TCP_FLAG_RST
    } else {
        TCP_FLAG_RST | TCP_FLAG_ACK
    };

    build_response_packet(
        packet.version,
        packet.destination_ip,
        packet.source_ip,
        packet.destination_port,
        packet.source_port,
        response_seq,
        response_ack,
        response_flags,
        &[],
    )
}

pub(super) fn build_response_packet(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_response_packet_custom(
        version,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        0xffff,
        &[],
        payload,
    )
}

pub(super) fn build_response_packet_custom(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            build_ipv4_tcp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload,
            )
        }
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            build_ipv6_tcp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload,
            )
        }
        _ => bail!("unexpected address family in TUN TCP response"),
    }
}

fn build_ipv4_tcp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if options.len() % 4 != 0 {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let total_len = IPV4_HEADER_LEN + tcp_header_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let tcp = &mut packet[IPV4_HEADER_LEN..];
    build_tcp_segment(
        tcp,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    );

    let tcp_checksum = tcp_checksum_ipv4(source_ip, destination_ip, tcp);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_tcp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if options.len() % 4 != 0 {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let total_len = IPV6_HEADER_LEN + tcp_header_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((tcp_header_len + payload.len()) as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let tcp = &mut packet[IPV6_HEADER_LEN..];
    build_tcp_segment(
        tcp,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    );

    let tcp_checksum = tcp_checksum_ipv6(source_ip, destination_ip, tcp);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(packet)
}

fn build_tcp_segment(
    tcp: &mut [u8],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) {
    let header_len = TCP_HEADER_LEN + options.len();
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement_number.to_be_bytes());
    tcp[12] = ((header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window_size.to_be_bytes());
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
    if !options.is_empty() {
        tcp[TCP_HEADER_LEN..header_len].copy_from_slice(options);
    }
    tcp[header_len..header_len + payload.len()].copy_from_slice(payload);
}

pub(super) fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            u16::from_be_bytes([chunk[0], 0]) as u32
        };
        sum = sum.wrapping_add(value);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn tcp_checksum_ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    checksum16(&pseudo)
}

pub(super) fn tcp_checksum_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(tcp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(tcp_segment);
    checksum16(&pseudo)
}

fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}
