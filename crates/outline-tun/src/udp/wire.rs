use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;

use crate::vnet::{VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_UDP_L4, VirtioNetHdr};
use crate::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_UDP, checksum16, checksum16_parts,
    ipv4_payload_checksum, ipv6_payload_checksum, locate_ipv6_upper_layer,
};
use socks5_proto::TargetAddr;

const UDP_HEADER_LEN: usize = 8;
pub(super) use crate::wire::IpVersion;

/// Max UDP payload coalesced into one `GSO_UDP_L4` super-packet. All datagrams
/// are `gso_size`, so this is a multiple of it; kept well under 65535 − headers
/// so the IPv4 `total_len` / IPv6 `payload_len` u16 never overflow.
pub(super) const GSO_MAX_UDP_SUPER_PAYLOAD: usize = 61_440;
/// Kernel `UDP_MAX_SEGMENTS`: at most 64 datagrams per `GSO_UDP_L4` super-packet.
pub(super) const UDP_MAX_SEGMENTS: usize = 64;
/// Minimum per-datagram payload treated as a coalescable UDP `gso_size`
/// (`sizeof(udphdr) + 1`); smaller datagrams are written one at a time.
pub(super) const UDP_GSO_MIN_DATAGRAM: usize = 9;

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

/// Defensive ceiling on datagrams produced from one UDP GRO super-packet. The
/// kernel caps a USO aggregate near 64 datagrams; this bound stops a single
/// malformed read from spawning an unbounded fan-out of `handle_packet`.
const MAX_UDP_GSO_SEGMENTS: usize = 128;

/// Re-segment a UDP GRO super-packet (`gso_type` `GSO_UDP_L4`) back into the
/// individual datagrams the kernel coalesced on read. The aggregate is one IP
/// packet: a single 8-byte UDP header followed by N datagrams of one 4-tuple,
/// each `gso_size` bytes (the last may be shorter).
///
/// The UDP header's `len` field spans the WHOLE aggregate here (not one
/// datagram), so — unlike [`parse_udp_packet`] — we must NOT trust it: the L4
/// payload region is bounded by the IP total length, and datagrams are cut from
/// it at `gso_size`. Ports / addresses are shared by every datagram. Order is
/// preserved front-to-back (per-flow NAT state depends on it). No checksum is
/// recomputed — the engine reads the payload directly and never validates the
/// UDP sum, so the output is byte-identical to the per-packet parse path.
pub(crate) fn resegment_udp_gso(packet: &[u8], gso_size: u16) -> Result<Vec<ParsedUdpPacket>> {
    if gso_size == 0 {
        bail!("UDP GSO super-packet with zero gso_size");
    }
    let gso_size = usize::from(gso_size);
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    let (version, source_ip, destination_ip, udp) = match version {
        4 => {
            if packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
                bail!("short IPv4 UDP GSO packet");
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < IPV4_HEADER_LEN
                || total_len < header_len + UDP_HEADER_LEN
                || packet.len() < total_len
            {
                bail!("invalid IPv4 UDP GSO lengths");
            }
            if packet[9] != IPV6_NEXT_HEADER_UDP {
                bail!("expected IPv4 UDP GSO packet");
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            (IpVersion::V4, IpAddr::V4(src), IpAddr::V4(dst), &packet[header_len..total_len])
        },
        6 => {
            if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
                bail!("short IPv6 UDP GSO packet");
            }
            let (next_header, udp_offset, total_len) = locate_ipv6_upper_layer(packet)?;
            if next_header != IPV6_NEXT_HEADER_UDP {
                bail!("expected IPv6 UDP GSO packet");
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&packet[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&packet[24..40]);
            (
                IpVersion::V6,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                &packet[udp_offset..total_len],
            )
        },
        other => bail!("unsupported IP version in UDP GSO packet: {other}"),
    };

    if udp.len() < UDP_HEADER_LEN {
        bail!("short UDP header in GSO super-packet");
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    // Deliberately ignore udp[4..6] (`uh->len`): it spans the whole aggregate,
    // not one datagram. The payload region is everything after the single UDP
    // header, already bounded by the IP total length above.
    let aggregate = &udp[UDP_HEADER_LEN..];
    if aggregate.is_empty() {
        bail!("empty UDP GSO aggregate");
    }
    let num_segments = aggregate.len().div_ceil(gso_size);
    if num_segments > MAX_UDP_GSO_SEGMENTS {
        bail!(
            "UDP GSO super-packet splits into {num_segments} datagrams (> {MAX_UDP_GSO_SEGMENTS})"
        );
    }

    let mut datagrams = Vec::with_capacity(num_segments);
    for chunk in aggregate.chunks(gso_size) {
        datagrams.push(ParsedUdpPacket {
            version,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            payload: chunk.to_vec(),
        });
    }
    Ok(datagrams)
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

/// Build a UDP `GSO_UDP_L4` super-packet for kernel USO: one IP+UDP header over
/// `payload` (the concatenation of N equal-sized `gso_size` datagrams of one
/// 4-tuple) carrying a *partial* (pseudo-header) UDP checksum the kernel
/// finalises per segment. Returns the packet and its `virtio_net_hdr`. The UDP
/// `len`, IP total length and pseudo-header length all span the WHOLE aggregate
/// (`8 + payload.len()`), not one datagram — `__udp_gso_segment` rewrites the
/// per-segment length and corrects the checksum via `csum16_sub(uh->check,
/// uh->len)`. Mirror of [`super::super::tcp`]'s `build_gso_tcp_packet`.
pub(super) fn build_gso_udp_packet(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    gso_size: u16,
    segments: &[Bytes],
) -> Result<(Vec<u8>, VirtioNetHdr)> {
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_ipv4_udp_gso_packet(src, dst, source_port, destination_port, gso_size, segments)
        },
        (IpVersion::V6, IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_ipv6_udp_gso_packet(src, dst, source_port, destination_port, gso_size, segments)
        },
        _ => bail!("UDP GSO address family mismatch"),
    }
}

/// Copy the batch's datagrams contiguously into the packet's payload region,
/// starting at `start`. This is the sole payload copy — the caller no longer
/// coalesces the `Bytes` into an intermediate buffer first.
fn write_segments(packet: &mut [u8], start: usize, segments: &[Bytes]) {
    let mut offset = start;
    for segment in segments {
        packet[offset..offset + segment.len()].copy_from_slice(segment);
        offset += segment.len();
    }
}

fn build_ipv4_udp_gso_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    gso_size: u16,
    segments: &[Bytes],
) -> Result<(Vec<u8>, VirtioNetHdr)> {
    let payload_len: usize = segments.iter().map(Bytes::len).sum();
    let udp_len = UDP_HEADER_LEN + payload_len;
    let total_len = IPV4_HEADER_LEN + udp_len;
    if total_len > usize::from(u16::MAX) {
        bail!("UDP GSO super-packet too large for IPv4 total_len");
    }
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
    write_segments(&mut packet, udp_offset + UDP_HEADER_LEN, segments);
    // Partial (pseudo-header) checksum — the kernel adds the L4 byte checksum
    // and finalises it per segment.
    let partial = ipv4_udp_partial_checksum(source_ip, destination_ip, udp_len);
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&partial.to_be_bytes());
    // IP header checksum (the kernel recomputes it per segment, but keep it
    // valid for observers on the local hop).
    let ip_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let vnet = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
        hdr_len: (udp_offset + UDP_HEADER_LEN) as u16,
        gso_size,
        csum_start: udp_offset as u16,
        csum_offset: 6,
    };
    Ok((packet, vnet))
}

fn build_ipv6_udp_gso_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    gso_size: u16,
    segments: &[Bytes],
) -> Result<(Vec<u8>, VirtioNetHdr)> {
    let payload_len: usize = segments.iter().map(Bytes::len).sum();
    let udp_len = UDP_HEADER_LEN + payload_len;
    if udp_len > usize::from(u16::MAX) {
        bail!("UDP GSO super-packet too large for IPv6 payload_len");
    }
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
    write_segments(&mut packet, udp_offset + UDP_HEADER_LEN, segments);
    let partial = ipv6_udp_partial_checksum(source_ip, destination_ip, udp_len);
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&partial.to_be_bytes());

    let vnet = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
        hdr_len: (udp_offset + UDP_HEADER_LEN) as u16,
        gso_size,
        csum_start: udp_offset as u16,
        csum_offset: 6,
    };
    Ok((packet, vnet))
}

/// Partial (pseudo-header) UDP checksum over the WHOLE aggregate length, stored
/// so the kernel's USO segmentation finalises each segment's checksum.
fn ipv4_udp_partial_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp_len: usize) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let protocol = [0u8, IPV6_NEXT_HEADER_UDP];
    let length = (udp_len as u16).to_be_bytes();
    !checksum16_parts(&[&source[..], &destination[..], &protocol[..], &length[..]])
}

fn ipv6_udp_partial_checksum(source: Ipv6Addr, destination: Ipv6Addr, udp_len: usize) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let length = (udp_len as u32).to_be_bytes();
    let next_header = [0u8, 0, 0, IPV6_NEXT_HEADER_UDP];
    !checksum16_parts(&[&source[..], &destination[..], &length[..], &next_header[..]])
}
