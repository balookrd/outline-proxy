#[cfg(test)]
#[path = "tests/test_utils.rs"]
pub(crate) mod test_utils;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail};

use socks5_proto::TargetAddr;

pub(crate) const IPV4_HEADER_LEN: usize = 20;
pub(crate) const IPV6_HEADER_LEN: usize = 40;

pub(crate) const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub(crate) const IPV6_NEXT_HEADER_TCP: u8 = 6;
pub(crate) const IPV6_NEXT_HEADER_UDP: u8 = 17;
pub(crate) const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
pub(crate) const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
pub(crate) const IPV6_NEXT_HEADER_AUTH: u8 = 51;
pub(crate) const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;
pub(crate) const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;
pub(crate) const IPV6_NEXT_HEADER_NONE: u8 = 59;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum IpVersion {
    V4,
    V6,
}

/// Prometheus label value for the IP family of a TUN packet.
pub(crate) fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

/// Builds a [`TargetAddr`] from an `(ip, port)` pair — the TUN path always
/// resolves to a literal IP (no domain), so this is a direct mapping.
pub(crate) fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

/// Maps a [`TargetAddr`] to a concrete [`SocketAddr`] without any DNS
/// resolution.
///
/// The TUN ingress always carries literal IP targets (see [`ip_to_target`]),
/// so the direct egress path can build the socket address synchronously. A
/// `Domain` target — which the TUN path never produces — yields `None`, so
/// the caller rejects it explicitly instead of stringifying the literal IP
/// back into `"<ip>:<port>"` and issuing a bogus `getaddrinfo` lookup that
/// stalls on the system resolver's multi-second timeout (glibc default
/// `RES_TIMEOUT` is 5 s) before falling back to the address it already had.
pub(crate) fn target_socket_addr(target: &TargetAddr) -> Option<SocketAddr> {
    match target {
        TargetAddr::IpV4(ip, port) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
        TargetAddr::IpV6(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
        TargetAddr::Domain(_, _) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv6PayloadInfo {
    pub(crate) next_header: u8,
    pub(crate) payload_offset: usize,
    pub(crate) total_len: usize,
    pub(crate) next_header_field_offset: usize,
}

pub(crate) fn checksum16(data: &[u8]) -> u16 {
    checksum16_parts(&[data])
}

pub(crate) fn checksum16_parts(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut pending = None;

    for part in parts {
        for &byte in *part {
            match pending.take() {
                Some(high) => {
                    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([high, byte])));
                },
                None => pending = Some(byte),
            }
        }
    }

    if let Some(high) = pending {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([high, 0])));
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn ipv4_payload_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let protocol = [0, protocol];
    let length = (payload.len() as u16).to_be_bytes();
    checksum16_parts(&[&source, &destination, &protocol, &length, payload])
}

pub(crate) fn ipv6_payload_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let length = (payload.len() as u32).to_be_bytes();
    let next_header = [0, 0, 0, next_header];
    checksum16_parts(&[&source, &destination, &length, &next_header, payload])
}

pub(crate) fn locate_ipv6_payload(packet: &[u8]) -> Result<Ipv6PayloadInfo> {
    if packet.len() < IPV6_HEADER_LEN {
        bail!("short IPv6 packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() < total_len {
        bail!("truncated IPv6 packet");
    }

    let mut next_header = packet[6];
    let mut next_header_field_offset = 6usize;
    let mut offset = IPV6_HEADER_LEN;
    loop {
        match next_header {
            IPV6_NEXT_HEADER_TCP
            | IPV6_NEXT_HEADER_UDP
            | IPV6_NEXT_HEADER_ICMPV6
            | IPV6_NEXT_HEADER_FRAGMENT
            | IPV6_NEXT_HEADER_NONE => {
                return Ok(Ipv6PayloadInfo {
                    next_header,
                    payload_offset: offset,
                    total_len,
                    next_header_field_offset,
                });
            },
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
                next_header_field_offset = offset;
                next_header = packet[offset];
                offset += header_len;
            },
            IPV6_NEXT_HEADER_AUTH => {
                if offset + 2 > total_len {
                    bail!("truncated IPv6 authentication header");
                }
                let header_len = (usize::from(packet[offset + 1]) + 2) * 4;
                if header_len < 8 || offset + header_len > total_len {
                    bail!("invalid IPv6 authentication header length");
                }
                next_header_field_offset = offset;
                next_header = packet[offset];
                offset += header_len;
            },
            _ => {
                return Ok(Ipv6PayloadInfo {
                    next_header,
                    payload_offset: offset,
                    total_len,
                    next_header_field_offset,
                });
            },
        }
    }
}

pub(crate) fn locate_ipv6_upper_layer(packet: &[u8]) -> Result<(u8, usize, usize)> {
    let info = locate_ipv6_payload(packet)?;
    Ok((info.next_header, info.payload_offset, info.total_len))
}

/// Recompute a received packet's TCP/UDP checksum in place.
///
/// With `IFF_VNET_HDR`, the kernel may hand us packets whose L4 checksum field is
/// not finalised — a locally-originated / forwarded packet often carries
/// `CHECKSUM_PARTIAL` (TX-offload not completed on a loopback/forward path),
/// flagged in the vnet header as `VIRTIO_NET_HDR_F_DATA_VALID` / `_NEEDS_CSUM`.
/// The payload is intact but the field would fail our validating parsers, so
/// this restores a valid checksum from the (trusted) payload. Only the 2-byte
/// checksum field is touched; a no-op for non-TCP/UDP, fragmented, or malformed
/// packets.
pub(crate) fn recompute_transport_checksum(packet: &mut [u8]) {
    match packet.first().map(|b| b >> 4) {
        Some(4) => recompute_ipv4_transport_checksum(packet),
        Some(6) => recompute_ipv6_transport_checksum(packet),
        _ => {},
    }
}

fn transport_checksum_field_offset(protocol: u8) -> Option<usize> {
    match protocol {
        IPV6_NEXT_HEADER_TCP => Some(16),
        IPV6_NEXT_HEADER_UDP => Some(6),
        _ => None,
    }
}

fn recompute_ipv4_transport_checksum(packet: &mut [u8]) {
    if packet.len() < IPV4_HEADER_LEN {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < IPV4_HEADER_LEN || total_len < ihl || total_len > packet.len() {
        return;
    }
    // Fragments carry only part of the L4 payload — never recompute.
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x3fff) != 0 {
        return;
    }
    let protocol = packet[9];
    let Some(field) = transport_checksum_field_offset(protocol) else {
        return;
    };
    if ihl + field + 2 > total_len {
        return;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    packet[ihl + field..ihl + field + 2].fill(0);
    let mut checksum =
        ipv4_payload_checksum(source, destination, protocol, &packet[ihl..total_len]);
    // A UDP checksum of 0 means "none"; the real value is transmitted as 0xffff.
    if protocol == IPV6_NEXT_HEADER_UDP && checksum == 0 {
        checksum = 0xffff;
    }
    packet[ihl + field..ihl + field + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recompute_ipv6_transport_checksum(packet: &mut [u8]) {
    let Ok((next_header, l4_offset, total_len)) = locate_ipv6_upper_layer(packet) else {
        return;
    };
    if next_header == IPV6_NEXT_HEADER_FRAGMENT {
        return;
    }
    let Some(field) = transport_checksum_field_offset(next_header) else {
        return;
    };
    if l4_offset + field + 2 > total_len || total_len > packet.len() {
        return;
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    let source = Ipv6Addr::from(source);
    let destination = Ipv6Addr::from(destination);
    packet[l4_offset + field..l4_offset + field + 2].fill(0);
    let mut checksum =
        ipv6_payload_checksum(source, destination, next_header, &packet[l4_offset..total_len]);
    if next_header == IPV6_NEXT_HEADER_UDP && checksum == 0 {
        checksum = 0xffff;
    }
    packet[l4_offset + field..l4_offset + field + 2].copy_from_slice(&checksum.to_be_bytes());
}

#[cfg(test)]
mod tests;
