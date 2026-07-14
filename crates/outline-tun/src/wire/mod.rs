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
    let mut sum: u64 = 0;
    // High byte of a 16-bit word straddling a part boundary: the internet
    // checksum groups the concatenation of all parts into big-endian 16-bit
    // words, so an odd-length part pairs its last byte with the first byte of
    // the next non-empty part.
    let mut pending: Option<u8> = None;

    for part in parts {
        let mut bytes = *part;
        if let Some(high) = pending {
            match bytes.split_first() {
                Some((&low, rest)) => {
                    sum += u64::from(u16::from_be_bytes([high, low]));
                    pending = None;
                    bytes = rest;
                },
                // Empty part: carry the pending high byte to the next one.
                None => continue,
            }
        }
        // `bytes` now begins on a 16-bit-word boundary. Fold eight bytes (four
        // words) per step through a wide accumulator: the one's-complement sum
        // is grouping-independent, so accumulating in u64 and folding the
        // end-around carry once at the end is exact, and a u64 cannot overflow
        // for any datagram size.
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let word =
                u64::from_be_bytes(chunk.try_into().expect("chunks_exact(8) yields 8 bytes"));
            sum += word >> 32;
            sum += word & 0xffff_ffff;
        }
        let rem = chunks.remainder();
        let mut i = 0;
        while i + 2 <= rem.len() {
            sum += u64::from(u16::from_be_bytes([rem[i], rem[i + 1]]));
            i += 2;
        }
        if i < rem.len() {
            pending = Some(rem[i]);
        }
    }

    if let Some(high) = pending {
        sum += u64::from(u16::from_be_bytes([high, 0]));
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

/// Provenance of a packet's L4 (TCP/UDP) checksum by the time an engine parses it.
///
/// The TCP parser validates the checksum over the whole segment — a full pass
/// over the payload. That pass is worth paying for a checksum we did not
/// produce, and pure waste for one we just wrote ourselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum L4Checksum {
    /// The checksum on the wire is the sender's (or the kernel handed the packet
    /// over with the checksum already final). Validate it.
    Unverified,
    /// [`recompute_transport_checksum`] rewrote this packet's checksum in this
    /// very read-loop iteration, over these exact bytes. Re-validating it would
    /// only re-check our own arithmetic.
    Recomputed,
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
///
/// Returns [`L4Checksum::Recomputed`] only when the checksum field was actually
/// rewritten. Every early return below (short packet, IP fragment, non-TCP/UDP
/// protocol, checksum field beyond the stated length) leaves the sender's
/// checksum in place, and the parser must still validate it — hence
/// [`L4Checksum::Unverified`] in those cases.
pub(crate) fn recompute_transport_checksum(packet: &mut [u8]) -> L4Checksum {
    let recomputed = match packet.first().map(|b| b >> 4) {
        Some(4) => recompute_ipv4_transport_checksum(packet),
        Some(6) => recompute_ipv6_transport_checksum(packet),
        _ => false,
    };
    if recomputed {
        L4Checksum::Recomputed
    } else {
        L4Checksum::Unverified
    }
}

fn transport_checksum_field_offset(protocol: u8) -> Option<usize> {
    match protocol {
        IPV6_NEXT_HEADER_TCP => Some(16),
        IPV6_NEXT_HEADER_UDP => Some(6),
        _ => None,
    }
}

fn recompute_ipv4_transport_checksum(packet: &mut [u8]) -> bool {
    if packet.len() < IPV4_HEADER_LEN {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < IPV4_HEADER_LEN || total_len < ihl || total_len > packet.len() {
        return false;
    }
    // Fragments carry only part of the L4 payload — never recompute.
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x3fff) != 0 {
        return false;
    }
    let protocol = packet[9];
    let Some(field) = transport_checksum_field_offset(protocol) else {
        return false;
    };
    if ihl + field + 2 > total_len {
        return false;
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
    true
}

fn recompute_ipv6_transport_checksum(packet: &mut [u8]) -> bool {
    let Ok((next_header, l4_offset, total_len)) = locate_ipv6_upper_layer(packet) else {
        return false;
    };
    if next_header == IPV6_NEXT_HEADER_FRAGMENT {
        return false;
    }
    let Some(field) = transport_checksum_field_offset(next_header) else {
        return false;
    };
    if l4_offset + field + 2 > total_len || total_len > packet.len() {
        return false;
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
    true
}

#[cfg(test)]
mod tests;
