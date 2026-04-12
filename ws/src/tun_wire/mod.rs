#[cfg(test)]
pub(crate) mod test_utils;

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IpVersion {
    V4,
    V6,
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
                }
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
            }
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
            }
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
            }
            _ => {
                return Ok(Ipv6PayloadInfo {
                    next_header,
                    payload_offset: offset,
                    total_len,
                    next_header_field_offset,
                });
            }
        }
    }
}

pub(crate) fn locate_ipv6_upper_layer(packet: &[u8]) -> Result<(u8, usize, usize)> {
    let info = locate_ipv6_payload(packet)?;
    Ok((info.next_header, info.payload_offset, info.total_len))
}

#[cfg(test)]
mod tests {
    use super::{checksum16, checksum16_parts};

    #[test]
    fn checksum16_parts_matches_flat_buffer_for_odd_boundaries() {
        let parts = [
            b"\x12".as_slice(),
            b"\x34\x56".as_slice(),
            b"\x78\x9a\xbc".as_slice(),
        ];
        let flat = b"\x12\x34\x56\x78\x9a\xbc";
        assert_eq!(checksum16_parts(&parts), checksum16(flat));
    }
}
