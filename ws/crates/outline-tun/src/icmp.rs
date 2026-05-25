//! Local ICMP / ICMPv6 synthesis.
//!
//! Two kinds of replies are built here:
//! * Echo reply — for `ping` requests targeted at the tunnel: we answer
//!   locally instead of forwarding upstream because there is no remote side
//!   for raw ICMP.
//! * `Fragmentation Needed` (IPv4) / `Packet Too Big` (IPv6) — emitted when
//!   the TUN UDP path drops an oversized datagram because the transport
//!   refuses to carry it. Without these, PMTUD inside the tunnel is blind
//!   and clients keep retransmitting the same too-large payload.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};

use crate::frag::fragment_ipv6_packet;
use crate::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_ICMPV6, checksum16, ipv6_payload_checksum,
    locate_ipv6_upper_layer,
};

pub(crate) const IPV6_MIN_PATH_MTU: usize = 1280;

/// Per RFC 791 every IPv4 host must accept at least 576-byte datagrams.
/// Used as a floor for the Next-Hop MTU we advertise so we never claim a
/// value below the protocol minimum (some clients reject too-small MTU
/// values as bogus).
pub(crate) const IPV4_MIN_PATH_MTU: u16 = 576;

const ICMPV4_TYPE_DEST_UNREACHABLE: u8 = 3;
const ICMPV4_CODE_FRAG_NEEDED: u8 = 4;
const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;
const ICMPV4_PROTOCOL: u8 = 1;
/// Number of original-packet bytes we copy into the ICMPv4 error body:
/// IP header (no options) + first 8 bytes of payload = UDP header. RFC
/// 1812 §4.3.2.3 says the receiver needs at least this much to match the
/// reply back to the offending socket.
const ICMPV4_QUOTED_PACKET_BYTES: usize = IPV4_HEADER_LEN + 8;

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

/// Build an IPv4 `ICMP Destination Unreachable / Fragmentation Needed`
/// (Type 3 / Code 4) reply for `original_packet`.
///
/// `next_hop_mtu` is the MTU we advertise to the sender; it gets clamped
/// to the IPv4 protocol minimum (576) and to `u16::MAX`. `original_packet`
/// must be at least one IP header + 8 bytes (i.e. the original IP header
/// plus its first 8 bytes of payload — for UDP that is the whole UDP
/// header, which the receiving stack needs to match the error to a
/// socket).
pub(crate) fn build_icmpv4_frag_needed(
    next_hop_mtu: u16,
    original_packet: &[u8],
) -> Result<Vec<u8>> {
    if original_packet.len() < ICMPV4_QUOTED_PACKET_BYTES {
        bail!("original IPv4 packet too short to quote in ICMP Frag Needed");
    }
    let original_header_len = usize::from(original_packet[0] & 0x0f) * 4;
    if original_header_len < IPV4_HEADER_LEN || original_packet.len() < original_header_len + 8 {
        bail!("invalid original IPv4 header for ICMP Frag Needed");
    }
    let source_ip = Ipv4Addr::new(
        original_packet[16],
        original_packet[17],
        original_packet[18],
        original_packet[19],
    );
    let destination_ip = Ipv4Addr::new(
        original_packet[12],
        original_packet[13],
        original_packet[14],
        original_packet[15],
    );
    let advertised_mtu = next_hop_mtu.max(IPV4_MIN_PATH_MTU);

    let quoted = &original_packet[..original_header_len + 8];
    let icmp_body_len = 8 + quoted.len();
    let total_len = IPV4_HEADER_LEN + icmp_body_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = ICMPV4_PROTOCOL;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let icmp_offset = IPV4_HEADER_LEN;
    packet[icmp_offset] = ICMPV4_TYPE_DEST_UNREACHABLE;
    packet[icmp_offset + 1] = ICMPV4_CODE_FRAG_NEEDED;
    // Bytes 2..4 are the ICMP checksum, written below.
    // Bytes 4..6 are unused (must be zero per RFC 792).
    packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&advertised_mtu.to_be_bytes());
    packet[icmp_offset + 8..icmp_offset + 8 + quoted.len()].copy_from_slice(quoted);
    let icmp_checksum = checksum16(&packet[icmp_offset..total_len]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

/// Build an IPv6 `ICMPv6 Packet Too Big` (Type 2 / Code 0) reply for
/// `original_packet`.
///
/// `mtu` is the MTU we advertise; it gets clamped to the IPv6 protocol
/// minimum (1280). The body includes as much of `original_packet` as fits
/// without growing the final IPv6 packet above the IPv6 minimum path MTU
/// — per RFC 4443 §2.4(c).
pub(crate) fn build_icmpv6_packet_too_big(mtu: u32, original_packet: &[u8]) -> Result<Vec<u8>> {
    if original_packet.len() < IPV6_HEADER_LEN {
        bail!("original IPv6 packet too short to quote in ICMPv6 PTB");
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&original_packet[24..40]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&original_packet[8..24]);
    let source_ip = Ipv6Addr::from(source);
    let destination_ip = Ipv6Addr::from(destination);

    let advertised_mtu = mtu.max(IPV6_MIN_PATH_MTU as u32);
    // Reserve space for the outer IPv6 header (40) and the ICMPv6 header
    // (8: type+code+checksum+MTU); copy as much of the offending packet
    // as fits without exceeding the IPv6 minimum link MTU (1280).
    let icmp_header_len = 8;
    let max_quote = IPV6_MIN_PATH_MTU
        .saturating_sub(IPV6_HEADER_LEN)
        .saturating_sub(icmp_header_len);
    let quoted_len = original_packet.len().min(max_quote);
    let quoted = &original_packet[..quoted_len];

    let icmp_body_len = icmp_header_len + quoted.len();
    let total_len = IPV6_HEADER_LEN + icmp_body_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_body_len as u16).to_be_bytes());
    packet[6] = IPV6_NEXT_HEADER_ICMPV6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let icmp_offset = IPV6_HEADER_LEN;
    packet[icmp_offset] = ICMPV6_TYPE_PACKET_TOO_BIG;
    packet[icmp_offset + 1] = 0;
    // Bytes 2..4 are the checksum, written below.
    packet[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&advertised_mtu.to_be_bytes());
    packet[icmp_offset + 8..icmp_offset + 8 + quoted.len()].copy_from_slice(quoted);
    let icmp_checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..total_len]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(packet)
}
