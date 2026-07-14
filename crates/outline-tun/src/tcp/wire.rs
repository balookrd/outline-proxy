// Low-level TCP/IP packet builders: the parameters here are the wire-format
// header fields themselves, so `too_many_arguments` is noise — refactoring
// into a struct just renames the same fields.
#![allow(clippy::too_many_arguments)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;

use super::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};
use crate::wire::{
    L4Checksum, checksum16, checksum16_parts, ipv4_payload_checksum, ipv6_payload_checksum,
    locate_ipv6_upper_layer,
};

const TCP_HEADER_LEN: usize = 20;
#[cfg(test)]
pub(super) use crate::wire::IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
pub(super) use crate::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, IPV6_NEXT_HEADER_TCP, IpVersion,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedTcpPacket {
    pub(crate) version: IpVersion,
    pub(crate) source_ip: IpAddr,
    pub(crate) destination_ip: IpAddr,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) sequence_number: u32,
    pub(crate) acknowledgement_number: u32,
    pub(crate) window_size: u16,
    pub(crate) max_segment_size: Option<u16>,
    pub(crate) window_scale: Option<u8>,
    pub(crate) sack_permitted: bool,
    pub(crate) sack_blocks: Vec<(u32, u32)>,
    pub(super) timestamp_value: Option<u32>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) timestamp_echo_reply: Option<u32>,
    pub(crate) flags: u8,
    pub(crate) payload: Bytes,
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

/// Parse an inbound TCP/IP packet.
///
/// `checksum` records where the segment's TCP checksum came from. The IP header
/// checksum is always verified (20 bytes); the *TCP* checksum covers the whole
/// segment, so validating it walks the entire payload — and that walk is skipped
/// for a checksum this process just wrote itself (see [`L4Checksum`]).
pub(crate) fn parse_tcp_packet(packet: &[u8], checksum: L4Checksum) -> Result<ParsedTcpPacket> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN TCP packet"))? >> 4;
    match version {
        4 => parse_ipv4_tcp_packet(packet, checksum),
        6 => parse_ipv6_tcp_packet(packet, checksum),
        other => bail!("unsupported IP version in TUN TCP packet: {other}"),
    }
}

/// Test shim: parse a packet carrying a sender-produced checksum, which is what
/// every test packet builder emits. Production call sites state the provenance
/// explicitly instead of defaulting to one.
#[cfg(test)]
pub(crate) fn parse_tcp_packet_unverified(packet: &[u8]) -> Result<ParsedTcpPacket> {
    parse_tcp_packet(packet, L4Checksum::Unverified)
}

fn parse_ipv4_tcp_packet(packet: &[u8], checksum: L4Checksum) -> Result<ParsedTcpPacket> {
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
        checksum,
    )
}

fn parse_ipv6_tcp_packet(packet: &[u8], checksum: L4Checksum) -> Result<ParsedTcpPacket> {
    if packet.len() < IPV6_HEADER_LEN + TCP_HEADER_LEN {
        bail!("short IPv6 TCP packet");
    }
    let (next_header, segment_offset, total_len) = locate_ipv6_upper_layer(packet)?;
    if next_header == IPV6_NEXT_HEADER_FRAGMENT {
        bail!("IPv6 fragments are not supported on TUN TCP path");
    }
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
        checksum,
    )
}

fn parse_tcp_segment(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
    checksum: L4Checksum,
) -> Result<ParsedTcpPacket> {
    if segment.len() < TCP_HEADER_LEN {
        bail!("short TCP segment");
    }
    match checksum {
        L4Checksum::Unverified => {
            validate_tcp_checksum(version, source_ip, destination_ip, segment)?;
        },
        // The read loop already folded this exact segment to produce the
        // checksum now sitting in it (the kernel handed the packet over with
        // `F_NEEDS_CSUM`), so validating is a second full pass over the payload
        // that can only ever confirm our own arithmetic. Keep the pass in debug
        // builds as a standing proof that the skip is sound.
        L4Checksum::Recomputed => debug_assert!(
            matches!(tcp_checksum_valid(version, source_ip, destination_ip, segment), Ok(true)),
            "a recomputed TCP checksum must validate"
        ),
    }
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
        payload: Bytes::copy_from_slice(&segment[header_len..]),
    })
}

/// Fold the pseudo-header and the whole segment (header + payload) and report
/// whether the carried checksum is correct. This walks every payload byte — the
/// single most expensive step of parsing a data segment.
fn tcp_checksum_valid(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<bool> {
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => Ok(
            ipv4_payload_checksum(source_ip, destination_ip, IPV6_NEXT_HEADER_TCP, segment) == 0,
        ),
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => Ok(
            ipv6_payload_checksum(source_ip, destination_ip, IPV6_NEXT_HEADER_TCP, segment) == 0,
        ),
        _ => bail!("unexpected address family while validating TCP checksum"),
    }
}

fn validate_tcp_checksum(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<()> {
    if !tcp_checksum_valid(version, source_ip, destination_ip, segment)? {
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
                    },
                    3 if body.len() == 1 => {
                        parsed.window_scale = Some(body[0].min(14));
                    },
                    4 if body.is_empty() => {
                        parsed.sack_permitted = true;
                    },
                    5 if body.len() >= 8 && body.len().is_multiple_of(8) => {
                        for block in body.chunks_exact(8) {
                            let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                            let right =
                                u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
                            if seq_lt(left, right) {
                                parsed.sack_blocks.push((left, right));
                            }
                        }
                    },
                    8 if body.len() == 8 => {
                        parsed.timestamp_value =
                            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                        parsed.timestamp_echo_reply =
                            Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
                    },
                    _ => {},
                }
                index += len;
            },
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
                TcpChecksumMode::Full,
            )
        },
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
                TcpChecksumMode::Full,
            )
        },
        _ => bail!("unexpected address family in TUN TCP response"),
    }
}

/// How the emitted TCP checksum is computed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpChecksumMode {
    /// Full RFC 793 checksum over pseudo-header + segment. Used for every
    /// packet written as a single IP packet (the normal path).
    Full,
    /// Partial (pseudo-header only) checksum for kernel TSO offload
    /// (`VIRTIO_NET_HDR_F_NEEDS_CSUM`): the kernel finalises the L4 checksum
    /// for each MSS segment it splits the super-segment into.
    Partial,
}

/// Build an IPv4 + TCP header (no payload). The IP total-length field and the
/// TCP checksum both account for the payload (`payload_len` bytes, supplied as
/// `payload_parts` for the `Full` checksum), but the payload bytes are never
/// copied into the returned buffer — the caller writes them as separate `writev`
/// slices. In `Partial` (TSO) mode the payload is not even read: the kernel
/// finalises the per-segment L4 checksum, so the pseudo-header checksum needs
/// only its length and `payload_parts` may be empty.
fn build_ipv4_tcp_header(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload_len: usize,
    payload_parts: &[&[u8]],
    checksum_mode: TcpChecksumMode,
) -> Result<Vec<u8>> {
    if !options.len().is_multiple_of(4) {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let total_len = IPV4_HEADER_LEN + tcp_header_len + payload_len;
    let mut header = vec![0u8; IPV4_HEADER_LEN + tcp_header_len];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[8] = 64;
    header[9] = 6;
    header[12..16].copy_from_slice(&source_ip.octets());
    header[16..20].copy_from_slice(&destination_ip.octets());

    write_tcp_header(
        &mut header[IPV4_HEADER_LEN..],
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
    );

    let tcp_checksum = match checksum_mode {
        // Sum the pseudo-header, the TCP header (checksum field still zero) and
        // the payload chunks as separate parts — `checksum16_parts` folds across
        // part boundaries, so this is byte-identical to the checksum of the
        // contiguous header+payload while leaving the payload uncopied.
        TcpChecksumMode::Full => {
            debug_assert_eq!(
                payload_parts.iter().map(|p| p.len()).sum::<usize>(),
                payload_len,
                "payload_parts must sum to payload_len in Full mode"
            );
            let source = source_ip.octets();
            let destination = destination_ip.octets();
            let protocol = [0u8, IPV6_NEXT_HEADER_TCP];
            let length = ((tcp_header_len + payload_len) as u16).to_be_bytes();
            let tcp_header = &header[IPV4_HEADER_LEN..];
            tcp_full_checksum(&source, &destination, &protocol, &length, tcp_header, payload_parts)
        },
        TcpChecksumMode::Partial => {
            ipv4_tcp_partial_checksum(source_ip, destination_ip, tcp_header_len + payload_len)
        },
    };
    header[IPV4_HEADER_LEN + 16..IPV4_HEADER_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    let header_checksum = checksum16(&header[..IPV4_HEADER_LEN]);
    header[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(header)
}

/// Full RFC 793 TCP checksum over the pseudo-header, the TCP header and the
/// payload chunks. Zero or one payload chunk uses a fixed-size parts array (no
/// allocation — the common ACK/FIN/single-segment path); multiple chunks (a
/// coalesced multi-`Bytes` segment) fall back to a heap parts list.
fn tcp_full_checksum(
    pseudo_a: &[u8],
    pseudo_b: &[u8],
    pseudo_c: &[u8],
    pseudo_d: &[u8],
    tcp_header: &[u8],
    payload_parts: &[&[u8]],
) -> u16 {
    if payload_parts.len() <= 1 {
        let payload = payload_parts.first().copied().unwrap_or(&[]);
        checksum16_parts(&[pseudo_a, pseudo_b, pseudo_c, pseudo_d, tcp_header, payload])
    } else {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(5 + payload_parts.len());
        parts.extend_from_slice(&[pseudo_a, pseudo_b, pseudo_c, pseudo_d, tcp_header]);
        parts.extend_from_slice(payload_parts);
        checksum16_parts(&parts)
    }
}

/// Build a full contiguous IPv4/TCP packet (header + payload). Thin wrapper over
/// [`build_ipv4_tcp_header`] used by the header-only control paths (reset, FIN,
/// pure ACK) and tests; the data path builds the header alone and writes the
/// payload vectored.
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
    checksum_mode: TcpChecksumMode,
) -> Result<Vec<u8>> {
    let mut packet = build_ipv4_tcp_header(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload.len(),
        &[payload],
        checksum_mode,
    )?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// IPv6 counterpart of [`build_ipv4_tcp_header`].
fn build_ipv6_tcp_header(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload_len: usize,
    payload_parts: &[&[u8]],
    checksum_mode: TcpChecksumMode,
) -> Result<Vec<u8>> {
    if !options.len().is_multiple_of(4) {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let mut header = vec![0u8; IPV6_HEADER_LEN + tcp_header_len];
    header[0] = 0x60;
    header[4..6].copy_from_slice(&((tcp_header_len + payload_len) as u16).to_be_bytes());
    header[6] = 6;
    header[7] = 64;
    header[8..24].copy_from_slice(&source_ip.octets());
    header[24..40].copy_from_slice(&destination_ip.octets());

    write_tcp_header(
        &mut header[IPV6_HEADER_LEN..],
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
    );

    let tcp_checksum = match checksum_mode {
        TcpChecksumMode::Full => {
            debug_assert_eq!(
                payload_parts.iter().map(|p| p.len()).sum::<usize>(),
                payload_len,
                "payload_parts must sum to payload_len in Full mode"
            );
            let source = source_ip.octets();
            let destination = destination_ip.octets();
            let length = ((tcp_header_len + payload_len) as u32).to_be_bytes();
            let next_header = [0u8, 0, 0, IPV6_NEXT_HEADER_TCP];
            let tcp_header = &header[IPV6_HEADER_LEN..];
            tcp_full_checksum(
                &source,
                &destination,
                &length,
                &next_header,
                tcp_header,
                payload_parts,
            )
        },
        TcpChecksumMode::Partial => {
            ipv6_tcp_partial_checksum(source_ip, destination_ip, tcp_header_len + payload_len)
        },
    };
    header[IPV6_HEADER_LEN + 16..IPV6_HEADER_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(header)
}

/// IPv6 counterpart of [`build_ipv4_tcp_packet`].
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
    checksum_mode: TcpChecksumMode,
) -> Result<Vec<u8>> {
    let mut packet = build_ipv6_tcp_header(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload.len(),
        &[payload],
        checksum_mode,
    )?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Partial (pseudo-header) TCP checksum for kernel TSO offload. Returns the
/// folded one's-complement sum of the pseudo-header, *not* complemented — the
/// kernel adds the checksum of the L4 bytes from `csum_start` and complements
/// the result for each MSS segment it emits. `tcp_len` is the full TCP
/// header+payload length of the super-segment (`tcp_gso_segment` corrects the
/// per-segment length delta).
fn ipv4_tcp_partial_checksum(source: Ipv4Addr, destination: Ipv4Addr, tcp_len: usize) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let protocol = [0u8, IPV6_NEXT_HEADER_TCP];
    let length = (tcp_len as u16).to_be_bytes();
    !checksum16_parts(&[&source[..], &destination[..], &protocol[..], &length[..]])
}

fn ipv6_tcp_partial_checksum(source: Ipv6Addr, destination: Ipv6Addr, tcp_len: usize) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let length = (tcp_len as u32).to_be_bytes();
    let next_header = [0u8, 0, 0, IPV6_NEXT_HEADER_TCP];
    !checksum16_parts(&[&source[..], &destination[..], &length[..], &next_header[..]])
}

/// Build the *header* of a TCP/IP super-segment carrying a *partial* checksum
/// for kernel TSO. Returns the header (IP + TCP, no payload), its L3 header
/// length (the vnet `csum_start`) and its L4 (TCP) header length, so the caller
/// can fill a `virtio_net_hdr` whose `hdr_len = l3 + l4` and whose `gso_size`
/// is the MSS the kernel splits `payload` into. The payload is written vectored
/// by the caller and never copied here.
pub(super) fn build_gso_tcp_header(
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
    payload_len: usize,
) -> Result<(Vec<u8>, u16, u16)> {
    let l4_len = (TCP_HEADER_LEN + options.len()) as u16;
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            let header = build_ipv4_tcp_header(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload_len,
                &[],
                TcpChecksumMode::Partial,
            )?;
            Ok((header, IPV4_HEADER_LEN as u16, l4_len))
        },
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            let header = build_ipv6_tcp_header(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload_len,
                &[],
                TcpChecksumMode::Partial,
            )?;
            Ok((header, IPV6_HEADER_LEN as u16, l4_len))
        },
        _ => bail!("unexpected address family in TUN GSO response"),
    }
}

/// Build the IP + TCP header (no payload) for a single downlink data packet
/// with a full RFC 793 checksum. Mirrors [`build_response_packet_custom`] but
/// leaves the payload for the caller to write vectored. `payload_parts` is the
/// payload split into one or more `Bytes` chunks (folded into the checksum in
/// order); the header records their combined length.
pub(super) fn build_data_header_custom(
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
    payload_parts: &[&[u8]],
) -> Result<Vec<u8>> {
    let payload_len = payload_parts.iter().map(|p| p.len()).sum();
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            build_ipv4_tcp_header(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload_len,
                payload_parts,
                TcpChecksumMode::Full,
            )
        },
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            build_ipv6_tcp_header(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload_len,
                payload_parts,
                TcpChecksumMode::Full,
            )
        },
        _ => bail!("unexpected address family in TUN TCP response"),
    }
}

/// Write the fixed TCP header and options into `tcp` (which must be exactly the
/// TCP header length). The checksum field is left zero for the caller to fill;
/// the payload is not written here.
fn write_tcp_header(
    tcp: &mut [u8],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
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
}
fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

#[cfg(test)]
#[path = "tests/wire.rs"]
mod tests;
