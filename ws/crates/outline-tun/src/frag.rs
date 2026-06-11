//! IPv6 fragmentation for outbound-to-TUN packets.
//!
//! Used only for locally-generated replies (currently ICMPv6 echo) that
//! exceed the IPv6 minimum path MTU. Forwarded traffic is never fragmented
//! by this module — the upstream side is expected to respect path MTU.

use anyhow::{Result, anyhow, bail};
use rand::random;

use crate::icmp::IPV6_MIN_PATH_MTU;
use crate::wire::{IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, locate_ipv6_payload};

pub(crate) fn fragment_ipv6_packet(packet: Vec<u8>, mtu: usize) -> Result<Vec<Vec<u8>>> {
    if mtu < IPV6_MIN_PATH_MTU {
        bail!("IPv6 fragmentation MTU must be at least {IPV6_MIN_PATH_MTU}");
    }
    if packet.len() <= mtu {
        return Ok(vec![packet]);
    }

    let info = locate_ipv6_payload(&packet)?;
    if info.next_header == IPV6_NEXT_HEADER_FRAGMENT {
        bail!("attempted to fragment an already-fragmented IPv6 packet");
    }

    let unfragmentable_len = info.payload_offset;
    let chunk_budget = mtu
        .checked_sub(unfragmentable_len + 8)
        .ok_or_else(|| anyhow!("IPv6 MTU is too small for fragment header"))?;
    let non_terminal_chunk_budget = chunk_budget & !7usize;
    if non_terminal_chunk_budget == 0 {
        bail!("IPv6 MTU leaves no room for fragment payload");
    }

    let fragmentable = &packet[info.payload_offset..info.total_len];
    let identification = random::<u32>();
    let mut fragments = Vec::new();
    let mut offset = 0usize;

    while offset < fragmentable.len() {
        let remaining = fragmentable.len() - offset;
        let is_last = remaining <= chunk_budget;
        let chunk_len = if is_last { remaining } else { non_terminal_chunk_budget };
        if chunk_len == 0 {
            bail!("IPv6 fragment chunk length is zero");
        }

        let total_len = unfragmentable_len
            .checked_add(8)
            .and_then(|len| len.checked_add(chunk_len))
            .ok_or_else(|| anyhow!("IPv6 fragment length overflow"))?;
        let payload_len = total_len
            .checked_sub(IPV6_HEADER_LEN)
            .ok_or_else(|| anyhow!("invalid IPv6 fragment length"))?;
        if payload_len > usize::from(u16::MAX) {
            bail!("IPv6 fragment payload exceeds maximum length");
        }

        let mut fragment = vec![0u8; total_len];
        fragment[..unfragmentable_len].copy_from_slice(&packet[..unfragmentable_len]);
        fragment[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        fragment[info.next_header_field_offset] = IPV6_NEXT_HEADER_FRAGMENT;
        fragment[info.payload_offset] = info.next_header;
        fragment[info.payload_offset + 1] = 0;
        let offset_units = u16::try_from(offset / 8)
            .map_err(|_| anyhow!("IPv6 fragment offset exceeds maximum"))?;
        let fragment_offset_field = (offset_units << 3) | u16::from(!is_last);
        fragment[info.payload_offset + 2..info.payload_offset + 4]
            .copy_from_slice(&fragment_offset_field.to_be_bytes());
        fragment[info.payload_offset + 4..info.payload_offset + 8]
            .copy_from_slice(&identification.to_be_bytes());
        fragment[info.payload_offset + 8..]
            .copy_from_slice(&fragmentable[offset..offset + chunk_len]);
        fragments.push(fragment);
        offset += chunk_len;
    }

    Ok(fragments)
}
