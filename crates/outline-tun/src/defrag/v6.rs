use std::time::Instant;

use anyhow::{Result, anyhow, bail};

use crate::wire::{IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, locate_ipv6_payload};

use super::PacketInspection;
use super::chunk::{FragmentChunk, chunks_are_complete};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Ipv6Key {
    pub(super) source: [u8; 16],
    pub(super) destination: [u8; 16],
    pub(super) identification: u32,
    pub(super) upper_layer_header: u8,
}

#[derive(Debug)]
pub(super) struct Ipv6Fragment<'a> {
    pub(super) key: Ipv6Key,
    pub(super) prefix: &'a [u8],
    pub(super) next_header_field_offset: usize,
    pub(super) upper_layer_header: u8,
    pub(super) offset: usize,
    pub(super) more_fragments: bool,
    pub(super) payload: &'a [u8],
}

#[derive(Debug)]
pub(super) struct Ipv6FragmentSet {
    pub(super) deadline: Instant,
    pub(super) prefix: Vec<u8>,
    pub(super) next_header_field_offset: usize,
    pub(super) upper_layer_header: u8,
    pub(super) chunks: Vec<FragmentChunk>,
    pub(super) total_payload_len: Option<usize>,
}

impl Ipv6FragmentSet {
    pub(super) fn estimated_bytes(&self) -> usize {
        self.prefix.len() + self.chunks.iter().map(FragmentChunk::len).sum::<usize>()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.total_payload_len
            .is_some_and(|total| chunks_are_complete(&self.chunks, total))
    }

    pub(super) fn build_packet(self) -> Result<Vec<u8>> {
        let payload_len = self
            .total_payload_len
            .ok_or_else(|| anyhow!("missing IPv6 reassembled payload length"))?;
        if !chunks_are_complete(&self.chunks, payload_len) {
            bail!("incomplete IPv6 fragment set");
        }
        let total_len = self
            .prefix
            .len()
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("IPv6 packet length overflow"))?;
        let ipv6_payload_len = total_len
            .checked_sub(IPV6_HEADER_LEN)
            .ok_or_else(|| anyhow!("invalid IPv6 reassembled prefix length"))?;
        if ipv6_payload_len > usize::from(u16::MAX) {
            bail!("IPv6 reassembled payload exceeds maximum length");
        }

        let mut packet = vec![0u8; total_len];
        packet[..self.prefix.len()].copy_from_slice(&self.prefix);
        packet[self.next_header_field_offset] = self.upper_layer_header;
        packet[4..6].copy_from_slice(&(ipv6_payload_len as u16).to_be_bytes());

        let mut offset = self.prefix.len();
        for chunk in self.chunks {
            packet[offset..offset + chunk.data.len()].copy_from_slice(&chunk.data);
            offset += chunk.data.len();
        }
        Ok(packet)
    }
}

pub(super) fn inspect_ipv6(packet: &[u8]) -> Result<PacketInspection<'_>> {
    let info = locate_ipv6_payload(packet)?;
    if info.next_header != IPV6_NEXT_HEADER_FRAGMENT {
        return Ok(PacketInspection::Passthrough);
    }
    if info.payload_offset + 8 > info.total_len {
        bail!("truncated IPv6 fragment header");
    }

    let fragment_offset_and_flags =
        u16::from_be_bytes([packet[info.payload_offset + 2], packet[info.payload_offset + 3]]);
    let offset = usize::from(fragment_offset_and_flags >> 3)
        .checked_mul(8)
        .ok_or_else(|| anyhow!("IPv6 fragment offset overflow"))?;
    let more_fragments = (fragment_offset_and_flags & 0x1) != 0;
    let payload = &packet[info.payload_offset + 8..info.total_len];
    if more_fragments && !payload.len().is_multiple_of(8) {
        bail!("IPv6 non-terminal fragment payload length is not 8-byte aligned");
    }

    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    Ok(PacketInspection::Ipv6Fragment(Ipv6Fragment {
        key: Ipv6Key {
            source,
            destination,
            identification: u32::from_be_bytes([
                packet[info.payload_offset + 4],
                packet[info.payload_offset + 5],
                packet[info.payload_offset + 6],
                packet[info.payload_offset + 7],
            ]),
            upper_layer_header: packet[info.payload_offset],
        },
        prefix: &packet[..info.payload_offset],
        next_header_field_offset: info.next_header_field_offset,
        upper_layer_header: packet[info.payload_offset],
        offset,
        more_fragments,
        payload,
    }))
}

pub(super) fn ipv6_prefix_matches(stored: &[u8], incoming: &[u8]) -> bool {
    if stored.len() != incoming.len() {
        return false;
    }
    if stored.len() < IPV6_HEADER_LEN {
        return false;
    }
    stored[..4] == incoming[..4]
        && stored[6..] == incoming[6..]
        && stored[4..6].len() == incoming[4..6].len()
}
