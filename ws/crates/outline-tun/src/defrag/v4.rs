use std::time::Instant;

use anyhow::{Result, anyhow, bail};

use crate::wire::IPV4_HEADER_LEN;

use super::PacketInspection;
use super::chunk::{FragmentChunk, chunks_are_complete};

const IPV4_MF_FLAG: u16 = 0x2000;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Ipv4Key {
    pub(super) source: [u8; 4],
    pub(super) destination: [u8; 4],
    pub(super) protocol: u8,
    pub(super) identification: u16,
}

#[derive(Debug)]
pub(super) struct Ipv4Fragment<'a> {
    pub(super) key: Ipv4Key,
    pub(super) header: &'a [u8],
    pub(super) offset: usize,
    pub(super) more_fragments: bool,
    pub(super) payload: &'a [u8],
}

#[derive(Debug)]
pub(super) struct Ipv4FragmentSet {
    pub(super) deadline: Instant,
    pub(super) header: Option<Vec<u8>>,
    pub(super) chunks: Vec<FragmentChunk>,
    pub(super) total_payload_len: Option<usize>,
}

impl Ipv4FragmentSet {
    pub(super) fn estimated_bytes(&self) -> usize {
        self.header.as_ref().map_or(0, Vec::len)
            + self.chunks.iter().map(FragmentChunk::len).sum::<usize>()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.header.is_some()
            && self
                .total_payload_len
                .is_some_and(|total| chunks_are_complete(&self.chunks, total))
    }

    pub(super) fn build_packet(self) -> Result<Vec<u8>> {
        let header = self
            .header
            .ok_or_else(|| anyhow!("missing IPv4 first fragment header"))?;
        let payload_len = self
            .total_payload_len
            .ok_or_else(|| anyhow!("missing IPv4 reassembled payload length"))?;
        if !chunks_are_complete(&self.chunks, payload_len) {
            bail!("incomplete IPv4 fragment set");
        }
        let total_len = header
            .len()
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("IPv4 packet length overflow"))?;
        if total_len > usize::from(u16::MAX) {
            bail!("IPv4 reassembled packet exceeds maximum length");
        }

        let mut packet = vec![0u8; total_len];
        packet[..header.len()].copy_from_slice(&header);
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0u16.to_be_bytes());

        let mut offset = header.len();
        for chunk in self.chunks {
            packet[offset..offset + chunk.data.len()].copy_from_slice(&chunk.data);
            offset += chunk.data.len();
        }

        let checksum = crate::wire::checksum16(&packet[..header.len()]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(packet)
    }
}

pub(super) fn inspect_ipv4(packet: &[u8]) -> Result<PacketInspection<'_>> {
    if packet.len() < IPV4_HEADER_LEN {
        bail!("short IPv4 packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 packet");
    }

    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    let offset = usize::from(fragment_field & IPV4_FRAGMENT_OFFSET_MASK)
        .checked_mul(8)
        .ok_or_else(|| anyhow!("IPv4 fragment offset overflow"))?;
    let more_fragments = (fragment_field & IPV4_MF_FLAG) != 0;
    if offset == 0 && !more_fragments {
        return Ok(PacketInspection::Passthrough);
    }

    let payload = &packet[header_len..total_len];
    if more_fragments && !payload.len().is_multiple_of(8) {
        bail!("IPv4 non-terminal fragment payload length is not 8-byte aligned");
    }
    Ok(PacketInspection::Ipv4Fragment(Ipv4Fragment {
        key: Ipv4Key {
            source: [packet[12], packet[13], packet[14], packet[15]],
            destination: [packet[16], packet[17], packet[18], packet[19]],
            protocol: packet[9],
            identification: u16::from_be_bytes([packet[4], packet[5]]),
        },
        header: &packet[..header_len],
        offset,
        more_fragments,
        payload,
    }))
}
