use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};

use crate::memory::maybe_shrink_hash_map;
use crate::metrics;
use crate::tun_wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, IpVersion, locate_ipv6_payload,
};

const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FRAGMENT_SETS: usize = 1024;
const MAX_FRAGMENTS_PER_SET: usize = 64;
const MAX_BYTES_PER_SET: usize = 128 * 1024;
const MAX_TOTAL_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
const IPV4_MF_FLAG: u16 = 0x2000;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(crate) enum DefragmentedPacket {
    ReadyBorrowed,
    ReadyOwned(Vec<u8>),
    Pending,
    Dropped(&'static str),
}

pub(crate) struct TunDefragmenter {
    ipv4_sets: HashMap<Ipv4Key, Ipv4FragmentSet>,
    ipv6_sets: HashMap<Ipv6Key, Ipv6FragmentSet>,
    total_buffered_bytes: usize,
    next_cleanup_at: Instant,
    max_fragment_sets: usize,
    max_fragments_per_set: usize,
    max_bytes_per_set: usize,
    max_total_buffered_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv4Key {
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    identification: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv6Key {
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
    upper_layer_header: u8,
}

#[derive(Debug)]
struct Ipv4FragmentSet {
    deadline: Instant,
    header: Option<Vec<u8>>,
    chunks: Vec<FragmentChunk>,
    total_payload_len: Option<usize>,
}

#[derive(Debug)]
struct Ipv6FragmentSet {
    deadline: Instant,
    prefix: Vec<u8>,
    next_header_field_offset: usize,
    upper_layer_header: u8,
    chunks: Vec<FragmentChunk>,
    total_payload_len: Option<usize>,
}

#[derive(Debug)]
struct FragmentChunk {
    offset: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
enum PacketInspection<'a> {
    Passthrough,
    Ipv4Fragment(Ipv4Fragment<'a>),
    Ipv6Fragment(Ipv6Fragment<'a>),
}

#[derive(Debug)]
struct Ipv4Fragment<'a> {
    key: Ipv4Key,
    header: &'a [u8],
    offset: usize,
    more_fragments: bool,
    payload: &'a [u8],
}

#[derive(Debug)]
struct Ipv6Fragment<'a> {
    key: Ipv6Key,
    prefix: &'a [u8],
    next_header_field_offset: usize,
    upper_layer_header: u8,
    offset: usize,
    more_fragments: bool,
    payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkInsertOutcome {
    Inserted(usize),
    DuplicateExact,
    Overlap,
}

impl Default for TunDefragmenter {
    fn default() -> Self {
        Self::new(
            MAX_TOTAL_BUFFERED_BYTES,
            MAX_BYTES_PER_SET,
            MAX_FRAGMENT_SETS,
            MAX_FRAGMENTS_PER_SET,
        )
    }
}

impl TunDefragmenter {
    pub(crate) fn new(
        max_total_buffered_bytes: usize,
        max_bytes_per_set: usize,
        max_fragment_sets: usize,
        max_fragments_per_set: usize,
    ) -> Self {
        Self {
            ipv4_sets: HashMap::new(),
            ipv6_sets: HashMap::new(),
            total_buffered_bytes: 0,
            next_cleanup_at: Instant::now() + CLEANUP_INTERVAL,
            max_fragment_sets,
            max_fragments_per_set,
            max_bytes_per_set,
            max_total_buffered_bytes,
        }
    }

    pub(crate) fn cleanup_interval() -> Duration {
        CLEANUP_INTERVAL
    }

    pub(crate) fn push(&mut self, packet: &[u8]) -> Result<DefragmentedPacket> {
        let now = Instant::now();
        self.run_maintenance_at(now);

        match inspect_packet(packet)? {
            PacketInspection::Passthrough => Ok(DefragmentedPacket::ReadyBorrowed),
            PacketInspection::Ipv4Fragment(fragment) => {
                metrics::record_tun_ip_fragment_received("ipv4");
                self.handle_ipv4_fragment(now, fragment)
            },
            PacketInspection::Ipv6Fragment(fragment) => {
                metrics::record_tun_ip_fragment_received("ipv6");
                self.handle_ipv6_fragment(now, fragment)
            },
        }
    }

    pub(crate) fn run_maintenance(&mut self) {
        self.run_maintenance_at(Instant::now());
    }

    fn run_maintenance_at(&mut self, now: Instant) {
        if now >= self.next_cleanup_at {
            self.sweep_expired(now);
            self.next_cleanup_at = now + CLEANUP_INTERVAL;
        }
    }

    fn handle_ipv4_fragment(
        &mut self,
        now: Instant,
        fragment: Ipv4Fragment<'_>,
    ) -> Result<DefragmentedPacket> {
        if !self.ipv4_sets.contains_key(&fragment.key)
            && self.fragment_set_count() >= self.max_fragment_sets
        {
            metrics::record_tun_ip_reassembly("ipv4", "resource_limit");
            return Ok(DefragmentedPacket::Dropped("fragment resource limit"));
        }

        let mut should_remove = None::<&'static str>;
        let mut is_complete = false;

        {
            let set = self.ipv4_sets.entry(fragment.key).or_insert_with(|| Ipv4FragmentSet {
                deadline: now + REASSEMBLY_TIMEOUT,
                header: None,
                chunks: Vec::new(),
                total_payload_len: None,
            });
            if set.header.is_none() && fragment.offset == 0 {
                set.header = Some(fragment.header.to_vec());
                self.total_buffered_bytes += fragment.header.len();
            }

            match insert_chunk(&mut set.chunks, fragment.offset, fragment.payload) {
                ChunkInsertOutcome::Inserted(bytes) => {
                    self.total_buffered_bytes += bytes;
                },
                ChunkInsertOutcome::DuplicateExact => {
                    set.deadline = now + REASSEMBLY_TIMEOUT;
                    return Ok(DefragmentedPacket::Pending);
                },
                ChunkInsertOutcome::Overlap => {
                    should_remove = Some("overlap");
                },
            }

            if should_remove.is_none() {
                let fragment_end = fragment
                    .offset
                    .checked_add(fragment.payload.len())
                    .ok_or_else(|| anyhow!("IPv4 fragment end offset overflow"))?;
                if !fragment.more_fragments {
                    match set.total_payload_len {
                        Some(existing) if existing != fragment_end => {
                            should_remove = Some("inconsistent");
                        },
                        _ => set.total_payload_len = Some(fragment_end),
                    }
                }

                set.deadline = now + REASSEMBLY_TIMEOUT;

                if should_remove.is_none()
                    && (set.chunks.len() > self.max_fragments_per_set
                        || set.estimated_bytes() > self.max_bytes_per_set
                        || self.total_buffered_bytes > self.max_total_buffered_bytes)
                {
                    should_remove = Some("resource_limit");
                }

                if should_remove.is_none() {
                    is_complete = set.is_complete();
                }
            }
        }

        self.set_active_fragment_sets_metric(IpVersion::V4);

        if let Some(reason) = should_remove {
            self.remove_ipv4_set(fragment.key);
            metrics::record_tun_ip_reassembly("ipv4", reason);
            return Ok(DefragmentedPacket::Dropped("fragment sequence dropped"));
        }

        if !is_complete {
            return Ok(DefragmentedPacket::Pending);
        }

        let packet = self
            .ipv4_sets
            .remove(&fragment.key)
            .expect("complete IPv4 fragment set must exist")
            .build_packet()?;
        maybe_shrink_hash_map(&mut self.ipv4_sets);
        self.recalculate_total_buffered_bytes();
        self.set_active_fragment_sets_metric(IpVersion::V4);
        metrics::record_tun_ip_reassembly("ipv4", "success");
        Ok(DefragmentedPacket::ReadyOwned(packet))
    }

    fn handle_ipv6_fragment(
        &mut self,
        now: Instant,
        fragment: Ipv6Fragment<'_>,
    ) -> Result<DefragmentedPacket> {
        if !self.ipv6_sets.contains_key(&fragment.key)
            && self.fragment_set_count() >= self.max_fragment_sets
        {
            metrics::record_tun_ip_reassembly("ipv6", "resource_limit");
            return Ok(DefragmentedPacket::Dropped("fragment resource limit"));
        }

        let mut should_remove = None::<&'static str>;
        let mut is_complete = false;

        {
            if !self.ipv6_sets.contains_key(&fragment.key) {
                self.total_buffered_bytes += fragment.prefix.len();
                self.ipv6_sets.insert(
                    fragment.key,
                    Ipv6FragmentSet {
                        deadline: now + REASSEMBLY_TIMEOUT,
                        prefix: fragment.prefix.to_vec(),
                        next_header_field_offset: fragment.next_header_field_offset,
                        upper_layer_header: fragment.upper_layer_header,
                        chunks: Vec::new(),
                        total_payload_len: None,
                    },
                );
            }
            let set = self
                .ipv6_sets
                .get_mut(&fragment.key)
                .expect("IPv6 fragment set must exist");

            if !ipv6_prefix_matches(&set.prefix, fragment.prefix)
                || set.next_header_field_offset != fragment.next_header_field_offset
                || set.upper_layer_header != fragment.upper_layer_header
            {
                should_remove = Some("inconsistent");
            } else {
                match insert_chunk(&mut set.chunks, fragment.offset, fragment.payload) {
                    ChunkInsertOutcome::Inserted(bytes) => {
                        self.total_buffered_bytes += bytes;
                    },
                    ChunkInsertOutcome::DuplicateExact => {
                        set.deadline = now + REASSEMBLY_TIMEOUT;
                        return Ok(DefragmentedPacket::Pending);
                    },
                    ChunkInsertOutcome::Overlap => {
                        should_remove = Some("overlap");
                    },
                }
            }

            if should_remove.is_none() {
                let fragment_end = fragment
                    .offset
                    .checked_add(fragment.payload.len())
                    .ok_or_else(|| anyhow!("IPv6 fragment end offset overflow"))?;
                if !fragment.more_fragments {
                    match set.total_payload_len {
                        Some(existing) if existing != fragment_end => {
                            should_remove = Some("inconsistent");
                        },
                        _ => set.total_payload_len = Some(fragment_end),
                    }
                }

                set.deadline = now + REASSEMBLY_TIMEOUT;

                if should_remove.is_none()
                    && (set.chunks.len() > self.max_fragments_per_set
                        || set.estimated_bytes() > self.max_bytes_per_set
                        || self.total_buffered_bytes > self.max_total_buffered_bytes)
                {
                    should_remove = Some("resource_limit");
                }

                if should_remove.is_none() {
                    is_complete = set.is_complete();
                }
            }
        }

        self.set_active_fragment_sets_metric(IpVersion::V6);

        if let Some(reason) = should_remove {
            self.remove_ipv6_set(fragment.key);
            metrics::record_tun_ip_reassembly("ipv6", reason);
            return Ok(DefragmentedPacket::Dropped("fragment sequence dropped"));
        }

        if !is_complete {
            return Ok(DefragmentedPacket::Pending);
        }

        let packet = self
            .ipv6_sets
            .remove(&fragment.key)
            .expect("complete IPv6 fragment set must exist")
            .build_packet()?;
        maybe_shrink_hash_map(&mut self.ipv6_sets);
        self.recalculate_total_buffered_bytes();
        self.set_active_fragment_sets_metric(IpVersion::V6);
        metrics::record_tun_ip_reassembly("ipv6", "success");
        Ok(DefragmentedPacket::ReadyOwned(packet))
    }

    fn sweep_expired(&mut self, now: Instant) {
        let mut ipv4_changed = false;
        self.ipv4_sets.retain(|_, set| {
            if now < set.deadline {
                return true;
            }
            metrics::record_tun_ip_reassembly("ipv4", "timeout");
            ipv4_changed = true;
            false
        });
        let mut ipv6_changed = false;
        self.ipv6_sets.retain(|_, set| {
            if now < set.deadline {
                return true;
            }
            metrics::record_tun_ip_reassembly("ipv6", "timeout");
            ipv6_changed = true;
            false
        });
        if ipv4_changed {
            maybe_shrink_hash_map(&mut self.ipv4_sets);
            self.set_active_fragment_sets_metric(IpVersion::V4);
        }
        if ipv6_changed {
            maybe_shrink_hash_map(&mut self.ipv6_sets);
            self.set_active_fragment_sets_metric(IpVersion::V6);
        }
        if ipv4_changed || ipv6_changed {
            self.recalculate_total_buffered_bytes();
        }
    }

    fn fragment_set_count(&self) -> usize {
        self.ipv4_sets.len() + self.ipv6_sets.len()
    }

    fn set_active_fragment_sets_metric(&self, version: IpVersion) {
        let count = match version {
            IpVersion::V4 => self.ipv4_sets.len(),
            IpVersion::V6 => self.ipv6_sets.len(),
        };
        metrics::set_tun_ip_fragment_sets_active(ip_family_name(version), count);
    }

    fn remove_ipv4_set(&mut self, key: Ipv4Key) {
        self.ipv4_sets.remove(&key);
        maybe_shrink_hash_map(&mut self.ipv4_sets);
        self.recalculate_total_buffered_bytes();
        self.set_active_fragment_sets_metric(IpVersion::V4);
    }

    fn remove_ipv6_set(&mut self, key: Ipv6Key) {
        self.ipv6_sets.remove(&key);
        maybe_shrink_hash_map(&mut self.ipv6_sets);
        self.recalculate_total_buffered_bytes();
        self.set_active_fragment_sets_metric(IpVersion::V6);
    }

    fn recalculate_total_buffered_bytes(&mut self) {
        self.total_buffered_bytes = self
            .ipv4_sets
            .values()
            .map(Ipv4FragmentSet::estimated_bytes)
            .sum::<usize>()
            + self
                .ipv6_sets
                .values()
                .map(Ipv6FragmentSet::estimated_bytes)
                .sum::<usize>();
    }
}

impl Ipv4FragmentSet {
    fn estimated_bytes(&self) -> usize {
        self.header.as_ref().map_or(0, Vec::len)
            + self.chunks.iter().map(FragmentChunk::len).sum::<usize>()
    }

    fn is_complete(&self) -> bool {
        self.header.is_some()
            && self
                .total_payload_len
                .is_some_and(|total| chunks_are_complete(&self.chunks, total))
    }

    fn build_packet(self) -> Result<Vec<u8>> {
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

        let checksum = crate::tun_wire::checksum16(&packet[..header.len()]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(packet)
    }
}

impl Ipv6FragmentSet {
    fn estimated_bytes(&self) -> usize {
        self.prefix.len() + self.chunks.iter().map(FragmentChunk::len).sum::<usize>()
    }

    fn is_complete(&self) -> bool {
        self.total_payload_len
            .is_some_and(|total| chunks_are_complete(&self.chunks, total))
    }

    fn build_packet(self) -> Result<Vec<u8>> {
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

impl FragmentChunk {
    fn end(&self) -> usize {
        self.offset + self.data.len()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

fn inspect_packet(packet: &[u8]) -> Result<PacketInspection<'_>> {
    let version = packet.first().copied().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => inspect_ipv4(packet),
        6 => inspect_ipv6(packet),
        _ => Ok(PacketInspection::Passthrough),
    }
}

fn inspect_ipv4(packet: &[u8]) -> Result<PacketInspection<'_>> {
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

fn inspect_ipv6(packet: &[u8]) -> Result<PacketInspection<'_>> {
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

fn insert_chunk(chunks: &mut Vec<FragmentChunk>, offset: usize, data: &[u8]) -> ChunkInsertOutcome {
    let Some(end) = offset.checked_add(data.len()) else {
        return ChunkInsertOutcome::Overlap;
    };

    let mut index = 0usize;
    while index < chunks.len() {
        let existing = &chunks[index];
        if end <= existing.offset {
            break;
        }
        if offset >= existing.end() {
            index += 1;
            continue;
        }
        if offset == existing.offset && end == existing.end() && data == existing.data.as_slice() {
            return ChunkInsertOutcome::DuplicateExact;
        }
        return ChunkInsertOutcome::Overlap;
    }

    chunks.insert(index, FragmentChunk { offset, data: data.to_vec() });
    ChunkInsertOutcome::Inserted(data.len())
}

fn chunks_are_complete(chunks: &[FragmentChunk], total_len: usize) -> bool {
    let mut cursor = 0usize;
    for chunk in chunks {
        if chunk.offset != cursor {
            return false;
        }
        cursor += chunk.data.len();
    }
    cursor == total_len
}

fn ip_family_name(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

fn ipv6_prefix_matches(stored: &[u8], incoming: &[u8]) -> bool {
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
