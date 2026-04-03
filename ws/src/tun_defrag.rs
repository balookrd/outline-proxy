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
            }
            PacketInspection::Ipv6Fragment(fragment) => {
                metrics::record_tun_ip_fragment_received("ipv6");
                self.handle_ipv6_fragment(now, fragment)
            }
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
            let set = self
                .ipv4_sets
                .entry(fragment.key)
                .or_insert_with(|| Ipv4FragmentSet {
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
                }
                ChunkInsertOutcome::DuplicateExact => {
                    set.deadline = now + REASSEMBLY_TIMEOUT;
                    return Ok(DefragmentedPacket::Pending);
                }
                ChunkInsertOutcome::Overlap => {
                    should_remove = Some("overlap");
                }
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
                        }
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
                    }
                    ChunkInsertOutcome::DuplicateExact => {
                        set.deadline = now + REASSEMBLY_TIMEOUT;
                        return Ok(DefragmentedPacket::Pending);
                    }
                    ChunkInsertOutcome::Overlap => {
                        should_remove = Some("overlap");
                    }
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
                        }
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
    let version = packet
        .first()
        .copied()
        .ok_or_else(|| anyhow!("empty TUN packet"))?
        >> 4;
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
    if more_fragments && (payload.len() % 8 != 0) {
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

    let fragment_offset_and_flags = u16::from_be_bytes([
        packet[info.payload_offset + 2],
        packet[info.payload_offset + 3],
    ]);
    let offset = usize::from(fragment_offset_and_flags >> 3)
        .checked_mul(8)
        .ok_or_else(|| anyhow!("IPv6 fragment offset overflow"))?;
    let more_fragments = (fragment_offset_and_flags & 0x1) != 0;
    let payload = &packet[info.payload_offset + 8..info.total_len];
    if more_fragments && (payload.len() % 8 != 0) {
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

    chunks.insert(
        index,
        FragmentChunk {
            offset,
            data: data.to_vec(),
        },
    );
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

#[cfg(test)]
mod tests {
    use super::{DefragmentedPacket, TunDefragmenter};
    use crate::tun::build_icmp_echo_reply;
    use crate::tun_tcp::parse_tcp_packet_for_tests as parse_tcp_packet;
    use crate::tun_udp::{build_ipv4_udp_packet, parse_udp_packet};
    use crate::tun_wire::{
        IPV6_HEADER_LEN, IPV6_NEXT_HEADER_DESTINATION_OPTIONS, IPV6_NEXT_HEADER_FRAGMENT,
        IPV6_NEXT_HEADER_ICMPV6, IPV6_NEXT_HEADER_UDP, checksum16, ipv6_payload_checksum,
        locate_ipv6_payload, locate_ipv6_upper_layer,
    };
    use crate::tun_wire_test_utils::{assert_transport_checksum_valid, transport_offset};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn passes_through_non_fragmented_ipv4_packets() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello",
        )
        .unwrap();
        let mut defrag = TunDefragmenter::default();
        match defrag.push(&packet).unwrap() {
            DefragmentedPacket::ReadyBorrowed => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn reassembles_ipv4_udp_fragments() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello fragmented udp",
        )
        .unwrap();
        let fragments = fragment_ipv4_packet(
            &packet,
            &[16, packet.len() - transport_offset(&packet) - 16],
        );
        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[1]).unwrap(),
            DefragmentedPacket::Pending
        ));
        let reassembled = match defrag.push(&fragments[0]).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(reassembled, packet);
        let parsed = parse_udp_packet(&reassembled).unwrap();
        assert_eq!(parsed.payload, b"hello fragmented udp");
    }

    #[test]
    fn drops_overlapping_ipv4_fragments() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello fragmented udp",
        )
        .unwrap();
        let fragments = fragment_ipv4_packet(
            &packet,
            &[16, packet.len() - transport_offset(&packet) - 16],
        );
        let mut overlapping = fragments[1].clone();
        let offset_units = 1u16.to_be_bytes();
        overlapping[6] = offset_units[0];
        overlapping[7] = offset_units[1];

        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[0]).unwrap(),
            DefragmentedPacket::Pending
        ));
        assert!(matches!(
            defrag.push(&overlapping).unwrap(),
            DefragmentedPacket::Dropped(_)
        ));
    }

    #[test]
    fn reassembles_ipv6_udp_fragments_with_extension_headers() {
        let packet = build_ipv6_udp_packet_with_destination_options(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            5353,
            41000,
            b"hello over ipv6 fragments",
        );
        let fragments = fragment_ipv6_packet(&packet, 16);
        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[1]).unwrap(),
            DefragmentedPacket::Pending
        ));
        let reassembled = match defrag.push(&fragments[0]).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };
        let parsed = parse_udp_packet(&reassembled).unwrap();
        assert_eq!(parsed.payload, b"hello over ipv6 fragments");
        let (next_header, _, _) = locate_ipv6_upper_layer(&reassembled).unwrap();
        assert_eq!(next_header, IPV6_NEXT_HEADER_UDP);
        assert_transport_checksum_valid(&reassembled, IPV6_NEXT_HEADER_UDP);
    }

    #[test]
    fn reassembles_ipv6_atomic_fragment_for_icmpv6() {
        let packet = build_ipv6_icmp_echo_request_with_fragment_header(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            0x1234,
            0x0007,
            b"ping",
            false,
        );
        let mut defrag = TunDefragmenter::default();
        let reassembled = match defrag.push(&packet).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };
        let reply = build_icmp_echo_reply(&reassembled).unwrap();
        assert_eq!(reply[transport_offset(&reply)], 129);
    }

    #[test]
    fn reassembles_ipv6_icmp_fragments_and_builds_local_reply() {
        let packet = build_ipv6_icmp_echo_request(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            0x3701,
            0x0044,
            &[0x5a; 1452],
        );
        let fragments = fragment_ipv6_packet(&packet, 1368);

        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].len(), IPV6_HEADER_LEN + 8 + 1368);
        assert_eq!(fragments[1].len(), IPV6_HEADER_LEN + 8 + 92);

        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[0]).unwrap(),
            DefragmentedPacket::Pending
        ));
        let reassembled = match defrag.push(&fragments[1]).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };

        let reply = build_icmp_echo_reply(&reassembled).unwrap();
        let (_, payload_offset, total_len) = locate_ipv6_upper_layer(&reply).unwrap();

        assert_eq!(reply[payload_offset], 129);
        assert_eq!(
            reply[payload_offset + 4..payload_offset + 8],
            [0x37, 0x01, 0x00, 0x44]
        );
        assert_eq!(total_len, IPV6_HEADER_LEN + 1460);
        assert_transport_checksum_valid(&reply, IPV6_NEXT_HEADER_ICMPV6);
    }

    #[test]
    fn maintenance_sweeps_expired_fragment_sets_without_new_fragments() {
        let packet = build_ipv6_icmp_echo_request(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            0x3701,
            0x0044,
            &[0x5a; 1452],
        );
        let fragments = fragment_ipv6_packet(&packet, 1368);

        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[0]).unwrap(),
            DefragmentedPacket::Pending
        ));
        assert_eq!(defrag.ipv6_sets.len(), 1);
        assert!(defrag.total_buffered_bytes > 0);

        let key = *defrag.ipv6_sets.keys().next().expect("fragment set");
        defrag
            .ipv6_sets
            .get_mut(&key)
            .expect("fragment set")
            .deadline = Instant::now() - Duration::from_secs(1);
        defrag.next_cleanup_at = Instant::now() - Duration::from_secs(1);

        defrag.run_maintenance();

        assert!(defrag.ipv6_sets.is_empty());
        assert_eq!(defrag.total_buffered_bytes, 0);
    }

    #[test]
    fn reassembles_ipv6_tcp_fragments() {
        let packet = build_ipv6_tcp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            40000,
            443,
            b"hello",
        );
        let fragments = fragment_ipv6_packet(&packet, 24);
        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[0]).unwrap(),
            DefragmentedPacket::Pending
        ));
        let reassembled = match defrag.push(&fragments[1]).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };
        let _ = parse_tcp_packet(&reassembled).unwrap();
        let tcp_offset = transport_offset(&reassembled);
        assert_eq!(&reassembled[tcp_offset + 20..], b"hello");
    }

    fn fragment_ipv4_packet(packet: &[u8], payload_sizes: &[usize]) -> Vec<Vec<u8>> {
        let header_len = transport_offset(packet);
        let payload = &packet[header_len..];
        let identification = [packet[4], packet[5]];
        let protocol = packet[9];
        let mut fragments = Vec::new();
        let mut cursor = 0usize;
        for (index, &size) in payload_sizes.iter().enumerate() {
            let end = cursor + size;
            let more = end < payload.len();
            let total_len = header_len + size;
            let mut fragment = vec![0u8; total_len];
            fragment[..header_len].copy_from_slice(&packet[..header_len]);
            fragment[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            fragment[4..6].copy_from_slice(&identification);
            let mut fragment_field = ((cursor / 8) as u16) & 0x1fff;
            if more {
                fragment_field |= 0x2000;
            }
            fragment[6..8].copy_from_slice(&fragment_field.to_be_bytes());
            fragment[10..12].copy_from_slice(&0u16.to_be_bytes());
            fragment[header_len..].copy_from_slice(&payload[cursor..end]);
            let checksum = checksum16(&fragment[..header_len]);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(fragment[9], protocol);
            fragments.push(fragment);
            cursor = end;
            let _ = index;
        }
        fragments
    }

    fn fragment_ipv6_packet(packet: &[u8], first_payload_len: usize) -> Vec<Vec<u8>> {
        let info = locate_ipv6_payload(packet).unwrap();
        let transport_offset = info.payload_offset;
        let previous_next_header_offset = info.next_header_field_offset;
        let upper_layer_header = info.next_header;
        let unfragmentable = &packet[..transport_offset];
        let fragmentable = &packet[transport_offset..];
        let first_len = first_payload_len.min(fragmentable.len());
        let split = first_len - (first_len % 8);
        let second_offset = split;
        let first_payload = &fragmentable[..split];
        let second_payload = &fragmentable[split..];
        let identification = 0x0102_0304u32;

        let mut fragments = Vec::new();
        for (offset, payload, more) in [
            (0usize, first_payload, !second_payload.is_empty()),
            (second_offset, second_payload, false),
        ] {
            if payload.is_empty() {
                continue;
            }
            let total_len = unfragmentable.len() + 8 + payload.len();
            let mut fragment = vec![0u8; total_len];
            fragment[..unfragmentable.len()].copy_from_slice(unfragmentable);
            fragment[4..6].copy_from_slice(&((total_len - IPV6_HEADER_LEN) as u16).to_be_bytes());
            fragment[previous_next_header_offset] = IPV6_NEXT_HEADER_FRAGMENT;
            fragment[transport_offset] = upper_layer_header;
            fragment[transport_offset + 1] = 0;
            let fragment_offset_field = (((offset / 8) as u16) << 3) | u16::from(more);
            fragment[transport_offset + 2..transport_offset + 4]
                .copy_from_slice(&fragment_offset_field.to_be_bytes());
            fragment[transport_offset + 4..transport_offset + 8]
                .copy_from_slice(&identification.to_be_bytes());
            fragment[transport_offset + 8..].copy_from_slice(payload);
            fragments.push(fragment);
        }
        fragments
    }

    fn build_ipv6_udp_packet_with_destination_options(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let extension_len = 8usize;
        let total_len = IPV6_HEADER_LEN + extension_len + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
        packet[6] = IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40] = IPV6_NEXT_HEADER_UDP;
        packet[48..50].copy_from_slice(&source_port.to_be_bytes());
        packet[50..52].copy_from_slice(&destination_port.to_be_bytes());
        packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[56..].copy_from_slice(payload);
        let checksum = ipv6_payload_checksum(
            source_ip,
            destination_ip,
            IPV6_NEXT_HEADER_UDP,
            &packet[48..],
        );
        packet[54..56].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_icmp_echo_request_with_fragment_header(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        more_fragments: bool,
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total_len = IPV6_HEADER_LEN + 8 + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + icmp_len) as u16).to_be_bytes());
        packet[6] = IPV6_NEXT_HEADER_FRAGMENT;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40] = IPV6_NEXT_HEADER_ICMPV6;
        packet[42..44].copy_from_slice(&(u16::from(more_fragments)).to_be_bytes());
        packet[44..48].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        packet[48] = 128;
        packet[52..54].copy_from_slice(&identifier.to_be_bytes());
        packet[54..56].copy_from_slice(&sequence.to_be_bytes());
        packet[56..].copy_from_slice(payload);
        let checksum = ipv6_payload_checksum(
            source_ip,
            destination_ip,
            IPV6_NEXT_HEADER_ICMPV6,
            &packet[48..],
        );
        packet[50..52].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_icmp_echo_request(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total_len = IPV6_HEADER_LEN + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        packet[6] = IPV6_NEXT_HEADER_ICMPV6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40] = 128;
        packet[44..46].copy_from_slice(&identifier.to_be_bytes());
        packet[46..48].copy_from_slice(&sequence.to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let checksum = ipv6_payload_checksum(
            source_ip,
            destination_ip,
            IPV6_NEXT_HEADER_ICMPV6,
            &packet[40..],
        );
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_tcp_packet(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let total_len = IPV6_HEADER_LEN + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x18;
        packet[54..56].copy_from_slice(&4096u16.to_be_bytes());
        packet[60..].copy_from_slice(payload);
        let checksum = ipv6_payload_checksum(source_ip, destination_ip, 6, &packet[40..]);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }
}
