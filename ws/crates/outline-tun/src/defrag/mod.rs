use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::utils::maybe_shrink_hash_map;
use outline_metrics as metrics;
use crate::wire::IpVersion;

use self::chunk::{ChunkInsertOutcome, insert_chunk};
use self::v4::{Ipv4Fragment, Ipv4FragmentSet, Ipv4Key, inspect_ipv4};
use self::v6::{Ipv6Fragment, Ipv6FragmentSet, Ipv6Key, inspect_ipv6, ipv6_prefix_matches};

mod chunk;
mod v4;
mod v6;

#[cfg(test)]
mod tests;

const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FRAGMENT_SETS: usize = 1024;
const MAX_FRAGMENTS_PER_SET: usize = 64;
const MAX_BYTES_PER_SET: usize = 128 * 1024;
const MAX_TOTAL_BUFFERED_BYTES: usize = 16 * 1024 * 1024;

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

enum PacketInspection<'a> {
    Passthrough,
    Ipv4Fragment(Ipv4Fragment<'a>),
    Ipv6Fragment(Ipv6Fragment<'a>),
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
                    .ok_or_else(|| anyhow::anyhow!("IPv4 fragment end offset overflow"))?;
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
                    .ok_or_else(|| anyhow::anyhow!("IPv6 fragment end offset overflow"))?;
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

fn inspect_packet(packet: &[u8]) -> Result<PacketInspection<'_>> {
    let version = packet.first().copied().ok_or_else(|| anyhow::anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => inspect_ipv4(packet),
        6 => inspect_ipv6(packet),
        _ => Ok(PacketInspection::Passthrough),
    }
}

fn ip_family_name(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}
