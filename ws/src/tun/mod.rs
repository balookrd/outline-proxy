use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::Ipv6Addr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rand::random;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::TunConfig;
use crate::metrics;
use crate::tun::defrag::{DefragmentedPacket, TunDefragmenter};
use crate::tun::tcp::TunTcpEngine;
use crate::tun::udp::{TunUdpEngine, classify_tun_udp_forward_error, parse_udp_packet};
use crate::tun::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, IPV6_NEXT_HEADER_ICMPV6,
    IPV6_NEXT_HEADER_NONE, IPV6_NEXT_HEADER_TCP, IPV6_NEXT_HEADER_UDP, checksum16,
    ipv6_payload_checksum, locate_ipv6_payload, locate_ipv6_upper_layer,
};
use crate::config::RouteTarget;
use crate::routing::RoutingTable;
use crate::types::TargetAddr;
use crate::uplink::{UplinkManager, UplinkRegistry};

const IPV6_MIN_PATH_MTU: usize = 1280;
const EBUSY_OS_ERROR: i32 = 16;
const TUN_OPEN_BUSY_RETRIES: usize = 20;
const TUN_OPEN_BUSY_RETRY_DELAY: Duration = Duration::from_millis(250);

pub mod defrag;
pub mod tcp;
pub mod udp;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

/// A cheaply-cloneable handle for writing IP packets to a TUN device.
///
/// Internally uses a `parking_lot::Mutex<std::fs::File>` (not tokio's async
/// mutex) for two reasons:
///
/// 1. **No internal write buffer**: `std::fs::File::write_all` issues a single
///    `write(2)` syscall directly, which is what TUN requires — each `write(2)`
///    delivers exactly one IP packet to the kernel.  `tokio::fs::File` has an
///    internal write buffer and needs an explicit `flush()` after each
///    `write_all`, doubling the async I/O per packet.
///
/// 2. **Short critical section**: a `write(2)` to a TUN device is a kernel
///    memcpy into a ring buffer — typically ≤ 10 µs.  Holding a sync mutex
///    for that duration is safe and avoids the overhead of a tokio async-mutex
///    queue (which is significant when hundreds of concurrent flows compete).
#[derive(Clone)]
pub(crate) struct SharedTunWriter {
    inner: Arc<parking_lot::Mutex<std::fs::File>>,
}

/// Per-flow dispatch context for the TUN path.
///
/// Resolves destination targets through the policy routing table to pick a
/// group's [`UplinkManager`]. `direct` and `drop` rules on the TUN side both
/// result in the packet being dropped — TUN cannot synthesise a "host's own
/// networking stack" path without fwmark/SO_BINDTODEVICE plumbing, which is
/// OS-specific and out of scope for this module. Users that want part of
/// their traffic to go outside the tunnel should exclude those prefixes
/// from the TUN routing table on the host.
#[derive(Clone)]
pub struct TunRouting {
    registry: UplinkRegistry,
    routing: Option<Arc<RoutingTable>>,
    default_group: UplinkManager,
    direct_fwmark: Option<u32>,
}

/// Resolved routing decision for a new TUN flow.
#[derive(Clone)]
pub enum TunRoute {
    /// Forward this flow through the named group's uplink manager.
    Group {
        name: String,
        manager: UplinkManager,
    },
    /// Forward via a local socket (with optional SO_MARK to escape the TUN
    /// routing loop). The TUN engine opens a plain TCP/UDP connection to the
    /// destination, relays data bidirectionally, and synthesises IP response
    /// packets back into the TUN device — same behaviour as the SOCKS5
    /// `via = "direct"` path.
    Direct { fwmark: Option<u32> },
    /// Drop the flow silently (matches `via = "drop"`).
    Drop { reason: &'static str },
}

impl TunRouting {
    pub fn new(
        registry: UplinkRegistry,
        routing: Option<Arc<RoutingTable>>,
        direct_fwmark: Option<u32>,
    ) -> Self {
        let default_group = registry.default_group().clone();
        Self { registry, routing, default_group, direct_fwmark }
    }

    /// Test-only helper: wrap a single [`UplinkManager`] as the sole group,
    /// with no routing table. Used by TUN engine tests that pre-build an
    /// `UplinkManager` directly.
    #[cfg(test)]
    pub fn from_single_manager(manager: UplinkManager) -> Self {
        Self {
            registry: UplinkRegistry::from_single_manager(manager.clone()),
            routing: None,
            default_group: manager,
            direct_fwmark: None,
        }
    }

    pub fn default_group(&self) -> &UplinkManager {
        &self.default_group
    }

    /// Resolve a TUN flow's destination to a group manager.
    pub async fn resolve(&self, target: &TargetAddr) -> TunRoute {
        let Some(table) = self.routing.as_ref() else {
            return TunRoute::Group {
                name: self.registry.default_group_name().to_string(),
                manager: self.default_group.clone(),
            };
        };
        let decision = table.resolve(target).await;
        self.materialize_target(decision.primary, decision.fallback).await
    }

    async fn materialize_target(
        &self,
        primary: RouteTarget,
        fallback: Option<RouteTarget>,
    ) -> TunRoute {
        match primary {
            RouteTarget::Direct => {
                TunRoute::Direct { fwmark: self.direct_fwmark }
            },
            RouteTarget::Drop => TunRoute::Drop { reason: "policy_drop" },
            RouteTarget::Group(name) => {
                let Some(manager) = self.registry.group_by_name(&name) else {
                    // Config validation rejects unknown groups in `via`, but
                    // defensively honour the declared fallback before dropping
                    // — dropping silently would be a worse failure mode than
                    // using the escape hatch the user wrote.
                    warn!(group = %name, "TUN route references unknown group");
                    if let Some(fb) = fallback {
                        return Box::pin(self.materialize_target(fb, None)).await;
                    }
                    return TunRoute::Drop { reason: "unknown_group" };
                };
                // Fallback applies only when the primary group has no
                // healthy uplinks at resolve time; Direct/Drop primaries are
                // terminal decisions.
                if fallback.is_some()
                    && !manager
                        .has_any_healthy(crate::uplink::TransportKind::Udp)
                        .await
                    && !manager
                        .has_any_healthy(crate::uplink::TransportKind::Tcp)
                        .await
                    && let Some(fb) = fallback {
                        // Recurse once — fallback doesn't chain further.
                        return Box::pin(self.materialize_target(fb, None)).await;
                    }
                TunRoute::Group { name, manager: manager.clone() }
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDisposition {
    Udp,
    Tcp,
    IcmpEchoRequest,
    Unsupported(&'static str),
}

pub async fn spawn_tun_loop(config: TunConfig, routing: TunRouting) -> Result<()> {
    let tun_path = config.path.clone();
    let tun_name = config.name.clone();
    let tun_mtu = config.mtu;
    let tun_path_for_task = tun_path.clone();
    let device = open_tun_device_with_retry(&config)
        .await
        .with_context(|| format!("failed to open TUN device {}", config.path.display()))?;
    // The reader uses tokio::fs::File for non-blocking async reads.
    // The writer keeps the raw std::fs::File — see SharedTunWriter for rationale.
    let reader = File::from_std(device.try_clone().context("failed to clone TUN file descriptor")?);
    let writer = SharedTunWriter {
        inner: Arc::new(parking_lot::Mutex::new(device)),
    };

    let idle_timeout = config.idle_timeout;
    let max_flows = config.max_flows;
    let defrag_max_fragment_sets = config.defrag_max_fragment_sets;
    let defrag_max_fragments_per_set = config.defrag_max_fragments_per_set;
    let defrag_max_total_bytes = config.defrag_max_total_bytes;
    let defrag_max_bytes_per_set = config.defrag_max_bytes_per_set;
    let udp_engine = TunUdpEngine::new(writer.clone(), routing.clone(), max_flows, idle_timeout);
    let tcp_engine = TunTcpEngine::new(
        writer.clone(),
        routing.clone(),
        max_flows,
        idle_timeout,
        config.tcp.clone(),
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(
            reader,
            writer,
            udp_engine,
            tcp_engine,
            tun_mtu,
            defrag_max_total_bytes,
            defrag_max_bytes_per_set,
            defrag_max_fragment_sets,
            defrag_max_fragments_per_set,
        )
        .await
        {
            warn!(path = %tun_path_for_task.display(), error = %format!("{error:#}"), "TUN loop stopped");
        }
    });

    info!(
        path = %tun_path.display(),
        name = tun_name.as_deref().unwrap_or("n/a"),
        mtu = tun_mtu,
        max_flows,
        idle_timeout_secs = idle_timeout.as_secs(),
        "TUN loop started"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn tun_read_loop(
    mut reader: File,
    writer: SharedTunWriter,
    udp_engine: TunUdpEngine,
    tcp_engine: TunTcpEngine,
    mtu: usize,
    defrag_max_total_bytes: usize,
    defrag_max_bytes_per_set: usize,
    defrag_max_fragment_sets: usize,
    defrag_max_fragments_per_set: usize,
) -> Result<()> {
    let mut buf = vec![0u8; mtu + 256];
    let defragmenter = Arc::new(Mutex::new(TunDefragmenter::new(
        defrag_max_total_bytes,
        defrag_max_bytes_per_set,
        defrag_max_fragment_sets,
        defrag_max_fragments_per_set,
    )));
    spawn_tun_defragmenter_cleanup(Arc::downgrade(&defragmenter));
    loop {
        let read = reader.read(&mut buf).await.context("failed to read TUN packet")?;
        if read == 0 {
            bail!("TUN device returned EOF");
        }
        let input_packet = &buf[..read];
        let version_nibble = input_packet[0] >> 4;
        let owned_packet = {
            let mut defragmenter = defragmenter.lock().await;
            match defragmenter.push(input_packet) {
                Ok(DefragmentedPacket::ReadyBorrowed) => None,
                Ok(DefragmentedPacket::ReadyOwned(packet)) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "fragment_reassembled",
                    );
                    Some(packet)
                },
                Ok(DefragmentedPacket::Pending) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "fragment_buffered",
                    );
                    continue;
                },
                Ok(DefragmentedPacket::Dropped(reason)) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "fragment_drop",
                    );
                    debug!(reason, packet_len = read, "dropping fragmented TUN packet");
                    continue;
                },
                Err(error) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "error",
                    );
                    debug!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "dropping malformed fragmented TUN packet"
                    );
                    continue;
                },
            }
        };
        let packet_storage;
        let packet = if let Some(packet) = owned_packet {
            packet_storage = packet;
            packet_storage.as_slice()
        } else {
            input_packet
        };
        let version_nibble = packet[0] >> 4;
        let disposition = match classify_packet(packet) {
            Ok(disposition) => disposition,
            Err(error) => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "error",
                );
                debug!(error = %format!("{error:#}"), packet_len = read, "dropping malformed TUN packet");
                continue;
            },
        };
        match disposition {
            PacketDisposition::Udp => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "accepted",
                );
                let parsed = match parse_udp_packet(packet) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        metrics::record_tun_packet(
                            "tun_to_upstream",
                            ip_family_name(version_nibble),
                            "error",
                        );
                        debug!(error = %format!("{error:#}"), packet_len = read, "dropping malformed UDP packet from TUN");
                        continue;
                    },
                };
                if let Err(error) = udp_engine.handle_packet(parsed).await {
                    metrics::record_tun_udp_forward_error(classify_tun_udp_forward_error(&error));
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "udp_error",
                    );
                    warn!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "failed to forward UDP packet from TUN"
                    );
                    continue;
                }
            },
            PacketDisposition::Tcp => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "tcp_observed",
                );
                if let Err(error) = tcp_engine.handle_packet(packet).await {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "tcp_error",
                    );
                    warn!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "failed to handle TCP packet from TUN"
                    );
                }
            },
            PacketDisposition::IcmpEchoRequest => match build_icmp_echo_reply_packets(packet) {
                Ok(replies) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "icmp_local_reply",
                    );
                    if replies.len() > 1 {
                        debug!(
                            reply_packet_len = replies.iter().map(Vec::len).sum::<usize>(),
                            fragment_count = replies.len(),
                            "fragmented local IPv6 ICMP echo reply to minimum MTU"
                        );
                    }
                    if let Err(error) = writer.write_packets(&replies).await {
                        metrics::record_tun_packet(
                            "upstream_to_tun",
                            ip_family_name(version_nibble),
                            "error",
                        );
                        warn!(
                            error = %format!("{error:#}"),
                            packet_len = read,
                            "failed to write local ICMP echo reply to TUN"
                        );
                    } else {
                        metrics::record_tun_icmp_local_reply(ip_family_name(version_nibble));
                        metrics::record_tun_packet(
                            "upstream_to_tun",
                            ip_family_name(version_nibble),
                            "icmp_local_reply",
                        );
                    }
                },
                Err(error) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "error",
                    );
                    debug!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "dropping malformed ICMP packet from TUN"
                    );
                },
            },
            PacketDisposition::Unsupported(reason) => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "unsupported",
                );
                debug!(reason, packet_len = read, "ignoring unsupported TUN packet");
            },
        }
    }
}

fn spawn_tun_defragmenter_cleanup(defragmenter: Weak<Mutex<TunDefragmenter>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TunDefragmenter::cleanup_interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(defragmenter) = defragmenter.upgrade() else {
                break;
            };
            defragmenter.lock().await.run_maintenance();
        }
    });
}

impl SharedTunWriter {
    #[cfg(test)]
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self { inner: Arc::new(parking_lot::Mutex::new(file)) }
    }

    /// Write one IP packet to the TUN device.
    ///
    /// Uses a synchronous `write_all(2)` call through a `parking_lot::Mutex`.
    /// The critical section is bounded by a single kernel memcpy (≤ 10 µs for
    /// typical MTU-sized packets), so holding a sync mutex is safe here and
    /// avoids the overhead of an async-mutex queue under concurrent callers.
    ///
    /// The function signature is `async` for compatibility with the many call
    /// sites that use `.await`, but it never actually suspends.
    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.inner
            .lock()
            .write_all(packet)
            .context("failed to write packet to TUN")
    }

    /// Write a batch of IP packets to the TUN device, one `write(2)` per packet.
    ///
    /// Each call to `write_all` issues a separate `write(2)` syscall, which is
    /// required by TUN: the kernel delivers one IP packet per `write(2)`.
    /// The mutex is acquired once and held for the entire batch to avoid the
    /// overhead of repeated lock/unlock cycles.
    pub(crate) async fn write_packets(&self, packets: &[Vec<u8>]) -> Result<()> {
        let mut writer = self.inner.lock();
        for packet in packets {
            writer.write_all(packet).context("failed to write packet to TUN")?;
        }
        Ok(())
    }
}

fn classify_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => classify_ipv4_packet(packet),
        6 => classify_ipv6_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn classify_ipv4_packet(packet: &[u8]) -> Result<PacketDisposition> {
    if packet.len() < IPV4_HEADER_LEN {
        bail!("short IPv4 packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN || packet.len() < header_len {
        bail!("invalid IPv4 header length");
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        return Ok(PacketDisposition::Unsupported("IPv4 fragments are not supported on TUN"));
    }
    Ok(match packet[9] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        1 => classify_ipv4_icmp_packet(packet, header_len)?,
        _ => PacketDisposition::Unsupported("unsupported IPv4 protocol on TUN"),
    })
}

fn classify_ipv6_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let (next_header, payload_offset, _) = locate_ipv6_upper_layer(packet)?;
    Ok(match next_header {
        IPV6_NEXT_HEADER_UDP => PacketDisposition::Udp,
        IPV6_NEXT_HEADER_TCP => PacketDisposition::Tcp,
        IPV6_NEXT_HEADER_ICMPV6 => classify_ipv6_icmp_packet(packet, payload_offset)?,
        IPV6_NEXT_HEADER_FRAGMENT => {
            PacketDisposition::Unsupported("IPv6 fragments are not supported on TUN")
        },
        IPV6_NEXT_HEADER_NONE => {
            PacketDisposition::Unsupported("IPv6 no-next-header packets are not supported on TUN")
        },
        _ => PacketDisposition::Unsupported(
            "unsupported IPv6 payload protocol or extension header path on TUN",
        ),
    })
}

fn classify_ipv4_icmp_packet(packet: &[u8], header_len: usize) -> Result<PacketDisposition> {
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        bail!("truncated IPv4 ICMP packet");
    }
    Ok(match packet[header_len] {
        8 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMP is not supported on TUN"),
    })
}

fn classify_ipv6_icmp_packet(packet: &[u8], payload_offset: usize) -> Result<PacketDisposition> {
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if total_len < payload_offset + 8 || packet.len() < total_len {
        bail!("truncated IPv6 ICMP packet");
    }
    Ok(match packet[payload_offset] {
        128 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMPv6 is not supported on TUN"),
    })
}

pub(crate) fn build_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => build_ipv4_icmp_echo_reply(packet),
        6 => build_ipv6_icmp_echo_reply(packet),
        other => bail!("unsupported IP version in ICMP packet: {other}"),
    }
}

fn build_icmp_echo_reply_packets(packet: &[u8]) -> Result<Vec<Vec<u8>>> {
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

fn fragment_ipv6_packet(packet: Vec<u8>, mtu: usize) -> Result<Vec<Vec<u8>>> {
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

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp_packet: &[u8]) -> u16 {
    ipv6_payload_checksum(source, destination, IPV6_NEXT_HEADER_ICMPV6, icmp_packet)
}

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
}

async fn open_tun_device_with_retry(config: &TunConfig) -> Result<std::fs::File> {
    for attempt in 0..=TUN_OPEN_BUSY_RETRIES {
        match open_tun_device(config) {
            Ok(file) => return Ok(file),
            Err(error) if is_tun_device_busy_error(&error) && attempt < TUN_OPEN_BUSY_RETRIES => {
                warn!(
                    name = config.name.as_deref().unwrap_or("n/a"),
                    path = %config.path.display(),
                    attempt = attempt + 1,
                    retry_in_ms = TUN_OPEN_BUSY_RETRY_DELAY.as_millis(),
                    "TUN interface is busy, retrying attach"
                );
                tokio::time::sleep(TUN_OPEN_BUSY_RETRY_DELAY).await;
            },
            Err(error) if is_tun_device_busy_error(&error) => {
                bail!(
                    "TUN interface {} remained busy after {} retries; another process may still own it: {error:#}",
                    config.name.as_deref().unwrap_or("n/a"),
                    TUN_OPEN_BUSY_RETRIES
                );
            },
            Err(error) => return Err(error),
        }
    }
    unreachable!("retry loop always returns");
}

fn is_tun_device_busy_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|io_error| io_error.raw_os_error() == Some(EBUSY_OS_ERROR))
}

#[cfg(target_os = "linux")]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    let name = config
        .name
        .as_ref()
        .ok_or_else(|| anyhow!("missing tun.name for Linux TUN attach"))?;
    if name.len() >= libc::IFNAMSIZ {
        bail!("tun.name is too long for Linux ifreq: {}", name);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))?;

    let mut ifreq = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
    for (index, byte) in name.as_bytes().iter().enumerate() {
        ifreq.name[index] = *byte as libc::c_char;
    }
    unsafe {
        std::ptr::write_unaligned(
            ifreq.data.as_mut_ptr() as *mut libc::c_short,
            IFF_TUN | IFF_NO_PI,
        );
    }

    let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &ifreq) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF failed");
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))
}
