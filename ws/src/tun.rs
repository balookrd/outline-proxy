use std::fs::OpenOptions;
use std::net::Ipv6Addr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rand::random;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::TunConfig;
use crate::metrics;
use crate::tun_defrag::{DefragmentedPacket, TunDefragmenter};
use crate::tun_tcp::TunTcpEngine;
use crate::tun_udp::{TunUdpEngine, classify_tun_udp_forward_error, parse_udp_packet};
use crate::tun_wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, IPV6_NEXT_HEADER_ICMPV6,
    IPV6_NEXT_HEADER_NONE, IPV6_NEXT_HEADER_TCP, IPV6_NEXT_HEADER_UDP, checksum16,
    ipv6_payload_checksum, locate_ipv6_payload, locate_ipv6_upper_layer,
};
use crate::uplink::UplinkManager;

const IPV6_MIN_PATH_MTU: usize = 1280;
const EBUSY_OS_ERROR: i32 = 16;
const TUN_OPEN_BUSY_RETRIES: usize = 20;
const TUN_OPEN_BUSY_RETRY_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub(crate) struct SharedTunWriter {
    inner: Arc<Mutex<File>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDisposition {
    Udp,
    Tcp,
    IcmpEchoRequest,
    Unsupported(&'static str),
}

pub async fn spawn_tun_loop(config: TunConfig, uplinks: UplinkManager) -> Result<()> {
    let tun_path = config.path.clone();
    let tun_name = config.name.clone();
    let tun_mtu = config.mtu;
    let tun_path_for_task = tun_path.clone();
    let device = open_tun_device_with_retry(&config)
        .await
        .with_context(|| format!("failed to open TUN device {}", config.path.display()))?;
    let reader = File::from_std(
        device
            .try_clone()
            .context("failed to clone TUN file descriptor")?,
    );
    let writer = SharedTunWriter {
        inner: Arc::new(Mutex::new(File::from_std(device))),
    };

    let idle_timeout = config.idle_timeout;
    let max_flows = config.max_flows;
    let udp_engine = TunUdpEngine::new(writer.clone(), uplinks.clone(), max_flows, idle_timeout);
    let tcp_engine = TunTcpEngine::new(
        writer.clone(),
        uplinks.clone(),
        max_flows,
        idle_timeout,
        config.tcp.clone(),
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(reader, writer, udp_engine, tcp_engine, tun_mtu).await {
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

async fn tun_read_loop(
    mut reader: File,
    writer: SharedTunWriter,
    udp_engine: TunUdpEngine,
    tcp_engine: TunTcpEngine,
    mtu: usize,
) -> Result<()> {
    let mut buf = vec![0u8; mtu + 256];
    let defragmenter = Arc::new(Mutex::new(TunDefragmenter::default()));
    spawn_tun_defragmenter_cleanup(Arc::downgrade(&defragmenter));
    loop {
        let read = reader
            .read(&mut buf)
            .await
            .context("failed to read TUN packet")?;
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
                }
                Ok(DefragmentedPacket::Pending) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "fragment_buffered",
                    );
                    continue;
                }
                Ok(DefragmentedPacket::Dropped(reason)) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "fragment_drop",
                    );
                    debug!(reason, packet_len = read, "dropping fragmented TUN packet");
                    continue;
                }
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
                }
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
            }
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
                    }
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
            }
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
            }
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
                }
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
                }
            },
            PacketDisposition::Unsupported(reason) => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "unsupported",
                );
                debug!(reason, packet_len = read, "ignoring unsupported TUN packet");
            }
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
    pub(crate) fn new(file: File) -> Self {
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }

    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let mut writer = self.inner.lock().await;
        writer
            .write_all(packet)
            .await
            .context("failed to write packet to TUN")?;
        writer.flush().await.context("failed to flush TUN packet")?;
        Ok(())
    }

    pub(crate) async fn write_packets(&self, packets: &[Vec<u8>]) -> Result<()> {
        let mut writer = self.inner.lock().await;
        for packet in packets {
            writer
                .write_all(packet)
                .await
                .context("failed to write packet to TUN")?;
        }
        writer.flush().await.context("failed to flush TUN packet")?;
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
        return Ok(PacketDisposition::Unsupported(
            "IPv4 fragments are not supported on TUN",
        ));
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
        }
        IPV6_NEXT_HEADER_NONE => {
            PacketDisposition::Unsupported("IPv6 no-next-header packets are not supported on TUN")
        }
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
        let chunk_len = if is_last {
            remaining
        } else {
            non_terminal_chunk_budget
        };
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
            }
            Err(error) if is_tun_device_busy_error(&error) => {
                bail!(
                    "TUN interface {} remained busy after {} retries; another process may still own it: {error:#}",
                    config.name.as_deref().unwrap_or("n/a"),
                    TUN_OPEN_BUSY_RETRIES
                );
            }
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

    let mut ifreq = IfReq {
        name: [0; libc::IFNAMSIZ],
        data: [0; 24],
    };
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

#[cfg(test)]
mod tests {
    use super::{
        EBUSY_OS_ERROR, IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_MIN_PATH_MTU,
        IPV6_NEXT_HEADER_FRAGMENT, PacketDisposition, build_icmp_echo_reply,
        build_icmp_echo_reply_packets, checksum16, classify_packet, icmpv6_checksum,
        is_tun_device_busy_error,
    };
    use crate::tun_defrag::{DefragmentedPacket, TunDefragmenter};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn tcp_packets_are_classified_for_tun_tcp_path() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
    }

    #[test]
    fn ipv6_tcp_packets_with_destination_options_are_classified_for_tun_tcp_path() {
        let packet = build_ipv6_tcp_packet_with_extension_header(60, 6);
        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
    }

    #[test]
    fn ipv6_udp_packets_with_destination_options_are_classified_for_tun_udp_path() {
        let packet = build_ipv6_udp_packet_with_extension_header();
        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
    }

    #[test]
    fn ipv6_fragmented_packets_are_reported_as_unsupported() {
        let packet = build_ipv6_tcp_packet_with_extension_header(44, 6);
        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::Unsupported("IPv6 fragments are not supported on TUN")
        );
    }

    #[test]
    fn ipv4_icmp_echo_request_gets_local_reply() {
        let packet = build_ipv4_icmp_echo_request(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            0x1234,
            0x0007,
            b"ping",
        );

        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::IcmpEchoRequest
        );
        let reply = build_icmp_echo_reply(&packet).unwrap();

        assert_eq!(reply[9], 1);
        assert_eq!(reply[12..16], [8, 8, 8, 8]);
        assert_eq!(reply[16..20], [10, 0, 0, 2]);
        assert_eq!(reply[IPV4_HEADER_LEN], 0);
        assert_eq!(
            reply[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 8],
            [0x12, 0x34, 0x00, 0x07]
        );
        assert_eq!(&reply[IPV4_HEADER_LEN + 8..], b"ping");
        assert_eq!(
            checksum16(
                &reply[IPV4_HEADER_LEN..usize::from(u16::from_be_bytes([reply[2], reply[3]]))]
            ),
            0
        );
    }

    #[test]
    fn ipv6_icmp_echo_request_gets_local_reply() {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let packet = build_ipv6_icmp_echo_request(source, destination, 0xabcd, 0x0002, b"pong");

        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::IcmpEchoRequest
        );
        let reply = build_icmp_echo_reply(&packet).unwrap();

        assert_eq!(reply[6], 58);
        assert_eq!(reply[8..24], destination.octets());
        assert_eq!(reply[24..40], source.octets());
        assert_eq!(reply[IPV6_HEADER_LEN], 129);
        assert_eq!(
            reply[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 8],
            [0xab, 0xcd, 0x00, 0x02]
        );
        assert_eq!(&reply[IPV6_HEADER_LEN + 8..], b"pong");
        let checksum = icmpv6_checksum(destination, source, &reply[IPV6_HEADER_LEN..]);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn ipv6_icmp_echo_request_with_destination_options_gets_local_reply() {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let packet = build_ipv6_icmp_echo_request_with_extension_header(
            source,
            destination,
            0xabcd,
            0x0002,
            b"pong",
        );

        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::IcmpEchoRequest
        );
        let reply = build_icmp_echo_reply(&packet).unwrap();
        let (_, payload_offset, total_len) =
            crate::tun_wire::locate_ipv6_upper_layer(&reply).unwrap();

        assert_eq!(reply[8..24], destination.octets());
        assert_eq!(reply[24..40], source.octets());
        assert_eq!(reply[payload_offset], 129);
        assert_eq!(
            reply[payload_offset + 4..payload_offset + 8],
            [0xab, 0xcd, 0x00, 0x02]
        );
        assert_eq!(&reply[payload_offset + 8..total_len], b"pong");
        let checksum = icmpv6_checksum(destination, source, &reply[payload_offset..total_len]);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn large_ipv6_icmp_echo_replies_are_fragmented_to_minimum_mtu() {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let payload = vec![0x5a; 1452];
        let packet = build_ipv6_icmp_echo_request(source, destination, 0xabcd, 0x0002, &payload);

        let fragments = build_icmp_echo_reply_packets(&packet).unwrap();
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].len(), IPV6_MIN_PATH_MTU);
        assert!(
            fragments
                .iter()
                .all(|fragment| fragment.len() <= IPV6_MIN_PATH_MTU)
        );
        assert_eq!(fragments[0][6], IPV6_NEXT_HEADER_FRAGMENT);

        let mut defrag = TunDefragmenter::default();
        assert!(matches!(
            defrag.push(&fragments[0]).unwrap(),
            DefragmentedPacket::Pending
        ));
        let reassembled = match defrag.push(&fragments[1]).unwrap() {
            DefragmentedPacket::ReadyOwned(packet) => packet,
            other => panic!("unexpected result: {other:?}"),
        };
        let (_, payload_offset, total_len) =
            crate::tun_wire::locate_ipv6_upper_layer(&reassembled).unwrap();
        assert_eq!(reassembled[8..24], destination.octets());
        assert_eq!(reassembled[24..40], source.octets());
        assert_eq!(reassembled[payload_offset], 129);
        assert_eq!(
            reassembled[payload_offset + 4..payload_offset + 8],
            [0xab, 0xcd, 0x00, 0x02]
        );
        assert_eq!(
            &reassembled[payload_offset + 8..total_len],
            payload.as_slice()
        );
        let checksum =
            icmpv6_checksum(destination, source, &reassembled[payload_offset..total_len]);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn detects_busy_tun_attach_errors_from_context_chain() {
        let error = anyhow::Error::from(std::io::Error::from_raw_os_error(EBUSY_OS_ERROR))
            .context("TUNSETIFF failed");
        assert!(is_tun_device_busy_error(&error));
    }

    fn build_ipv4_icmp_echo_request(
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total_len = IPV4_HEADER_LEN + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        let icmp_offset = IPV4_HEADER_LEN;
        packet[icmp_offset] = 8;
        packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
        packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[icmp_offset + 8..].copy_from_slice(payload);
        let icmp_checksum = checksum16(&packet[icmp_offset..]);
        packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
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
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        let icmp_offset = IPV6_HEADER_LEN;
        packet[icmp_offset] = 128;
        packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
        packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[icmp_offset + 8..].copy_from_slice(payload);
        let checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..]);
        packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_tcp_packet_with_extension_header(
        next_header: u8,
        terminal_header: u8,
    ) -> Vec<u8> {
        let extension_len = 8usize;
        let tcp_len = 20usize;
        let total_len = IPV6_HEADER_LEN + extension_len + tcp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + tcp_len) as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        packet[IPV6_HEADER_LEN] = terminal_header;
        if next_header == 44 {
            packet[IPV6_HEADER_LEN + 1] = 0;
        } else {
            packet[IPV6_HEADER_LEN + 1] = 0;
        }
        packet[IPV6_HEADER_LEN + extension_len + 12] = 0x50;
        packet[IPV6_HEADER_LEN + extension_len + 13] = 0x10;
        packet
    }

    fn build_ipv6_udp_packet_with_extension_header() -> Vec<u8> {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let udp_len = 8usize;
        let extension_len = 8usize;
        let total_len = IPV6_HEADER_LEN + extension_len + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
        packet[6] = 60;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 17;
        packet[48..50].copy_from_slice(&53u16.to_be_bytes());
        packet[50..52].copy_from_slice(&40000u16.to_be_bytes());
        packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
        let checksum =
            crate::tun_wire::ipv6_payload_checksum(source, destination, 17, &packet[48..]);
        packet[54..56].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_icmp_echo_request_with_extension_header(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let extension_len = 8usize;
        let total_len = IPV6_HEADER_LEN + extension_len + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + icmp_len) as u16).to_be_bytes());
        packet[6] = 60;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40] = 58;
        let icmp_offset = IPV6_HEADER_LEN + extension_len;
        packet[icmp_offset] = 128;
        packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
        packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[icmp_offset + 8..].copy_from_slice(payload);
        let checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..]);
        packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }
}
