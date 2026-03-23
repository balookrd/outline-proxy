use std::fs::OpenOptions;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::TunConfig;
use crate::metrics;
use crate::tun_tcp::TunTcpEngine;
use crate::tun_udp::{TunUdpEngine, classify_tun_udp_forward_error, parse_udp_packet};
use crate::uplink::UplinkManager;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

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
    let device = open_tun_device(&config)
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
    loop {
        let read = reader
            .read(&mut buf)
            .await
            .context("failed to read TUN packet")?;
        if read == 0 {
            bail!("TUN device returned EOF");
        }
        let packet = &buf[..read];
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
            PacketDisposition::IcmpEchoRequest => match build_icmp_echo_reply(packet) {
                Ok(reply) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "icmp_local_reply",
                    );
                    if let Err(error) = writer.write_packet(&reply).await {
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
    if packet.len() < IPV6_HEADER_LEN {
        bail!("short IPv6 packet");
    }
    Ok(match packet[6] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        58 => classify_ipv6_icmp_packet(packet)?,
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

fn classify_ipv6_icmp_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if payload_len < 8 || packet.len() < total_len {
        bail!("truncated IPv6 ICMP packet");
    }
    Ok(match packet[IPV6_HEADER_LEN] {
        128 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMPv6 is not supported on TUN"),
    })
}

fn build_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => build_ipv4_icmp_echo_reply(packet),
        6 => build_ipv6_icmp_echo_reply(packet),
        other => bail!("unsupported IP version in ICMP packet: {other}"),
    }
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
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if payload_len < 8 || packet.len() < total_len {
        bail!("invalid IPv6 ICMP packet lengths");
    }
    if packet[6] != 58 {
        bail!("expected IPv6 ICMP packet");
    }
    if packet[IPV6_HEADER_LEN] != 128 {
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
    reply[IPV6_HEADER_LEN] = 129;
    reply[IPV6_HEADER_LEN + 2] = 0;
    reply[IPV6_HEADER_LEN + 3] = 0;
    let icmp_checksum = icmpv6_checksum(
        Ipv6Addr::from(destination),
        Ipv6Addr::from(source),
        &reply[IPV6_HEADER_LEN..total_len],
    );
    reply[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(reply)
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            u16::from_be_bytes([chunk[0], 0]) as u32
        };
        sum = sum.wrapping_add(value);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp_packet.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(icmp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp_packet);
    checksum16(&pseudo)
}

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
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
        IPV4_HEADER_LEN, IPV6_HEADER_LEN, PacketDisposition, build_icmp_echo_reply, checksum16,
        classify_packet, icmpv6_checksum,
    };
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
}
