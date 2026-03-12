use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::config::TunConfig;
use crate::metrics;
use crate::transport::UdpWsTransport;
use crate::tun_tcp::TunTcpEngine;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    version: IpVersion,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone)]
struct UdpFlowState {
    id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    uplink_name: String,
    created_at: Instant,
    last_seen: Instant,
}

#[derive(Clone)]
pub(crate) struct SharedTunWriter {
    inner: Arc<Mutex<File>>,
}

#[derive(Debug, Clone)]
struct ParsedUdpPacket {
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDisposition {
    Udp,
    Tcp,
    Unsupported(&'static str),
}

type FlowTable = Arc<Mutex<HashMap<UdpFlowKey, UdpFlowState>>>;

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

    let flows = Arc::new(Mutex::new(HashMap::new()));
    let flow_ids = Arc::new(AtomicU64::new(1));
    let idle_timeout = config.idle_timeout;
    let max_flows = config.max_flows;
    let tcp_engine = TunTcpEngine::new(
        writer.clone(),
        uplinks.clone(),
        max_flows,
        idle_timeout,
        config.tcp.clone(),
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    spawn_flow_cleanup_loop(Arc::clone(&flows), idle_timeout);

    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(
            reader, writer, tcp_engine, uplinks, flows, flow_ids, tun_mtu, max_flows,
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

async fn tun_read_loop(
    mut reader: File,
    writer: SharedTunWriter,
    tcp_engine: TunTcpEngine,
    uplinks: UplinkManager,
    flows: FlowTable,
    flow_ids: Arc<AtomicU64>,
    mtu: usize,
    max_flows: usize,
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
                forward_udp_packet(parsed, &writer, &uplinks, &flows, &flow_ids, max_flows).await?;
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
                    debug!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "dropping malformed TCP packet from TUN"
                    );
                }
            }
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

async fn forward_udp_packet(
    packet: ParsedUdpPacket,
    writer: &SharedTunWriter,
    uplinks: &UplinkManager,
    flows: &FlowTable,
    flow_ids: &Arc<AtomicU64>,
    max_flows: usize,
) -> Result<()> {
    let remote_target = ip_to_target(packet.destination_ip, packet.destination_port);
    let key = UdpFlowKey {
        version: packet.version,
        local_ip: packet.source_ip,
        local_port: packet.source_port,
        remote_ip: packet.destination_ip,
        remote_port: packet.destination_port,
    };

    let existing = {
        let mut guard = flows.lock().await;
        guard.get_mut(&key).map(|flow| {
            flow.last_seen = Instant::now();
            (
                flow.id,
                Arc::clone(&flow.transport),
                flow.uplink_index,
                flow.uplink_name.clone(),
            )
        })
    };

    let (flow_id, transport, uplink_index, uplink_name) = match existing {
        Some(existing) => existing,
        None => {
            create_udp_flow(
                key.clone(),
                writer.clone(),
                uplinks,
                flows,
                flow_ids,
                max_flows,
            )
            .await?
        }
    };

    let payload = build_udp_payload(&remote_target, &packet.payload)?;
    metrics::add_udp_datagram("client_to_upstream");
    metrics::add_bytes("udp", "client_to_upstream", payload.len());

    if let Err(error) = transport.send_packet(&payload).await {
        uplinks
            .report_runtime_failure(uplink_index, TransportKind::Udp, &error)
            .await;
        close_flow_if_current(flows, &key, flow_id, "send_error").await;
        let (replacement_flow_id, replacement_transport, replacement_index, replacement_name) =
            create_udp_flow(
                key.clone(),
                writer.clone(),
                uplinks,
                flows,
                flow_ids,
                max_flows,
            )
            .await?;
        metrics::record_failover("udp", &uplink_name, &replacement_name);
        replacement_transport.send_packet(&payload).await?;
        debug!(
            flow_id = replacement_flow_id,
            uplink = %replacement_name,
            "recreated TUN UDP flow after send failure"
        );
        let _ = replacement_index;
    }

    Ok(())
}

async fn create_udp_flow(
    key: UdpFlowKey,
    writer: SharedTunWriter,
    uplinks: &UplinkManager,
    flows: &FlowTable,
    flow_ids: &Arc<AtomicU64>,
    max_flows: usize,
) -> Result<(u64, Arc<UdpWsTransport>, usize, String)> {
    let (candidate, transport) =
        select_udp_candidate_and_connect(uplinks, &ip_to_target(key.remote_ip, key.remote_port))
            .await?;
    let transport = Arc::new(transport);
    let now = Instant::now();
    let flow_id = flow_ids.fetch_add(1, Ordering::Relaxed);
    let state = UdpFlowState {
        id: flow_id,
        transport: Arc::clone(&transport),
        uplink_index: candidate.index,
        uplink_name: candidate.uplink.name.clone(),
        created_at: now,
        last_seen: now,
    };

    {
        let mut guard = flows.lock().await;
        if let Some(existing) = guard.get_mut(&key) {
            existing.last_seen = now;
            return Ok((
                existing.id,
                Arc::clone(&existing.transport),
                existing.uplink_index,
                existing.uplink_name.clone(),
            ));
        }
        if guard.len() >= max_flows {
            if let Some(evicted_key) = oldest_flow_key(&guard) {
                if let Some(evicted) = guard.remove(&evicted_key) {
                    metrics::record_tun_flow_closed(
                        &evicted.uplink_name,
                        "evicted",
                        now.saturating_duration_since(evicted.created_at),
                    );
                    warn!(
                        evicted_flow_id = evicted.id,
                        evicted_uplink = %evicted.uplink_name,
                        max_flows,
                        "evicted oldest TUN UDP flow due to flow table limit"
                    );
                }
            } else {
                bail!("TUN flow table limit reached and no flow could be evicted");
            }
        }
        guard.insert(key.clone(), state);
    }

    metrics::record_uplink_selected("udp", &candidate.uplink.name);
    metrics::record_tun_flow_created(&candidate.uplink.name);
    debug!(
        flow_id,
        uplink = %candidate.uplink.name,
        local = %format!("{}:{}", key.local_ip, key.local_port),
        remote = %format!("{}:{}", key.remote_ip, key.remote_port),
        "created TUN UDP flow"
    );
    spawn_udp_flow_reader(
        key,
        flow_id,
        Arc::clone(&transport),
        candidate.index,
        writer,
        uplinks.clone(),
        Arc::clone(flows),
    );

    Ok((
        flow_id,
        transport,
        candidate.index,
        candidate.uplink.name.clone(),
    ))
}

async fn select_udp_candidate_and_connect(
    uplinks: &UplinkManager,
    remote_target: &TargetAddr,
) -> Result<(UplinkCandidate, UdpWsTransport)> {
    let mut last_error = None;
    for candidate in uplinks.udp_candidates(Some(remote_target)).await {
        match uplinks.acquire_udp_standby_or_connect(&candidate).await {
            Ok(transport) => {
                return Ok((candidate, transport));
            }
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            }
        }
    }
    Err(anyhow!(
        "all UDP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

fn spawn_udp_flow_reader(
    key: UdpFlowKey,
    flow_id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: FlowTable,
) {
    tokio::spawn(async move {
        let result = async {
            loop {
                let payload = transport.read_packet().await?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                let packet = build_response_packet(
                    key.version,
                    &target,
                    key.local_ip,
                    key.local_port,
                    &payload[consumed..],
                )?;
                metrics::add_udp_datagram("upstream_to_client");
                metrics::add_bytes("udp", "upstream_to_client", payload.len());
                writer.write_packet(&packet).await?;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(key.version),
                    "accepted",
                );
                let mut guard = flows.lock().await;
                if let Some(flow) = guard.get_mut(&key) {
                    if flow.id == flow_id {
                        flow.last_seen = Instant::now();
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let close_reason = if result.is_ok() {
            "closed"
        } else {
            "read_error"
        };

        if let Err(ref error) = result {
            uplinks
                .report_runtime_failure(uplink_index, TransportKind::Udp, &error)
                .await;
            metrics::record_tun_packet(
                "upstream_to_tun",
                ip_family_from_version(key.version),
                "error",
            );
            warn!(
                flow_id,
                error = %format!("{error:#}"),
                "TUN UDP flow reader stopped"
            );
        }
        close_flow_if_current(&flows, &key, flow_id, close_reason).await;
    });
}

fn spawn_flow_cleanup_loop(flows: FlowTable, idle_timeout: Duration) {
    tokio::spawn(async move {
        loop {
            sleep(TUN_FLOW_CLEANUP_INTERVAL).await;
            cleanup_idle_flows(&flows, idle_timeout).await;
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
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn build_response_packet(
    version: IpVersion,
    target: &TargetAddr,
    local_ip: IpAddr,
    local_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (version, target, local_ip) {
        (IpVersion::V4, TargetAddr::IpV4(remote_ip, remote_port), IpAddr::V4(local_ip)) => {
            build_ipv4_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        }
        (IpVersion::V6, TargetAddr::IpV6(remote_ip, remote_port), IpAddr::V6(local_ip)) => {
            build_ipv6_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        }
        _ => bail!("unexpected response address family for TUN UDP flow"),
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
        _ => PacketDisposition::Unsupported("non-UDP IP protocol is not supported on TUN"),
    })
}

fn classify_ipv6_packet(packet: &[u8]) -> Result<PacketDisposition> {
    if packet.len() < IPV6_HEADER_LEN {
        bail!("short IPv6 packet");
    }
    Ok(match packet[6] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        _ => PacketDisposition::Unsupported(
            "IPv6 extension headers or non-UDP payloads are not supported on TUN",
        ),
    })
}

fn parse_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv4 UDP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + UDP_HEADER_LEN {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 packet");
    }
    if packet[9] != 17 {
        bail!("expected IPv4 UDP packet");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V4,
        source_ip: IpAddr::V4(src),
        destination_ip: IpAddr::V4(dst),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv6 UDP packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() < total_len {
        bail!("truncated IPv6 packet");
    }
    if packet[6] != 17 {
        bail!("expected IPv6 UDP packet");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let udp = &packet[IPV6_HEADER_LEN..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated IPv6 UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V6,
        source_ip: IpAddr::V6(Ipv6Addr::from(src)),
        destination_ip: IpAddr::V6(Ipv6Addr::from(dst)),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

fn build_ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV4_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = udp_checksum_ipv4(
        source_ip,
        destination_ip,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_udp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV6_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = udp_checksum_ipv6(
        source_ip,
        destination_ip,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
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

fn udp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    checksum16(&pseudo)
}

fn udp_checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(udp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(udp_segment);
    checksum16(&pseudo)
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
}

fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

fn oldest_flow_key(flows: &HashMap<UdpFlowKey, UdpFlowState>) -> Option<UdpFlowKey> {
    flows
        .iter()
        .min_by_key(|(_, flow)| flow.last_seen)
        .map(|(key, _)| key.clone())
}

async fn close_flow_if_current(
    flows: &FlowTable,
    key: &UdpFlowKey,
    flow_id: u64,
    reason: &'static str,
) {
    let mut guard = flows.lock().await;
    if guard.get(key).map(|flow| flow.id) == Some(flow_id) {
        if let Some(flow) = guard.remove(key) {
            metrics::record_tun_flow_closed(
                &flow.uplink_name,
                reason,
                Instant::now().saturating_duration_since(flow.created_at),
            );
        }
    }
}

async fn cleanup_idle_flows(flows: &FlowTable, idle_timeout: Duration) {
    let now = Instant::now();
    let mut guard = flows.lock().await;
    let expired: Vec<UdpFlowKey> = guard
        .iter()
        .filter_map(|(key, flow)| {
            (now.saturating_duration_since(flow.last_seen) >= idle_timeout).then(|| key.clone())
        })
        .collect();
    for key in expired {
        if let Some(flow) = guard.remove(&key) {
            metrics::record_tun_flow_closed(
                &flow.uplink_name,
                "idle_timeout",
                now.saturating_duration_since(flow.created_at),
            );
        }
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
        IpVersion, PacketDisposition, build_ipv4_udp_packet, build_ipv6_udp_packet,
        classify_packet, parse_udp_packet,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_udp_roundtrip() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello",
        )
        .unwrap();

        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V4);
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 40000);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let packet = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            5353,
            41000,
            b"world",
        )
        .unwrap();

        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V6);
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 5353);
        assert_eq!(parsed.destination_port, 41000);
        assert_eq!(parsed.payload, b"world");
    }

    #[test]
    fn tcp_packets_are_classified_for_tun_tcp_path() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
    }
}
