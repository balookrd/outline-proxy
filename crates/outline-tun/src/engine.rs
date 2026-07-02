//! TUN read loop and engine lifecycle.
//!
//! Owns the top-level `spawn_tun_loop` entry point: opens the device, wires
//! up the UDP/TCP engines and the IPv6 defragmenter, then runs the read
//! loop that classifies each packet and dispatches it to the right engine
//! (or synthesises a local ICMP reply).

use std::sync::{Arc, Weak};

use anyhow::{Context, Result, bail};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use outline_metrics as metrics;

use crate::classify::{PacketDisposition, classify_packet};
use crate::config::TunConfig;
use crate::defrag::{DefragmentedPacket, TunDefragmenter};
use crate::device::{open_tun_device_with_retry, set_nonblocking};
use crate::icmp::{build_icmp_echo_reply_packets, icmp_echo_destination};
use crate::routing::{TunRoute, TunRouting};
use crate::tcp::TunTcpEngine;
use crate::udp::{
    TunUdpEngine, classify_tun_udp_forward_error, parse_udp_packet, resegment_udp_gso,
};
use crate::vnet::{
    VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP_L4, VIRTIO_NET_HDR_LEN, VirtioNetHdr,
};
use crate::wire::ip_to_target;
use crate::writer::SharedTunWriter;

#[cfg(test)]
#[path = "tests/engine.rs"]
mod tests;

/// Opens the TUN device and spawns the read loop plus the engine-wide
/// cleanup / maintenance tasks, returning once they are running.
///
/// Lifecycle (deliberate, not an oversight): these tasks are
/// **process-lifetime**. No handle is returned and there is no cooperative
/// shutdown, because the TUN device and its config are fixed at startup —
/// the control-plane `/control/apply` path hot-swaps only uplink groups, and
/// changing `[tun]` (like `listen` / `routing` / `metrics`) requires a full
/// process restart (see `outline-ws-rust` `http::control::apply`). The engine
/// is therefore created exactly once per process and the OS tears the fd and
/// tasks down on exit. The per-engine cleanup/maintenance loops in
/// `tcp::engine` and `udp` intentionally share this lifetime (unlike the
/// defragmenter cleanup, which is `Weak`-scoped to the read loop).
///
/// If TUN is ever made hot-reloadable (recreating the engine while the
/// process keeps running), this MUST grow an explicit teardown: return a
/// shutdown handle and cancel the read loop + cleanup/maintenance tasks
/// before respawning. Otherwise two read loops race on the same TUN fd and
/// the previous engine's tasks leak (they hold a strong `engine` clone).
pub async fn spawn_tun_loop(
    config: TunConfig,
    routing: TunRouting,
    dns_cache: Arc<outline_transport::DnsCache>,
) -> Result<()> {
    let tun_path = config.path.clone();
    let tun_name = config.name.clone();
    let tun_mtu = config.mtu;
    let tun_path_for_task = tun_path.clone();
    let (device, gso_enabled) = open_tun_device_with_retry(&config)
        .await
        .with_context(|| format!("failed to open TUN device {}", config.path.display()))?;
    set_nonblocking(&device).context("failed to set O_NONBLOCK on TUN device")?;
    let async_fd = Arc::new(
        AsyncFd::with_interest(device, Interest::READABLE | Interest::WRITABLE)
            .context("failed to register TUN fd with tokio reactor")?,
    );
    // `gso_enabled` (fd opened with IFF_VNET_HDR) governs the read/write vnet
    // framing and lets the TCP engine emit downlink TSO super-segments.
    let writer = SharedTunWriter::from_async_fd(async_fd.clone(), gso_enabled);

    let idle_timeout = config.idle_timeout;
    let max_flows = config.max_flows;
    let defrag_max_fragment_sets = config.defrag_max_fragment_sets;
    let defrag_max_fragments_per_set = config.defrag_max_fragments_per_set;
    let defrag_max_total_bytes = config.defrag_max_total_bytes;
    let defrag_max_bytes_per_set = config.defrag_max_bytes_per_set;
    let udp_engine = TunUdpEngine::new(
        writer.clone(),
        routing.clone(),
        max_flows,
        idle_timeout,
        config.pmtud_emit_below_quic_initial,
        config.sniff_quic,
        config.sniff_override_exclude.clone(),
    );
    let tcp_engine = TunTcpEngine::new(
        writer.clone(),
        routing.clone(),
        max_flows,
        idle_timeout,
        gso_enabled,
        config.tcp.clone(),
        dns_cache,
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(
            async_fd,
            writer,
            udp_engine,
            tcp_engine,
            routing,
            tun_mtu,
            gso_enabled,
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
    reader: Arc<AsyncFd<std::fs::File>>,
    writer: SharedTunWriter,
    udp_engine: TunUdpEngine,
    tcp_engine: TunTcpEngine,
    routing: TunRouting,
    mtu: usize,
    gso_enabled: bool,
    defrag_max_total_bytes: usize,
    defrag_max_bytes_per_set: usize,
    defrag_max_fragment_sets: usize,
    defrag_max_fragments_per_set: usize,
) -> Result<()> {
    use std::io::Read as _;

    // Sized to hold a full GRO super-packet (up to 64 KB) plus the
    // virtio_net_hdr prefix and headroom: with RX offload the kernel can
    // coalesce several inbound MSS segments / datagrams into one >MSS read, and
    // a smaller buffer would truncate it. Without offload this is one larger
    // one-off allocation for the single read buffer — negligible.
    let mut buf = vec![0u8; mtu.max(65_535) + 256 + VIRTIO_NET_HDR_LEN];
    let defragmenter = Arc::new(Mutex::new(TunDefragmenter::new(
        defrag_max_total_bytes,
        defrag_max_bytes_per_set,
        defrag_max_fragment_sets,
        defrag_max_fragments_per_set,
    )));
    spawn_tun_defragmenter_cleanup(Arc::downgrade(&defragmenter));
    loop {
        let read = reader
            .async_io(Interest::READABLE, |f| {
                let mut r: &std::fs::File = f;
                r.read(&mut buf)
            })
            .await
            .context("failed to read TUN packet")?;
        if read == 0 {
            bail!("TUN device returned EOF");
        }
        // Strip the virtio_net_hdr prefix when IFF_VNET_HDR is enabled and
        // dispatch by gso_type. With RX offload (`TUNSETOFFLOAD`) the kernel may
        // hand us TCP GRO super-packets (TCPV4/6) or UDP GRO super-packets
        // (UDP_L4); without it, only GSO_NONE single packets (possibly with an
        // un-finalised L4 checksum). The gso_type match MUST precede any
        // recompute: `recompute_transport_checksum` sizes off the 16-bit IP
        // total_len, so a UDP aggregate takes a separate re-segmentation path
        // and never reaches recompute here.
        let input_packet = if gso_enabled {
            if read <= VIRTIO_NET_HDR_LEN {
                debug!(read, "dropping short TUN read (no packet after vnet header)");
                continue;
            }
            let header = VirtioNetHdr::decode(&buf[..VIRTIO_NET_HDR_LEN])
                .expect("read > VIRTIO_NET_HDR_LEN guarantees a full header");
            match header.gso_type {
                VIRTIO_NET_HDR_GSO_UDP_L4 => {
                    // UDP GRO: split the aggregate back into its datagrams and
                    // dispatch each in order — behaviourally identical to the
                    // per-packet path (the kernel merely batched the read).
                    dispatch_udp_gso_superpacket(
                        &udp_engine,
                        &buf[VIRTIO_NET_HDR_LEN..read],
                        header.gso_size,
                    )
                    .await;
                    continue;
                },
                VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6 => {
                    // TCP GRO super-packet — the userspace TCP receive path
                    // accepts an oversized segment whole (it sizes from IP
                    // total_len, buffers as `Bytes`, and trims to the window).
                    // Count it (the uplink GRO signal — how often the kernel
                    // actually coalesced inbound TCP), recompute the checksum the
                    // kernel may have left un-finalised, then hand the packet to
                    // the normal classify / dispatch path below.
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(buf[VIRTIO_NET_HDR_LEN] >> 4),
                        "tcp_gro_superpacket",
                    );
                    if header.flags != 0 {
                        crate::wire::recompute_transport_checksum(
                            &mut buf[VIRTIO_NET_HDR_LEN..read],
                        );
                    }
                    &buf[VIRTIO_NET_HDR_LEN..read]
                },
                VIRTIO_NET_HDR_GSO_NONE => {
                    // A single packet, possibly with an un-finalised L4 checksum
                    // (F_NEEDS_CSUM / F_DATA_VALID from a CHECKSUM_PARTIAL local
                    // / forwarded hop). Recompute, then hand it to the normal
                    // classify / dispatch path below.
                    if header.flags != 0 {
                        crate::wire::recompute_transport_checksum(
                            &mut buf[VIRTIO_NET_HDR_LEN..read],
                        );
                    }
                    &buf[VIRTIO_NET_HDR_LEN..read]
                },
                other => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        "unknown",
                        "vnet_gso_unsupported",
                    );
                    debug!(gso_type = other, "dropping unsupported GSO super-packet on TUN read");
                    continue;
                },
            }
        } else {
            &buf[..read]
        };
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
            PacketDisposition::IcmpEchoRequest => {
                if echo_reply_suppressed_for_down_group(&routing, packet).await {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "icmp_reply_suppressed",
                    );
                    continue;
                }
                match build_icmp_echo_reply_packets(packet) {
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
                }
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

/// Split a UDP GRO super-packet into its datagrams and forward each to the UDP
/// engine, in order. Behaviourally identical to the per-packet path — the
/// kernel merely coalesced several same-flow datagrams into one read. A
/// malformed aggregate is dropped whole (never partially delivered).
async fn dispatch_udp_gso_superpacket(udp_engine: &TunUdpEngine, packet: &[u8], gso_size: u16) {
    let version_nibble = packet.first().map_or(0, |b| b >> 4);
    let datagrams = match resegment_udp_gso(packet, gso_size) {
        Ok(datagrams) => datagrams,
        Err(error) => {
            metrics::record_tun_packet(
                "tun_to_upstream",
                ip_family_name(version_nibble),
                "udp_gso_resegment_error",
            );
            debug!(
                error = %format!("{error:#}"),
                gso_size,
                "dropping malformed UDP GSO super-packet"
            );
            return;
        },
    };
    // Counts UDP GRO super-packets the kernel actually delivered — the signal
    // for whether `TUN_F_CSUM|TSO` (without USO) still yields UDP aggregates on
    // this kernel, or UDP truly stays per-datagram (to confirm on the live host).
    metrics::record_tun_packet(
        "tun_to_upstream",
        ip_family_name(version_nibble),
        "udp_gso_superpacket",
    );
    debug!(count = datagrams.len(), gso_size, "re-segmented UDP GRO super-packet");
    for parsed in datagrams {
        metrics::record_tun_packet("tun_to_upstream", ip_family_name(version_nibble), "accepted");
        if let Err(error) = udp_engine.handle_packet(parsed).await {
            metrics::record_tun_udp_forward_error(classify_tun_udp_forward_error(&error));
            metrics::record_tun_packet(
                "tun_to_upstream",
                ip_family_name(version_nibble),
                "udp_error",
            );
            warn!(
                error = %format!("{error:#}"),
                "failed to forward UDP datagram from GSO super-packet"
            );
        }
    }
}

/// Group-health gate for the local ICMP echo reply.
///
/// Returns `true` when the echo request's destination routes to a group
/// that opted into `tun_suppress_icmp_reply_when_down` and that group
/// currently has no healthy uplink on either transport — the same
/// `has_any_healthy` signal the route-fallback decision uses. Direct/drop
/// routes and unparseable destinations never suppress; the reply builder
/// remains the sole validator for malformed packets.
async fn echo_reply_suppressed_for_down_group(routing: &TunRouting, packet: &[u8]) -> bool {
    let Some(destination) = icmp_echo_destination(packet) else {
        return false;
    };
    // Port 0: policy routing matches on CIDR prefixes only.
    let target = ip_to_target(destination, 0);
    let TunRoute::Group { name, manager } = routing.resolve(&target).await else {
        return false;
    };
    if !manager.load_balancing().tun_suppress_icmp_reply_when_down {
        return false;
    }
    if manager.has_any_healthy(outline_uplink::TransportKind::Tcp).await
        || manager.has_any_healthy(outline_uplink::TransportKind::Udp).await
    {
        return false;
    }
    debug!(
        group = %name,
        destination = %destination,
        "suppressing local ICMP echo reply: no healthy uplink in group"
    );
    true
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

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
}
