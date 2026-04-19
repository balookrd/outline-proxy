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
use crate::icmp::build_icmp_echo_reply_packets;
use crate::routing::TunRouting;
use crate::tcp::TunTcpEngine;
use crate::udp::{TunUdpEngine, classify_tun_udp_forward_error, parse_udp_packet};
use crate::writer::SharedTunWriter;

pub async fn spawn_tun_loop(
    config: TunConfig,
    routing: TunRouting,
    dns_cache: Arc<outline_transport::DnsCache>,
) -> Result<()> {
    let tun_path = config.path.clone();
    let tun_name = config.name.clone();
    let tun_mtu = config.mtu;
    let tun_path_for_task = tun_path.clone();
    let device = open_tun_device_with_retry(&config)
        .await
        .with_context(|| format!("failed to open TUN device {}", config.path.display()))?;
    set_nonblocking(&device).context("failed to set O_NONBLOCK on TUN device")?;
    let async_fd = Arc::new(
        AsyncFd::with_interest(device, Interest::READABLE | Interest::WRITABLE)
            .context("failed to register TUN fd with tokio reactor")?,
    );
    let writer = SharedTunWriter::from_async_fd(async_fd.clone());

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
        dns_cache,
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(
            async_fd,
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
    reader: Arc<AsyncFd<std::fs::File>>,
    writer: SharedTunWriter,
    udp_engine: TunUdpEngine,
    tcp_engine: TunTcpEngine,
    mtu: usize,
    defrag_max_total_bytes: usize,
    defrag_max_bytes_per_set: usize,
    defrag_max_fragment_sets: usize,
    defrag_max_fragments_per_set: usize,
) -> Result<()> {
    use std::io::Read as _;

    let mut buf = vec![0u8; mtu + 256];
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

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
}
