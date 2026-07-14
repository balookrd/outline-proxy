use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::warn;

use outline_metrics as metrics;
use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;

use socks5_proto::TargetAddr;

use super::group::GroupUdpContext;

pub(super) const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
pub(super) const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;
/// Receive window for every UDP socket on the relay paths.
///
/// A datagram read into a shorter buffer is silently truncated by the kernel,
/// so this must cover the largest datagram a socket can hand us — 65_527 bytes
/// over IPv6 (a 65_535-byte payload length minus the 8-byte UDP header), above
/// the 65_507-byte IPv4 ceiling. Sized at the u16 maximum, matching the window
/// the SOCKS5 receive loop has always used. Oversize *relayed* packets are a
/// separate concern: they are still dropped with a WARN against
/// [`MAX_UDP_RELAY_PACKET_SIZE`] / [`MAX_CLIENT_UDP_PACKET_SIZE`] after the
/// read, rather than being truncated inside it.
pub(super) const MAX_RECV_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

pub(super) fn udp_metric_payload_len(target: &TargetAddr, payload_len: usize) -> Result<usize> {
    Ok(target.to_wire_bytes()?.len().saturating_add(payload_len))
}

/// Forward a datagram to a directly-contacted server via the direct socket.
/// Domain targets are resolved through the shared DNS cache, mirroring the
/// TCP direct path so SOCKS5 UDP ASSOCIATE clients that send `ATYP=03` can
/// use policy-direct routing.
pub(super) async fn send_udp_direct(
    direct_socket: &Option<Arc<UdpSocket>>,
    target: &TargetAddr,
    payload: &[u8],
    cache: &outline_transport::DnsCache,
) -> Result<()> {
    let Some(sock) = direct_socket else {
        warn!(target = %target, "UDP direct route requested but direct socket not allocated; dropping");
        return Ok(());
    };
    let metric_payload_len = udp_metric_payload_len(target, payload.len())?;
    let target_addr = match target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => {
            let resolved = outline_transport::resolve_host_with_preference(
                cache,
                host,
                *port,
                "UDP direct resolve",
                false,
            )
            .await
            .with_context(|| format!("UDP direct: failed to resolve {target}"))?;
            match resolved.first().copied() {
                Some(addr) => addr,
                None => {
                    warn!(target = %target, "UDP direct: DNS returned no addresses; dropping");
                    return Ok(());
                },
            }
        },
    };
    sock.send_to(payload, target_addr)
        .await
        .context("direct UDP send failed")?;
    metrics::direct_udp_counters("up").record(metric_payload_len);
    Ok(())
}

pub(super) async fn send_tunneled_udp(
    ctx: &GroupUdpContext,
    target: Option<&TargetAddr>,
    payload: &[u8],
) -> Result<()> {
    ctx.send_packet(target, payload).await
}
