use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::warn;

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use outline_metrics as metrics;
use outline_transport::is_dropped_oversized_udp_error;
use outline_uplink::TransportKind;

use socks5_proto::TargetAddr;

use super::group::GroupUdpContext;
use super::transport::{failover_udp_transport, reconcile_global_udp_transport};

pub(super) const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
pub(super) const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;

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
    metrics::add_udp_datagram(
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
    );
    metrics::add_bytes(
        "udp",
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
        metric_payload_len,
    );
    Ok(())
}

/// Send a pre-wrapped payload through a group's active transport, with
/// reconciliation + runtime failover mirroring the pre-refactor uplink loop.
pub(super) async fn send_tunneled_udp(
    ctx: &GroupUdpContext,
    target: Option<&TargetAddr>,
    payload: &[u8],
) -> Result<()> {
    reconcile_global_udp_transport(&ctx.manager, &ctx.active, target).await?;
    let (transport, uplink_name, active_index) = {
        let active = ctx.active.lock().await;
        (Arc::clone(&active.transport), active.uplink_name.clone(), active.index)
    };
    let group = ctx.manager.group_name();
    if let Err(error) = transport.send_packet(payload).await {
        if is_dropped_oversized_udp_error(&error) {
            return Ok(());
        }
        let replacement =
            failover_udp_transport(&ctx.manager, &ctx.active, target, active_index, error).await?;
        if let Err(error) = replacement.transport.send_packet(payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            return Err(error);
        }
        metrics::add_udp_datagram("client_to_upstream", group, &replacement.uplink_name);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            group,
            &replacement.uplink_name,
            payload.len(),
        );
        ctx.manager.report_active_traffic(replacement.index, TransportKind::Udp).await;
    } else {
        metrics::add_udp_datagram("client_to_upstream", group, &uplink_name);
        metrics::add_bytes("udp", "client_to_upstream", group, &uplink_name, payload.len());
        ctx.manager.report_active_traffic(active_index, TransportKind::Udp).await;
    }
    Ok(())
}
