//! TCP-tunnel data-path probe.  Dials a target host:port through the
//! Shadowsocks tunnel and succeeds as long as the remote sends *any* byte (or
//! closes cleanly).  Useful when the target speaks a server-first protocol
//! (SMTP, SSH, TLS) where the probe does not need to craft a request.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::DnsCache;

use crate::config::{TargetAddr, TcpProbeConfig, UplinkConfig, WsTransportMode};

use super::metrics::BytesRecorder;
use super::transport::{close_probe_tcp_writer, connect_probe_tcp};

pub(super) async fn run_tcp_tunnel_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &TcpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: WsTransportMode,
) -> Result<bool> {
    let target = if let Ok(ip) = probe.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => TargetAddr::IpV4(v4, probe.port),
            IpAddr::V6(v6) => TargetAddr::IpV6(v6, probe.port),
        }
    } else {
        TargetAddr::Domain(probe.host.clone(), probe.port)
    };

    let target_wire = target.to_wire_bytes()?;
    let (mut writer, mut reader) = connect_probe_tcp(
        cache,
        uplink,
        &target,
        "probe_tcp_tunnel",
        "TCP-tunnel probe",
        effective_tcp_mode,
        dial_limit,
    )
    .await?;

    let bytes = BytesRecorder { group, uplink: &uplink.name, transport: "tcp", probe: "tcp" };
    let result = async {
        writer
            .send_chunk(&target_wire)
            .await
            .context("failed to send TCP tunnel probe target address")?;
        bytes.outgoing(target_wire.len());

        match reader.read_chunk().await {
            Ok(chunk) => {
                bytes.incoming(chunk.len());
                debug!(
                    uplink = %uplink.name,
                    target = %format!("{}:{}", probe.host, probe.port),
                    bytes = chunk.len(),
                    "TCP tunnel probe received data from target"
                );
            },
            Err(ref e) if reader.closed_cleanly() => {
                debug!(
                    uplink = %uplink.name,
                    target = %format!("{}:{}", probe.host, probe.port),
                    error = %format!("{e:#}"),
                    "TCP tunnel probe: remote closed cleanly"
                );
            },
            Err(e) => {
                return Err(e)
                    .context(format!("TCP tunnel probe to {}:{} failed", probe.host, probe.port));
            },
        }

        Ok::<bool, anyhow::Error>(true)
    }
    .await;

    close_probe_tcp_writer(&uplink.name, "tcp", &mut writer).await;
    result
}
