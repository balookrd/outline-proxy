//! TCP-tunnel data-path probe.  Dials a target host:port through the
//! Shadowsocks tunnel and succeeds as long as the remote sends *any* byte (or
//! closes cleanly).  Useful when the target speaks a server-first protocol
//! (SMTP, SSH, TLS) where the probe does not need to craft a request.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{DnsCache, TcpReader, TcpWriter};

use crate::config::{TargetAddr, TcpProbeConfig, UplinkConfig, UplinkTransport, WsTransportMode};

use super::metrics::BytesRecorder;
use super::transport::{close_probe_tcp_writer, connect_probe_tcp};

pub(super) async fn run_tcp_tunnel_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &TcpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: WsTransportMode,
) -> Result<(bool, Option<WsTransportMode>)> {
    let target = if let Ok(ip) = probe.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => TargetAddr::IpV4(v4, probe.port),
            IpAddr::V6(v6) => TargetAddr::IpV6(v6, probe.port),
        }
    } else {
        TargetAddr::Domain(probe.host.clone(), probe.port)
    };

    // VLESS encodes the target in the request header — sending the SOCKS5
    // wire form as the first application chunk would leak as garbage into
    // the upstream stream. SS-AEAD requires it.
    let needs_socks5_target = uplink.transport != UplinkTransport::Vless;
    let target_wire = target.to_wire_bytes()?;
    let (mut writer, mut reader, downgraded_from) = connect_probe_tcp(
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
    let result = exchange_tcp_tunnel_probe(
        &mut writer,
        &mut reader,
        &uplink.name,
        &probe.host,
        probe.port,
        &target_wire,
        needs_socks5_target,
        &bytes,
    )
    .await;

    close_probe_tcp_writer(&uplink.name, "tcp", &mut writer).await;
    result.map(|ok| (ok, downgraded_from))
}

/// I/O half of the TCP-tunnel probe: drives the connected (writer, reader)
/// pair through the SOCKS5 prefix (or VLESS header flush) and the
/// any-byte-or-clean-close acceptance check. Split out from
/// [`run_tcp_tunnel_probe`] so unit tests can drive it over an in-memory
/// transport.
#[allow(clippy::too_many_arguments)]
async fn exchange_tcp_tunnel_probe(
    writer: &mut TcpWriter,
    reader: &mut TcpReader,
    uplink_name: &str,
    target_host: &str,
    target_port: u16,
    target_wire: &[u8],
    needs_socks5_target: bool,
    bytes: &BytesRecorder<'_>,
) -> Result<bool> {
    if needs_socks5_target {
        writer
            .send_chunk(target_wire)
            .await
            .context("failed to send TCP tunnel probe target address")?;
        bytes.outgoing(target_wire.len());
    } else {
        // VLESS: flush the request header (which carries the target) by
        // sending an empty chunk; without this, server-first protocols
        // would have nothing to trigger the upstream dial and the probe
        // would hang waiting for a reply that never comes.
        writer
            .send_chunk(&[])
            .await
            .context("failed to flush VLESS request header for TCP tunnel probe")?;
    }

    match reader.read_chunk().await {
        Ok(chunk) => {
            bytes.incoming(chunk.len());
            debug!(
                uplink = %uplink_name,
                target = %format!("{target_host}:{target_port}"),
                bytes = chunk.len(),
                "TCP tunnel probe received data from target"
            );
        },
        Err(ref e) if reader.closed_cleanly() => {
            debug!(
                uplink = %uplink_name,
                target = %format!("{target_host}:{target_port}"),
                error = %format!("{e:#}"),
                "TCP tunnel probe: remote closed cleanly"
            );
        },
        Err(e) => {
            return Err(e)
                .context(format!("TCP tunnel probe to {target_host}:{target_port} failed"));
        },
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::test_loopback::spawn_vless_loopback;

    /// Regression for the "VLESS TCP-tunnel probe leaks SOCKS5 target_wire
    /// into the upstream stream" bug AND the "VLESS request header is
    /// never flushed for server-first targets" bug. With
    /// `needs_socks5_target = false` the fake VLESS server must see an
    /// empty app stream (just the request header, then EOF) — meaning
    /// the empty `send_chunk(&[])` correctly flushed the header, and no
    /// SOCKS5 prefix leaked in.
    #[tokio::test]
    async fn vless_tcp_tunnel_probe_flushes_header_without_socks5_prefix() {
        let (mut writer, mut reader, server) = spawn_vless_loopback(b"OK");

        let dummy_target =
            TargetAddr::Domain("example.com".to_string(), 25).to_wire_bytes().unwrap();
        let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "tcp" };
        let result = exchange_tcp_tunnel_probe(
            &mut writer,
            &mut reader,
            "u",
            "example.com",
            25,
            &dummy_target,
            false, // VLESS path
            &bytes,
        )
        .await
        .expect("exchange_tcp_tunnel_probe failed");
        assert!(result, "any byte from the target counts as success");

        writer.close().await.unwrap();
        let capture = server.await.unwrap().unwrap();
        assert!(
            capture.app_stream.is_empty(),
            "VLESS tcp-tunnel app stream must be empty (target carried in request header) — got: {:?}",
            capture.app_stream
        );
    }
}
