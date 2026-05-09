//! TLS handshake-only data-path probe.
//!
//! Drives `ClientHello → ServerHello/Certificate → Finished → close_notify`
//! through the uplink tunnel against a configured `(SNI, port)` target. No
//! HTTP exchange follows the handshake — the goal is to reproduce the
//! user-flow `chunk0_timeout` pattern when upstream filtering silently drops
//! TLS records for a specific SNI. The plain-HTTP probe never exercises TLS,
//! and the WS sub-probe only covers the *outer* handshake to the uplink
//! server itself; this probe fills the gap by validating the *inner*
//! transport to a real product edge.
//!
//! Decoupled from `[probe.http]` so the metric label (`probe="tls"`) and
//! configuration (`[outline.probe.tls]`) reflect what the probe actually
//! does — a TLS handshake — instead of pretending to be a degenerate HTTP
//! exchange under an `https://` URL.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{
    DnsCache, TcpReader, TcpWriter, TlsClientConnection, TlsServerName,
    build_https_probe_client_config,
};

use crate::config::{TargetAddr, TlsProbeTarget, TransportMode, UplinkConfig, UplinkTransport};

use super::metrics::BytesRecorder;
use super::transport::{close_probe_tcp_writer, connect_probe_tcp};

pub(super) async fn run_tls_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    target_spec: &TlsProbeTarget,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: TransportMode,
) -> Result<(bool, Option<TransportMode>)> {
    // Build the SOCKS5/VLESS target descriptor from the configured target.
    // Domain hosts go through the proxy's DNS path on the uplink server side;
    // bare IPs (rare for a TLS probe but valid) route through atyp v4/v6.
    let target = if let Ok(ip) = target_spec.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => TargetAddr::IpV4(v4, target_spec.port),
            IpAddr::V6(v6) => TargetAddr::IpV6(v6, target_spec.port),
        }
    } else {
        TargetAddr::Domain(target_spec.host.clone(), target_spec.port)
    };

    // VLESS bakes the target into its own request header at dial time, so the
    // SOCKS5 atyp wire form must NOT be sent as the first chunk — the server
    // would forward those bytes verbatim into the upstream TLS stream and
    // corrupt `ClientHello`. Plain Shadowsocks-AEAD over WebSocket has no
    // header of its own and expects the SOCKS5 wire form as the first
    // decrypted bytes, so it still gets it.
    let needs_socks5_target = uplink.transport != UplinkTransport::Vless;
    let target_wire = target.to_wire_bytes()?;

    // No warm-pool reuse for TLS probes: the warm slot tracks plain-HTTP
    // keep-alive state, and a pipe bound to one TLS SNI cannot be reused for
    // a different SNI on the next cycle. Always fresh dial — the cost is
    // bounded by `probe.interval` (default 30 s+) so the extra handshakes
    // are negligible.
    let (mut writer, mut reader, downgraded_from) =
        connect_probe_tcp(cache, uplink, &target, "probe_tls", "TLS probe", effective_tcp_mode, dial_limit)
            .await?;

    let bytes = BytesRecorder { group, uplink: &uplink.name, transport: "tcp", probe: "tls" };
    let result = drive_tls_handshake(
        &mut writer,
        &mut reader,
        &target_spec.host,
        &target_wire,
        needs_socks5_target,
        &bytes,
    )
    .await;

    let probe_err = result.err();

    debug!(
        uplink = %uplink.name,
        transport = "tcp",
        probe = "tls",
        target_host = %target_spec.host,
        target_port = target_spec.port,
        ok = probe_err.is_none(),
        "closing probe transport after TLS probe"
    );
    close_probe_tcp_writer(&uplink.name, "tls", &mut writer).await;

    match probe_err {
        Some(err) => Err(err),
        None => Ok((true, downgraded_from)),
    }
}

/// I/O half of the TLS probe: drives the already-connected (writer, reader)
/// pair through the SOCKS5 prefix (when applicable) and a TLS handshake to
/// the named SNI, terminated with `close_notify`. Split out so unit tests
/// can drive it over an in-memory transport without standing up a real
/// network endpoint.
pub(super) async fn drive_tls_handshake(
    writer: &mut TcpWriter,
    reader: &mut TcpReader,
    sni: &str,
    target_wire: &[u8],
    needs_socks5_target: bool,
    bytes: &BytesRecorder<'_>,
) -> Result<()> {
    if needs_socks5_target {
        writer
            .send_chunk(target_wire)
            .await
            .context("failed to send TLS probe target")?;
        bytes.outgoing(target_wire.len());
    }

    // ALPN list mimics a typical browser. Server-side filtering that
    // discriminates by ALPN (e.g. dropping `h2` while passing `http/1.1`)
    // would otherwise be invisible to a probe that omits ALPN entirely.
    let config = build_https_probe_client_config(&[b"h2", b"http/1.1"]);
    let server_name = TlsServerName::try_from(sni.to_string())
        .map_err(|e| anyhow!("invalid TLS server name {sni}: {e}"))?;
    let mut conn = TlsClientConnection::new(config, server_name)
        .context("failed to construct TLS client connection")?;

    // Drive the handshake using rustls' synchronous state-machine API.
    // Pump pending writes out via `send_chunk` and feed server bytes in
    // by reading the next chunk. The outer `probe.timeout` (applied in
    // `probe::probe_uplink`) bounds the total wait — there is no inner
    // deadline here, so a silent upstream surfaces as a probe-level
    // timeout exactly the way `chunk0_timeout` surfaces on user flows.
    while conn.is_handshaking() {
        if conn.wants_write() {
            let mut wire = Vec::with_capacity(2048);
            while conn.wants_write() {
                conn.write_tls(&mut wire)
                    .context("rustls write_tls failed")?;
            }
            if !wire.is_empty() {
                writer
                    .send_chunk(&wire)
                    .await
                    .context("failed to forward TLS records to upstream")?;
                bytes.outgoing(wire.len());
            }
        } else {
            let chunk = reader
                .read_chunk()
                .await
                .context("failed to read TLS records from upstream")?;
            if chunk.is_empty() {
                bail!("TLS probe transport closed before handshake completed");
            }
            bytes.incoming(chunk.len());
            let chunk_bytes: &[u8] = &chunk;
            let chunk_len = chunk_bytes.len();
            let mut cursor = std::io::Cursor::new(chunk_bytes);
            while (cursor.position() as usize) < chunk_len {
                conn.read_tls(&mut cursor)
                    .context("rustls read_tls failed")?;
            }
            conn.process_new_packets()
                .context("TLS handshake processing failed")?;
        }
    }

    // Send `close_notify`: best-effort, the handshake itself succeeded
    // so a write failure here does not invalidate the probe outcome.
    conn.send_close_notify();
    let mut wire = Vec::new();
    while conn.wants_write() {
        let _ = conn.write_tls(&mut wire);
    }
    if !wire.is_empty() {
        let _ = writer.send_chunk(&wire).await;
        bytes.outgoing(wire.len());
    }

    Ok(())
}

#[cfg(test)]
#[path = "tests/tls.rs"]
mod tests;
