//! HTTP data-path probe.  Sends a HEAD request through the Shadowsocks
//! tunnel and verifies the response-status line — HEAD keeps probe traffic
//! tiny even when the configured URL points at a large object.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{DnsCache, TcpReader, TcpWriter};

use crate::config::{HttpProbeConfig, TargetAddr, UplinkConfig, UplinkTransport, WsTransportMode};

use super::metrics::BytesRecorder;
use super::transport::{close_probe_tcp_writer, connect_probe_tcp};

pub(super) async fn run_http_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &HttpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: WsTransportMode,
) -> Result<bool> {
    if probe.url.scheme() != "http" {
        bail!("only http:// probe URLs are currently supported");
    }

    let host = probe
        .url
        .host_str()
        .ok_or_else(|| anyhow!("http probe URL is missing host: {}", probe.url))?;
    let port = probe.url.port_or_known_default().unwrap_or(80);
    let target = if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => TargetAddr::IpV4(v4, port),
            IpAddr::V6(v6) => TargetAddr::IpV6(v6, port),
        }
    } else {
        TargetAddr::Domain(host.to_string(), port)
    };

    let path = {
        let mut path = if probe.url.path().is_empty() {
            "/".to_string()
        } else {
            probe.url.path().to_string()
        };
        if let Some(query) = probe.url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    };

    // VLESS encodes the target host:port in its request header, so the SOCKS5
    // atyp-prefixed wire form must NOT be sent as the first chunk — that would
    // leak as garbage bytes into the upstream HTTP stream and the origin server
    // would reply 400. Shadowsocks-AEAD has no header of its own and expects
    // the SOCKS5 wire form as the first decrypted bytes, so it still gets it.
    let needs_socks5_target = uplink.transport != UplinkTransport::Vless;
    let target_wire = target.to_wire_bytes()?;
    let (mut writer, mut reader) = connect_probe_tcp(
        cache,
        uplink,
        &target,
        "probe_http",
        "HTTP probe",
        effective_tcp_mode,
        dial_limit,
    )
    .await?;
    let bytes = BytesRecorder { group, uplink: &uplink.name, transport: "tcp", probe: "http" };
    let result = exchange_http_probe(
        &mut writer,
        &mut reader,
        host,
        port,
        &path,
        &target_wire,
        needs_socks5_target,
        &bytes,
    )
    .await;

    debug!(
        uplink = %uplink.name,
        transport = "tcp",
        probe = "http",
        url = %probe.url,
        "closing probe transport after HTTP probe"
    );
    close_probe_tcp_writer(&uplink.name, "http", &mut writer).await;
    result
}

/// I/O half of the HTTP probe: drives the already-connected (writer, reader)
/// pair through the SOCKS5 prefix (when applicable), HEAD request, and
/// response-status parse. Split out from [`run_http_probe`] so unit tests
/// can drive it over an in-memory transport without standing up a real
/// network endpoint.
#[allow(clippy::too_many_arguments)]
async fn exchange_http_probe(
    writer: &mut TcpWriter,
    reader: &mut TcpReader,
    host: &str,
    port: u16,
    path: &str,
    target_wire: &[u8],
    needs_socks5_target: bool,
    bytes: &BytesRecorder<'_>,
) -> Result<bool> {
    if needs_socks5_target {
        writer
            .send_chunk(target_wire)
            .await
            .context("failed to send HTTP probe target")?;
        bytes.outgoing(target_wire.len());
    }

    // Use HEAD so health checks do not pull response bodies through the data
    // path. This keeps probe traffic tiny even when the probe URL points at a
    // large page or object.
    let request = build_http_probe_request(host, port, path);
    writer
        .send_chunk(request.as_bytes())
        .await
        .context("failed to send HTTP probe request")?;
    bytes.outgoing(request.len());

    let response = reader
        .read_chunk()
        .await
        .context("failed to read HTTP probe response")?;
    bytes.incoming(response.len());
    let line = String::from_utf8_lossy(&response);
    let status = line
        .lines()
        .next()
        .and_then(|first| first.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP probe response status line"))?;

    Ok((200..400).contains(&status))
}

pub(crate) fn build_http_probe_request(host: &str, port: u16, path: &str) -> String {
    format!(
        "HEAD {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        format_http_host_header(host, port)
    )
}

fn format_http_host_header(host: &str, port: u16) -> String {
    let bracketed = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    match port {
        80 => bracketed,
        _ => format!("{bracketed}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::test_loopback::spawn_vless_loopback;

    /// Regression for the "VLESS HTTP probe leaks SOCKS5 target_wire into
    /// the upstream stream" bug: with `needs_socks5_target = false` the
    /// fake VLESS server must see exactly the HTTP HEAD request — no atyp
    /// / addr / port prefix. Equivalent to the live behavior on a VLESS
    /// uplink (any transport mode), since target is already encoded in
    /// the VLESS request header.
    #[tokio::test]
    async fn vless_http_probe_does_not_prefix_socks5_target() {
        let (mut writer, mut reader, server) =
            spawn_vless_loopback(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        let dummy_target = TargetAddr::Domain("example.com".to_string(), 80).to_wire_bytes().unwrap();
        let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "http" };
        let result = exchange_http_probe(
            &mut writer,
            &mut reader,
            "example.com",
            80,
            "/",
            &dummy_target,
            false, // VLESS path
            &bytes,
        )
        .await
        .expect("exchange_http_probe failed");
        assert!(result, "fake server returned 200; probe should report Ok(true)");

        // Drop the writer so the server task observes a clean EOF and the
        // capture future resolves.
        writer.close().await.unwrap();
        let capture = server.await.unwrap().unwrap();

        let app = String::from_utf8(capture.app_stream).unwrap();
        assert!(
            app.starts_with("HEAD / HTTP/1.1\r\n"),
            "VLESS app stream should start with the HEAD request — got: {app:?}"
        );
        assert!(
            !app.contains("\x02example.com"),
            "VLESS app stream must not contain a SOCKS5 atyp/host prefix — got: {app:?}"
        );
    }

    /// Symmetric positive control: with `needs_socks5_target = true` (the
    /// pre-fix behavior, still correct for SS-AEAD uplinks) the captured
    /// server-side stream MUST contain the SOCKS5 atyp prefix ahead of
    /// the HTTP request. Pinning this guards against accidentally
    /// flipping the default for SS uplinks.
    #[tokio::test]
    async fn ss_style_http_probe_prefixes_socks5_target() {
        let (mut writer, mut reader, server) =
            spawn_vless_loopback(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        let target = TargetAddr::Domain("example.com".to_string(), 80);
        let target_wire = target.to_wire_bytes().unwrap();
        let bytes = BytesRecorder { group: "g", uplink: "u", transport: "tcp", probe: "http" };
        let _ = exchange_http_probe(
            &mut writer,
            &mut reader,
            "example.com",
            80,
            "/",
            &target_wire,
            true, // SS path
            &bytes,
        )
        .await
        .expect("exchange_http_probe failed");

        writer.close().await.unwrap();
        let capture = server.await.unwrap().unwrap();
        // With needs_socks5_target=true the captured app stream begins
        // with the SOCKS5 atyp/host/port wire form, not "HEAD".
        assert!(
            capture.app_stream.starts_with(&target_wire),
            "SS-style probe must prefix target_wire to the app stream"
        );
    }
}
