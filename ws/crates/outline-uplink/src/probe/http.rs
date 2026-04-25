//! HTTP data-path probe.  Sends a HEAD request through the Shadowsocks
//! tunnel and verifies the response-status line — HEAD keeps probe traffic
//! tiny even when the configured URL points at a large object.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::DnsCache;

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
    let result = async {
        if needs_socks5_target {
            writer
                .send_chunk(&target_wire)
                .await
                .context("failed to send HTTP probe target")?;
            bytes.outgoing(target_wire.len());
        }

        // Use HEAD so health checks do not pull response bodies through the data
        // path. This keeps probe traffic tiny even when the probe URL points at a
        // large page or object.
        let request = build_http_probe_request(host, port, &path);
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

        Ok::<bool, anyhow::Error>((200..400).contains(&status))
    }
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
