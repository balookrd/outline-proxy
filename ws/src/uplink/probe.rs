use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tracing::debug;

use crate::config::{DnsProbeConfig, HttpProbeConfig, ProbeConfig, TcpProbeConfig, UplinkConfig};
use crate::transport::{
    DnsCache, TcpShadowsocksReader, TcpShadowsocksWriter, UdpWsTransport, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source, connect_shadowsocks_udp_with_source,
    connect_websocket_with_source,
};
use crate::types::{TargetAddr, UplinkTransport};

use super::types::ProbeOutcome;

pub(super) async fn probe_uplink(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::types::WsTransportMode,
    effective_udp_mode: crate::types::WsTransportMode,
) -> Result<ProbeOutcome> {
    let (tcp_ok, tcp_latency) = timeout(
        probe.timeout,
        run_tcp_probe(cache, group, uplink, probe, Arc::clone(&dial_limit), effective_tcp_mode),
    )
    .await
    .map_err(|_| anyhow!("tcp probe timed out after {:?}", probe.timeout))??;
    let (udp_ok, udp_applicable, udp_latency) = timeout(
        probe.timeout,
        run_udp_probe(cache, group, uplink, probe, dial_limit, effective_udp_mode),
    )
    .await
    .map_err(|_| anyhow!("udp probe timed out after {:?}", probe.timeout))??;

    Ok(ProbeOutcome {
        tcp_ok,
        udp_ok,
        udp_applicable,
        tcp_latency,
        udp_latency,
    })
}

pub(super) async fn run_tcp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::types::WsTransportMode,
) -> Result<(bool, Option<Duration>)> {
    let started = Instant::now();
    if probe.ws.enabled {
        let probe_started = Instant::now();
        let result = match uplink.transport {
            UplinkTransport::Websocket => {
                run_ws_probe(
                    cache,
                    group,
                    &uplink.name,
                    "tcp",
                    uplink
                        .tcp_ws_url
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing tcp_ws_url", uplink.name))?,
                    effective_tcp_mode,
                    uplink.fwmark,
                    Arc::clone(&dial_limit),
                    probe.timeout,
                )
                .await
            },
            UplinkTransport::Shadowsocks => {
                run_tcp_socket_probe(cache, uplink, Arc::clone(&dial_limit)).await
            },
        };
        crate::metrics::record_probe(
            group,
            &uplink.name,
            "tcp",
            "ws",
            result.is_ok(),
            probe_started.elapsed(),
        );
        result?;
    }
    if let Some(http_probe) = &probe.http {
        let probe_started = Instant::now();
        let result = run_http_probe(
                    cache,
            group,
            uplink,
            http_probe,
            Arc::clone(&dial_limit),
            effective_tcp_mode,
        )
        .await;
        crate::metrics::record_probe(
            group,
            &uplink.name,
            "tcp",
            "http",
            result.is_ok(),
            probe_started.elapsed(),
        );
        let ok = result?;
        return Ok((ok, Some(started.elapsed())));
    }
    if let Some(tcp_probe) = &probe.tcp {
        let probe_started = Instant::now();
        let result = run_tcp_tunnel_probe(
                    cache,
            group,
            uplink,
            tcp_probe,
            Arc::clone(&dial_limit),
            effective_tcp_mode,
        )
        .await;
        crate::metrics::record_probe(
            group,
            &uplink.name,
            "tcp",
            "tcp",
            result.is_ok(),
            probe_started.elapsed(),
        );
        let ok = result?;
        return Ok((ok, Some(started.elapsed())));
    }
    if probe.ws.enabled {
        return Ok((true, Some(started.elapsed())));
    }
    Ok((true, None))
}

pub(super) async fn run_udp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: crate::types::WsTransportMode,
) -> Result<(bool, bool, Option<Duration>)> {
    if !uplink.supports_udp() {
        return Ok((false, false, None));
    }

    let started = Instant::now();
    if probe.ws.enabled {
        let probe_started = Instant::now();
        let result = match uplink.transport {
            UplinkTransport::Websocket => {
                run_ws_probe(
                    cache,
                    group,
                    &uplink.name,
                    "udp",
                    uplink
                        .udp_ws_url
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing udp_ws_url", uplink.name))?,
                    effective_udp_mode,
                    uplink.fwmark,
                    Arc::clone(&dial_limit),
                    probe.timeout,
                )
                .await
            },
            UplinkTransport::Shadowsocks => {
                run_udp_socket_probe(cache, uplink, Arc::clone(&dial_limit)).await
            },
        };
        crate::metrics::record_probe(
            group,
            &uplink.name,
            "udp",
            "ws",
            result.is_ok(),
            probe_started.elapsed(),
        );
        result?;
    }
    if let Some(dns_probe) = &probe.dns {
        let probe_started = Instant::now();
        let result = run_dns_probe(
                    cache,
            group,
            uplink,
            dns_probe,
            Arc::clone(&dial_limit),
            effective_udp_mode,
        )
        .await;
        crate::metrics::record_probe(
            group,
            &uplink.name,
            "udp",
            "dns",
            result.is_ok(),
            probe_started.elapsed(),
        );
        let ok = result?;
        return Ok((ok, true, Some(started.elapsed())));
    }
    if probe.ws.enabled {
        return Ok((true, true, Some(started.elapsed())));
    }
    Ok((true, true, None))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ws_probe(
    cache: &DnsCache,
    _group: &str,
    uplink_name: &str,
    transport: &'static str,
    url: &url::Url,
    mode: crate::types::WsTransportMode,
    fwmark: Option<u32>,
    dial_limit: Arc<Semaphore>,
    _pong_timeout: Duration,
) -> Result<()> {
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
    // Verify WebSocket connectivity only — TCP connect + TLS + HTTP upgrade.
    // Many servers do not respond to WebSocket ping control frames (they expect
    // Shadowsocks data immediately), so we do not send a ping here.  The
    // data-path is checked by the http / dns sub-probes that follow.
    let mut ws_stream = connect_websocket_with_source(cache, url, mode, fwmark, false, "probe_ws")
        .await
        .with_context(|| format!("failed to connect WebSocket probe to {url}"))?;

    debug!(
        uplink = %uplink_name,
        transport,
        probe = "ws",
        url = %url,
        "WebSocket probe connected, closing"
    );
    if let Err(error) = ws_stream.close().await {
        debug!(
            uplink = %uplink_name,
            transport,
            probe = "ws",
            url = %url,
            error = %error,
            "probe websocket close returned error during teardown"
        );
    }
    Ok(())
}

pub(super) async fn run_tcp_socket_probe(
    cache: &DnsCache,
    uplink: &UplinkConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<()> {
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
    let addr = uplink
        .tcp_addr
        .as_ref()
        .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", uplink.name))?;
    let _stream =
        connect_shadowsocks_tcp_with_source(cache, addr, uplink.fwmark, uplink.ipv6_first, "probe_tcp")
            .await?;
    Ok(())
}

pub(super) async fn run_udp_socket_probe(
    cache: &DnsCache,
    uplink: &UplinkConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<()> {
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
    let addr = uplink
        .udp_addr
        .as_ref()
        .ok_or_else(|| anyhow!("uplink {} missing udp_addr", uplink.name))?;
    let _socket =
        connect_shadowsocks_udp_with_source(cache, addr, uplink.fwmark, uplink.ipv6_first, "probe_udp")
            .await?;
    Ok(())
}

pub(super) fn is_expected_standby_probe_failure(error: &anyhow::Error) -> bool {
    crate::error_text::is_expected_standby_probe_failure(error)
}

pub(super) fn build_http_probe_request(host: &str, port: u16, path: &str) -> String {
    format!(
        "HEAD {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        format_http_host_header(host, port)
    )
}

async fn close_probe_tcp_writer(
    uplink_name: &str,
    probe: &'static str,
    writer: &mut TcpShadowsocksWriter,
) {
    if let Err(error) = writer.close().await {
        debug!(
            uplink = %uplink_name,
            transport = "tcp",
            probe,
            error = %format!("{error:#}"),
            "probe transport close returned error during teardown"
        );
    }
}

async fn close_probe_udp_transport(
    uplink_name: &str,
    probe: &'static str,
    transport: &UdpWsTransport,
) {
    if let Err(error) = transport.close().await {
        debug!(
            uplink = %uplink_name,
            transport = "udp",
            probe,
            error = %format!("{error:#}"),
            "probe transport close returned error during teardown"
        );
    }
}

pub(super) async fn run_http_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &HttpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::types::WsTransportMode,
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

    let target_wire = target.to_wire_bytes()?;
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("probe_http", "tcp");
    let (mut writer, mut reader) = {
        let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
        match uplink.transport {
            UplinkTransport::Websocket => {
                let ws_stream = connect_websocket_with_source(cache, 
                    uplink
                        .tcp_ws_url
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing tcp_ws_url", uplink.name))?,
                    effective_tcp_mode,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_http",
                )
                .await
                .with_context(|| {
                    format!("failed to connect HTTP probe websocket for uplink {}", uplink.name)
                })?;
                let (ws_sink, ws_stream) = ws_stream.split();
                let (writer, ctrl_tx) = TcpShadowsocksWriter::connect(
                    ws_sink,
                    uplink.cipher,
                    &master_key,
                    Arc::clone(&lifetime),
                )
                .await?;
                let request_salt = writer.request_salt();
                let reader = TcpShadowsocksReader::new(
                    ws_stream,
                    uplink.cipher,
                    &master_key,
                    lifetime,
                    ctrl_tx,
                )
                .with_request_salt(request_salt);
                (writer, reader)
            },
            UplinkTransport::Shadowsocks => {
                let stream = connect_shadowsocks_tcp_with_source(cache, 
                    uplink
                        .tcp_addr
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", uplink.name))?,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_http",
                )
                .await
                .with_context(|| {
                    format!(
                        "failed to connect HTTP probe shadowsocks socket for uplink {}",
                        uplink.name
                    )
                })?;
                let (reader_half, writer_half) = stream.into_split();
                let writer = TcpShadowsocksWriter::connect_socket(
                    writer_half,
                    uplink.cipher,
                    &master_key,
                    Arc::clone(&lifetime),
                )?;
                let request_salt = writer.request_salt();
                let reader = TcpShadowsocksReader::new_socket(
                    reader_half,
                    uplink.cipher,
                    &master_key,
                    lifetime,
                )
                .with_request_salt(request_salt);
                (writer, reader)
            },
        }
    };
    let result = async {
        writer
            .send_chunk(&target_wire)
            .await
            .context("failed to send HTTP probe target")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "tcp",
            "http",
            "outgoing",
            target_wire.len(),
        );

        // Use HEAD so health checks do not pull response bodies through the data
        // path. This keeps probe traffic tiny even when the probe URL points at a
        // large page or object.
        let request = build_http_probe_request(host, port, &path);
        writer
            .send_chunk(request.as_bytes())
            .await
            .context("failed to send HTTP probe request")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "tcp",
            "http",
            "outgoing",
            request.len(),
        );

        let response = reader
            .read_chunk()
            .await
            .context("failed to read HTTP probe response")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "tcp",
            "http",
            "incoming",
            response.len(),
        );
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

pub(super) async fn run_tcp_tunnel_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &TcpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::types::WsTransportMode,
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
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("probe_tcp_tunnel", "tcp");
    let (mut writer, mut reader) = {
        let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
        match uplink.transport {
            UplinkTransport::Websocket => {
                let ws_stream = connect_websocket_with_source(cache, 
                    uplink
                        .tcp_ws_url
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing tcp_ws_url", uplink.name))?,
                    effective_tcp_mode,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_tcp_tunnel",
                )
                .await
                .with_context(|| {
                    format!(
                        "failed to connect TCP-tunnel probe websocket for uplink {}",
                        uplink.name
                    )
                })?;
                let (ws_sink, ws_stream) = ws_stream.split();
                let (writer, ctrl_tx) = TcpShadowsocksWriter::connect(
                    ws_sink,
                    uplink.cipher,
                    &master_key,
                    Arc::clone(&lifetime),
                )
                .await?;
                let request_salt = writer.request_salt();
                let reader = TcpShadowsocksReader::new(
                    ws_stream,
                    uplink.cipher,
                    &master_key,
                    lifetime,
                    ctrl_tx,
                )
                .with_request_salt(request_salt);
                (writer, reader)
            },
            UplinkTransport::Shadowsocks => {
                let stream = connect_shadowsocks_tcp_with_source(cache, 
                    uplink
                        .tcp_addr
                        .as_ref()
                        .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", uplink.name))?,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_tcp_tunnel",
                )
                .await
                .with_context(|| {
                    format!(
                        "failed to connect TCP-tunnel probe shadowsocks socket for uplink {}",
                        uplink.name
                    )
                })?;
                let (reader_half, writer_half) = stream.into_split();
                let writer = TcpShadowsocksWriter::connect_socket(
                    writer_half,
                    uplink.cipher,
                    &master_key,
                    Arc::clone(&lifetime),
                )?;
                let request_salt = writer.request_salt();
                let reader = TcpShadowsocksReader::new_socket(
                    reader_half,
                    uplink.cipher,
                    &master_key,
                    lifetime,
                )
                .with_request_salt(request_salt);
                (writer, reader)
            },
        }
    };

    let result = async {
        writer
            .send_chunk(&target_wire)
            .await
            .context("failed to send TCP tunnel probe target address")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "tcp",
            "tcp",
            "outgoing",
            target_wire.len(),
        );

        match reader.read_chunk().await {
            Ok(chunk) => {
                crate::metrics::add_probe_bytes(
                    group,
                    &uplink.name,
                    "tcp",
                    "tcp",
                    "incoming",
                    chunk.len(),
                );
                debug!(
                    uplink = %uplink.name,
                    target = %format!("{}:{}", probe.host, probe.port),
                    bytes = chunk.len(),
                    "TCP tunnel probe received data from target"
                );
            },
            Err(ref e) if reader.closed_cleanly => {
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

pub(super) async fn run_dns_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &DnsProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: crate::types::WsTransportMode,
) -> Result<bool> {
    let dns_server = probe.target_addr()?;
    let query = build_dns_query(&probe.name);
    let mut payload = dns_server.to_wire_bytes()?;
    payload.extend_from_slice(&query);

    let transport = {
        let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
        match uplink.transport {
            UplinkTransport::Websocket => {
                let udp_ws_url = uplink.udp_ws_url.as_ref().ok_or_else(|| {
                    anyhow!("uplink {} has no udp_ws_url for DNS probe", uplink.name)
                })?;
                UdpWsTransport::connect(cache, 
                    udp_ws_url,
                    effective_udp_mode,
                    uplink.cipher,
                    &uplink.password,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_dns",
                    None,
                )
                .await
                .with_context(|| {
                    format!("failed to connect DNS probe websocket for uplink {}", uplink.name)
                })?
            },
            UplinkTransport::Shadowsocks => {
                let socket = connect_shadowsocks_udp_with_source(cache, 
                    uplink.udp_addr.as_ref().ok_or_else(|| {
                        anyhow!("uplink {} has no udp_addr for DNS probe", uplink.name)
                    })?,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_dns",
                )
                .await
                .with_context(|| {
                    format!(
                        "failed to connect DNS probe shadowsocks socket for uplink {}",
                        uplink.name
                    )
                })?;
                UdpWsTransport::from_socket(socket, uplink.cipher, &uplink.password, "probe_dns")?
            },
        }
    };

    let result = async {
        transport
            .send_packet(&payload)
            .await
            .context("failed to send DNS probe packet")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "udp",
            "dns",
            "outgoing",
            payload.len(),
        );
        let response = transport
            .read_packet()
            .await
            .context("failed to read DNS probe response")?;
        crate::metrics::add_probe_bytes(
            group,
            &uplink.name,
            "udp",
            "dns",
            "incoming",
            response.len(),
        );
        let (_, consumed) = TargetAddr::from_wire_bytes(&response)?;
        let dns = &response[consumed..];

        if dns.len() < 12 {
            bail!("DNS probe response is too short");
        }
        if dns[..2] != query[..2] {
            bail!("DNS probe transaction id mismatch");
        }
        if dns[3] & 0x0f != 0 {
            bail!("DNS probe returned non-zero rcode");
        }

        Ok::<bool, anyhow::Error>(true)
    }
    .await;

    debug!(
        uplink = %uplink.name,
        transport = "udp",
        probe = "dns",
        "closing probe transport after DNS probe"
    );
    close_probe_udp_transport(&uplink.name, "dns", &transport).await;
    result
}

pub(super) fn build_dns_query(name: &str) -> Vec<u8> {
    let txid = 0x5353u16.to_be_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

pub(super) fn format_http_host_header(host: &str, port: u16) -> String {
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
