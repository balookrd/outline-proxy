//! HTTP data-path probe.  Sends a HEAD request through the Shadowsocks
//! tunnel and verifies the response-status line — HEAD keeps probe traffic
//! tiny even when the configured URL points at a large object.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{DnsCache, TcpReader, TcpWriter};

use crate::config::{HttpProbeConfig, TargetAddr, UplinkConfig, UplinkTransport, TransportMode};
use crate::manager::probe::warm_tcp::{self, WarmTcpProbe, WarmTcpProbeSlot};

use super::metrics::BytesRecorder;
use super::transport::{close_probe_tcp_writer, connect_probe_tcp};

pub(super) async fn run_http_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &HttpProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: TransportMode,
    warm_slot: Option<&WarmTcpProbeSlot>,
) -> Result<(bool, Option<TransportMode>)> {
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

    // Try to reuse a warm pipe from a previous probe cycle. VLESS and SS-
    // over-WS are both eligible: VLESS bakes the target into the dial-time
    // handshake (stateful tunnel), and SS-over-WS keeps the upstream TCP
    // alive via HTTP keep-alive — the SOCKS5 target prefix is only sent
    // once per cached pipe lifetime (gated by `dialed_fresh` below) so the
    // server's tunnel stays bound to the probe target across cycles.
    // Plain Shadowsocks (direct UDP socket) gets `None` — no slot is
    // populated for it.
    let warm_taken = warm_slot.and_then(|slot| warm_tcp::take_if_matches(slot, effective_tcp_mode));
    let (mut writer, mut reader, downgraded_from, dialed_fresh) = match warm_taken {
        Some(WarmTcpProbe::Vless { writer, reader, .. })
        | Some(WarmTcpProbe::Ws { writer, reader, .. }) => (writer, reader, None, false),
        None => {
            let (w, r, downgraded) = connect_probe_tcp(
                cache,
                uplink,
                &target,
                "probe_http",
                "HTTP probe",
                effective_tcp_mode,
                dial_limit,
            )
            .await?;
            (w, r, downgraded, true)
        },
    };

    let bytes = BytesRecorder { group, uplink: &uplink.name, transport: "tcp", probe: "http" };
    // Skip the SOCKS5 target prefix on a reused VLESS pipe — the server
    // already locked the tunnel onto the probe target at dial time. Sending
    // it again would corrupt the upstream HTTP byte stream.
    let send_socks5_prefix = needs_socks5_target && dialed_fresh;
    let result = exchange_http_probe(
        &mut writer,
        &mut reader,
        host,
        port,
        &path,
        &target_wire,
        send_socks5_prefix,
        &bytes,
    )
    .await;

    let server_will_close = result.as_ref().map(|r| r.server_will_close).unwrap_or(true);
    let status_ok = result.as_ref().map(|r| r.status_ok).unwrap_or(false);
    let probe_err = result.err();

    // Stash for the next cycle iff: no error, status ok, server intends
    // to keep the connection open, and the uplink kind has a warm slot
    // (VLESS or SS-over-WS). A downgrade marker also disqualifies —
    // `effective_tcp_mode` for the next cycle will be different and
    // `take_if_matches` would reject it anyway; close now so the upstream
    // socket goes away promptly.
    let keep_warm = probe_err.is_none()
        && status_ok
        && !server_will_close
        && downgraded_from.is_none()
        && warm_slot.is_some();
    if keep_warm {
        if let Some(slot) = warm_slot {
            let warm = match uplink.transport {
                UplinkTransport::Vless => {
                    WarmTcpProbe::Vless { writer, reader, mode: effective_tcp_mode }
                },
                UplinkTransport::Ws => {
                    WarmTcpProbe::Ws { writer, reader, mode: effective_tcp_mode }
                },
                // Slot is only populated for Vless / Ws. Direct
                // Shadowsocks should never reach this branch because
                // `warm_slot.is_some()` would be false. Defend against
                // misuse by closing instead of mis-tagging.
                UplinkTransport::Shadowsocks => {
                    close_probe_tcp_writer(&uplink.name, "http", &mut writer).await;
                    return match probe_err {
                        Some(err) => Err(err),
                        None => Ok((status_ok, downgraded_from)),
                    };
                },
            };
            warm_tcp::put_back(slot, warm);
        }
    } else {
        debug!(
            uplink = %uplink.name,
            transport = "tcp",
            probe = "http",
            url = %probe.url,
            dialed_fresh,
            server_will_close,
            "closing probe transport after HTTP probe"
        );
        close_probe_tcp_writer(&uplink.name, "http", &mut writer).await;
    }
    match probe_err {
        Some(err) => Err(err),
        None => Ok((status_ok, downgraded_from)),
    }
}

struct HttpProbeResult {
    status_ok: bool,
    /// `true` if the response signalled the server intends to close the
    /// connection (`Connection: close`, or HTTP/1.0 without explicit
    /// `keep-alive`). Used to gate whether the warm slot may keep the pipe.
    server_will_close: bool,
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
) -> Result<HttpProbeResult> {
    if needs_socks5_target {
        writer
            .send_chunk(target_wire)
            .await
            .context("failed to send HTTP probe target")?;
        bytes.outgoing(target_wire.len());
    }

    // Use HEAD + keep-alive so health checks do not pull response bodies
    // through the data path *and* so the probe pipe survives the request
    // for reuse on the next cycle (gated by the response Connection
    // header). HEAD keeps probe traffic tiny even when the probe URL
    // points at a large object.
    let request = build_http_probe_request(host, port, path);
    writer
        .send_chunk(request.as_bytes())
        .await
        .context("failed to send HTTP probe request")?;
    bytes.outgoing(request.len());

    // Read until end-of-headers (`\r\n\r\n`). HEAD responses have no body,
    // so once headers are in we are done — the next request can be sent
    // immediately without draining anything else. A small max-bytes guard
    // protects against a misbehaving upstream that streams forever.
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut accum: Vec<u8> = Vec::with_capacity(512);
    loop {
        let chunk = reader
            .read_chunk()
            .await
            .context("failed to read HTTP probe response")?;
        if chunk.is_empty() {
            // Underlying transport reported clean EOF before headers
            // completed.
            bail!("HTTP probe response truncated before end of headers");
        }
        bytes.incoming(chunk.len());
        accum.extend_from_slice(&chunk);
        if find_end_of_headers(&accum).is_some() {
            break;
        }
        if accum.len() >= MAX_HEADER_BYTES {
            bail!("HTTP probe response headers exceeded {MAX_HEADER_BYTES} bytes");
        }
    }
    let head_len = find_end_of_headers(&accum).expect("loop guarantees double-CRLF present");
    let head = &accum[..head_len];
    let head_str = String::from_utf8_lossy(head);

    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("invalid HTTP probe response status line"))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or("");
    let status = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP probe response status line"))?;

    // RFC 7230: HTTP/1.1 is keep-alive by default, HTTP/1.0 is close by
    // default; either side can override with `Connection`. Header-name
    // match is case-insensitive.
    let mut explicit_close = false;
    let mut explicit_keepalive = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("connection") {
                let v = value.trim();
                if v.eq_ignore_ascii_case("close") {
                    explicit_close = true;
                } else if v.eq_ignore_ascii_case("keep-alive") {
                    explicit_keepalive = true;
                }
            }
        }
    }
    let server_will_close = if explicit_close {
        true
    } else if explicit_keepalive {
        false
    } else {
        // No explicit Connection header: HTTP/1.0 means close, HTTP/1.1+
        // means keep-alive.
        !version.eq_ignore_ascii_case("HTTP/1.1")
    };

    Ok(HttpProbeResult {
        status_ok: (200..400).contains(&status),
        server_will_close,
    })
}

fn find_end_of_headers(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

pub(crate) fn build_http_probe_request(host: &str, port: u16, path: &str) -> String {
    format!(
        "HEAD {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
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
#[path = "tests/http.rs"]
mod tests;
