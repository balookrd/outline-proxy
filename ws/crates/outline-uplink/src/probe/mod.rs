//! Uplink probe orchestration.  This module decides which sub-probes to run
//! for a given uplink+probe config and records the attribution metrics around
//! each attempt.  Protocol-specific probe logic lives in the sibling
//! submodules (`ws`, `http`, `tcp_tunnel`, `dns`) and the shared Shadowsocks
//! TCP setup lives in `transport`.

mod dns;
mod http;
mod metrics;
mod tcp_tunnel;
mod transport;
mod ws;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};

use outline_transport::DnsCache;

use crate::config::{ProbeConfig, UplinkConfig, UplinkTransport, WsTransportMode};

use self::dns::run_dns_probe;
use self::http::run_http_probe;
use self::metrics::record_attempt;
use self::tcp_tunnel::run_tcp_tunnel_probe;
use self::ws::{run_quic_handshake_probe, run_tcp_socket_probe, run_udp_socket_probe, run_ws_probe};
use super::types::ProbeOutcome;

#[cfg(test)]
pub(crate) use self::http::build_http_probe_request;

pub(crate) fn is_expected_standby_probe_failure(error: &anyhow::Error) -> bool {
    crate::error_text::is_expected_standby_probe_failure(error)
}

pub(crate) async fn probe_uplink(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::config::WsTransportMode,
    effective_udp_mode: crate::config::WsTransportMode,
) -> Result<ProbeOutcome> {
    let (tcp_ok, tcp_latency, tcp_downgraded_from) = timeout(
        probe.timeout,
        run_tcp_probe(cache, group, uplink, probe, Arc::clone(&dial_limit), effective_tcp_mode),
    )
    .await
    .map_err(|_| anyhow!("tcp probe timed out after {:?}", probe.timeout))??;
    let (udp_ok, udp_applicable, udp_latency, udp_downgraded_from) = timeout(
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
        tcp_downgraded_from,
        udp_downgraded_from,
    })
}

async fn run_tcp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::config::WsTransportMode,
) -> Result<(bool, Option<Duration>, Option<WsTransportMode>)> {
    let started = Instant::now();
    let mut downgraded_from: Option<WsTransportMode> = None;
    if probe.ws.enabled {
        let ws_attempt = async {
            match uplink.transport {
                UplinkTransport::Ws | UplinkTransport::Vless => {
                    let url = uplink
                        .tcp_dial_url()
                        .ok_or_else(|| anyhow!("uplink {} missing dial URL", uplink.name))?;
                    if effective_tcp_mode == WsTransportMode::Quic {
                        run_quic_handshake_probe(
                            cache,
                            &uplink.name,
                            "tcp",
                            url,
                            uplink.transport,
                            uplink.fwmark,
                            uplink.ipv6_first,
                            Arc::clone(&dial_limit),
                        )
                        .await
                    } else {
                        run_ws_probe(
                            cache,
                            group,
                            &uplink.name,
                            "tcp",
                            url,
                            effective_tcp_mode,
                            uplink.fwmark,
                            Arc::clone(&dial_limit),
                            probe.timeout,
                        )
                        .await
                    }
                },
                UplinkTransport::Shadowsocks => {
                    run_tcp_socket_probe(cache, uplink, Arc::clone(&dial_limit)).await
                },
            }
        };
        let marker = record_attempt(group, &uplink.name, "tcp", "ws", ws_attempt).await?;
        downgraded_from = downgraded_from.or(marker);
    }
    if let Some(http_probe) = &probe.http {
        let (ok, marker) = record_attempt(
            group,
            &uplink.name,
            "tcp",
            "http",
            run_http_probe(
                cache,
                group,
                uplink,
                http_probe,
                Arc::clone(&dial_limit),
                effective_tcp_mode,
            ),
        )
        .await?;
        downgraded_from = downgraded_from.or(marker);
        return Ok((ok, Some(started.elapsed()), downgraded_from));
    }
    if let Some(tcp_probe) = &probe.tcp {
        let (ok, marker) = record_attempt(
            group,
            &uplink.name,
            "tcp",
            "tcp",
            run_tcp_tunnel_probe(
                cache,
                group,
                uplink,
                tcp_probe,
                Arc::clone(&dial_limit),
                effective_tcp_mode,
            ),
        )
        .await?;
        downgraded_from = downgraded_from.or(marker);
        return Ok((ok, Some(started.elapsed()), downgraded_from));
    }
    if probe.ws.enabled {
        return Ok((true, Some(started.elapsed()), downgraded_from));
    }
    Ok((true, None, downgraded_from))
}

async fn run_udp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: crate::config::WsTransportMode,
) -> Result<(bool, bool, Option<Duration>, Option<WsTransportMode>)> {
    if !uplink.supports_udp() {
        return Ok((false, false, None, None));
    }

    let started = Instant::now();
    let mut downgraded_from: Option<WsTransportMode> = None;
    if probe.ws.enabled {
        let ws_attempt = async {
            match uplink.transport {
                UplinkTransport::Ws | UplinkTransport::Vless => {
                    let url = uplink
                        .udp_dial_url()
                        .ok_or_else(|| anyhow!("uplink {} missing dial URL", uplink.name))?;
                    if effective_udp_mode == WsTransportMode::Quic {
                        run_quic_handshake_probe(
                            cache,
                            &uplink.name,
                            "udp",
                            url,
                            uplink.transport,
                            uplink.fwmark,
                            uplink.ipv6_first,
                            Arc::clone(&dial_limit),
                        )
                        .await
                    } else {
                        run_ws_probe(
                            cache,
                            group,
                            &uplink.name,
                            "udp",
                            url,
                            effective_udp_mode,
                            uplink.fwmark,
                            Arc::clone(&dial_limit),
                            probe.timeout,
                        )
                        .await
                    }
                },
                UplinkTransport::Shadowsocks => {
                    run_udp_socket_probe(cache, uplink, Arc::clone(&dial_limit)).await
                },
            }
        };
        let marker = record_attempt(group, &uplink.name, "udp", "ws", ws_attempt).await?;
        downgraded_from = downgraded_from.or(marker);
    }
    if let Some(dns_probe) = &probe.dns {
        let (ok, marker) = record_attempt(
            group,
            &uplink.name,
            "udp",
            "dns",
            run_dns_probe(
                cache,
                group,
                uplink,
                dns_probe,
                Arc::clone(&dial_limit),
                effective_udp_mode,
            ),
        )
        .await?;
        downgraded_from = downgraded_from.or(marker);
        return Ok((ok, true, Some(started.elapsed()), downgraded_from));
    }
    if probe.ws.enabled {
        return Ok((true, true, Some(started.elapsed()), downgraded_from));
    }
    Ok((true, true, None, downgraded_from))
}
