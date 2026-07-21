//! Uplink probe orchestration.  This module decides which sub-probes to run
//! for a given uplink+probe config and records the attribution metrics around
//! each attempt.  Protocol-specific probe logic lives in the sibling
//! submodules (`ws`, `http`, `tcp_tunnel`, `dns`) and the shared Shadowsocks
//! TCP setup lives in `transport`.

pub(crate) mod dns;
pub(crate) mod endpoint;
pub(crate) mod http;
mod metrics;
mod tcp_tunnel;
pub(crate) mod tls;
mod transport;
mod ws;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tracing::warn;

use outline_transport::DnsCache;

use crate::config::{ProbeConfig, SsPathKind, TransportMode, UplinkConfig, UplinkTransport};

use self::dns::run_dns_probe;
use self::http::run_http_probe;
use self::metrics::record_attempt;
use self::tcp_tunnel::run_tcp_tunnel_probe;
use self::tls::run_tls_probe;
use self::ws::run_ws_probe;
use super::manager::probe::outcome::ProbeOutcome;
use super::manager::probe::warm_tcp::WarmTcpProbeSlot;
use super::manager::probe::warm_udp::WarmUdpProbeSlot;

#[cfg(test)]
pub(crate) use self::http::build_http_probe_request;

pub(crate) fn is_expected_standby_probe_failure(error: &anyhow::Error) -> bool {
    crate::error_classify::is_expected_standby_probe_failure(error)
}

/// Outcome of a single transport plane's (TCP or UDP) probe cycle.
///
/// Splits the two signals the old single `bool` conflated:
///
/// * `carrier_ok` — the *outer* carrier handshake to our own uplink server
///   (WS/TLS upgrade or QUIC handshake) came up. This is what the
///   `H3 → H2 → H1` mode-downgrade cascade keys on, because a downgrade only
///   changes the outer carrier between us and the uplink server. Sourced from
///   the connectivity-only WS sub-probe (or a live warm pipe proving the same
///   handshake still works).
/// * `transport_ok` — the *inner* data path all the way to a real product edge
///   (TLS handshake / HTTP exchange / DNS round-trip through the tunnel)
///   succeeded. This is the site-reachability signal that drives health and
///   wire-failover. A slow or dead exit leg fails this while `carrier_ok`
///   stays true — and must NOT trip the carrier downgrade, since dropping the
///   outer carrier to a lower HTTP version cannot fix a problem that lives
///   past the uplink server.
///
/// When no dedicated carrier (WS) sub-probe runs — `[probe.ws] enabled = false`
/// with no warm pipe — there is no independent carrier signal, so `carrier_ok`
/// mirrors `transport_ok` to preserve the legacy "any probe failure caps the
/// carrier" behaviour.
struct PlaneProbe {
    transport_ok: bool,
    carrier_ok: bool,
    /// UDP only: false when the uplink has no UDP dial URL (probe not
    /// applicable). Always true for the TCP plane.
    applicable: bool,
    latency: Option<Duration>,
    downgraded_from: Option<TransportMode>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn probe_uplink(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::config::TransportMode,
    effective_udp_mode: crate::config::TransportMode,
    warm_tcp_slot: Option<WarmTcpProbeSlot>,
    warm_udp_slot: Option<WarmUdpProbeSlot>,
) -> Result<ProbeOutcome> {
    // Run the two planes concurrently. They share nothing but the read-mostly
    // DNS cache and the dial-limit semaphore, and running them in parallel is
    // load-bearing now that each plane owns per-stage timeouts internally: a
    // TCP app-stage that stalls for the full `probe.timeout` no longer delays
    // — let alone masks — the UDP plane. A timeout or error inside one plane
    // resolves that plane to `*_ok = false`; it never turns into a whole-probe
    // `Err`, so a stalled TCP-TLS handshake can no longer knock the healthy
    // UDP/QUIC carrier down with it.
    let (tcp, udp) = tokio::join!(
        run_tcp_probe(
            cache,
            group,
            uplink,
            probe,
            Arc::clone(&dial_limit),
            effective_tcp_mode,
            warm_tcp_slot,
        ),
        run_udp_probe(cache, group, uplink, probe, dial_limit, effective_udp_mode, warm_udp_slot),
    );

    Ok(ProbeOutcome {
        tcp_ok: tcp.transport_ok,
        tcp_carrier_ok: tcp.carrier_ok,
        udp_ok: udp.transport_ok,
        udp_carrier_ok: udp.carrier_ok,
        udp_applicable: udp.applicable,
        tcp_latency: tcp.latency,
        udp_latency: udp.latency,
        tcp_downgraded_from: tcp.downgraded_from,
        udp_downgraded_from: udp.downgraded_from,
    })
}

async fn run_tcp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::config::TransportMode,
    warm_tcp_slot: Option<WarmTcpProbeSlot>,
) -> PlaneProbe {
    let started = Instant::now();
    let mut downgraded_from: Option<TransportMode> = None;
    // The WS sub-probe verifies that the TCP+TLS+WebSocket-upgrade
    // (or QUIC handshake) pipeline can still be established. When a
    // warm-TCP slot already holds a pipe at the same effective carrier
    // mode, *that pipe is itself proof the same pipeline succeeded on
    // the previous cycle and is still alive* (the keepalive loop and/or
    // the next HTTP sub-probe will exercise it). Re-dialling a fresh WS
    // handshake here is redundant and pays the very cost the warm slot
    // exists to avoid. Skip it; the HTTP sub-probe below still validates
    // the data path through the warm pipe.
    let ws_warm_elided = probe.ws.enabled
        && matches!(uplink.transport, UplinkTransport::Vless | UplinkTransport::Ss)
        && warm_tcp_slot.as_ref().is_some_and(|slot| {
            use crate::manager::probe::warm_tcp::peek_matches;
            peek_matches(slot, effective_tcp_mode)
        });
    // ── Carrier-liveness stage ──────────────────────────────────────────
    // Establish whether the outer carrier to *our* uplink server is up. This
    // is the only signal allowed to drive the H3→H2→H1 mode-downgrade: the
    // cascade rewrites the outer carrier, so a failure of the far exit leg
    // (measured by the app stage below) must not reach it. A live warm pipe
    // counts as proof the same handshake still works this cycle.
    let (carrier_ok, carrier_probe_ran) = if ws_warm_elided {
        (true, true)
    } else if probe.ws.enabled
        && matches!(uplink.transport, UplinkTransport::Vless | UplinkTransport::Ss)
    {
        match uplink.tcp_dial_url() {
            None => {
                warn!(uplink = %uplink.name, "tcp probe: uplink missing dial URL");
                return PlaneProbe {
                    transport_ok: false,
                    carrier_ok: false,
                    applicable: true,
                    latency: Some(started.elapsed()),
                    downgraded_from,
                };
            },
            Some(url) => {
                let ws_attempt = run_ws_probe(
                    cache,
                    group,
                    &uplink.name,
                    "tcp",
                    url,
                    effective_tcp_mode,
                    uplink.fwmark,
                    uplink.combined_ss_kind(SsPathKind::Tcp),
                    Arc::clone(&dial_limit),
                    probe.timeout,
                );
                match timeout(
                    probe.timeout,
                    record_attempt(group, &uplink.name, "tcp", "ws", ws_attempt),
                )
                .await
                {
                    Ok(Ok(marker)) => {
                        downgraded_from = downgraded_from.or(marker);
                        (true, true)
                    },
                    Ok(Err(_)) | Err(_) => (false, true),
                }
            },
        }
    } else {
        // No dedicated carrier probe this cycle — fold the decision into the
        // app stage below (legacy behaviour when `[probe.ws] enabled = false`).
        (true, false)
    };

    // ── App / data-path stage ───────────────────────────────────────────
    // Reachability through the tunnel to a real product edge. Failures here
    // (dead/slow exit, silent upstream after ClientHello) mark the plane
    // unhealthy and drive wire-failover, but leave the carrier alone.
    // Skipped entirely when the carrier is already known down: an app
    // handshake cannot succeed over a dead carrier, and spending it would
    // just burn a doomed dial.
    // TLS handshake-only sub-probe takes precedence over the application-level
    // HTTP/TCP variants: when configured, it most closely reproduces the
    // user-flow `chunk0_timeout` failure mode (silent upstream after
    // ClientHello) so health flips fire on the right signal. Mutually
    // exclusive with `[probe.http]` / `[probe.tcp]` for the same reason
    // those two are: only one application-level probe runs per cycle to
    // bound the per-cycle handshake count.
    let app_ok: Option<bool> = if !carrier_ok {
        Some(false)
    } else if let Some(tls_probe) = &probe.tls {
        let target_spec = tls_probe.next_target();
        let attempt = record_attempt(
            group,
            &uplink.name,
            "tcp",
            "tls",
            run_tls_probe(
                cache,
                group,
                uplink,
                target_spec,
                Arc::clone(&dial_limit),
                effective_tcp_mode,
            ),
        );
        match timeout(probe.timeout, attempt).await {
            Ok(Ok((ok, marker))) => {
                downgraded_from = downgraded_from.or(marker);
                Some(ok)
            },
            Ok(Err(_)) | Err(_) => Some(false),
        }
    } else if let Some(http_probe) = &probe.http {
        let url = http_probe.next_url();
        let attempt = record_attempt(
            group,
            &uplink.name,
            "tcp",
            "http",
            run_http_probe(
                cache,
                group,
                uplink,
                url,
                Arc::clone(&dial_limit),
                effective_tcp_mode,
                warm_tcp_slot.as_ref(),
            ),
        );
        match timeout(probe.timeout, attempt).await {
            Ok(Ok((ok, marker))) => {
                downgraded_from = downgraded_from.or(marker);
                Some(ok)
            },
            Ok(Err(_)) | Err(_) => Some(false),
        }
    } else if let Some(tcp_probe) = &probe.tcp {
        let attempt = record_attempt(
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
        );
        match timeout(probe.timeout, attempt).await {
            Ok(Ok((ok, marker))) => {
                downgraded_from = downgraded_from.or(marker);
                Some(ok)
            },
            Ok(Err(_)) | Err(_) => Some(false),
        }
    } else {
        // Only a WS carrier probe (or nothing) configured: no separate data
        // path to validate — the plane's health is the carrier's health.
        None
    };

    // No app sub-probe ran: latency is meaningful only when *some* probe
    // (carrier or app) actually dialled. Mirror the pre-split contract where
    // a pure ws-probe reported elapsed time and a fully-unconfigured probe
    // reported `None`.
    let any_probe_ran = carrier_probe_ran || app_ok.is_some();
    let latency = any_probe_ran.then(|| started.elapsed());
    let transport_ok = app_ok.unwrap_or(carrier_ok);
    // When no dedicated carrier probe ran, there is no independent carrier
    // signal — mirror it from transport health so an app failure still caps
    // the carrier exactly as it did before the split.
    let carrier_ok = if carrier_probe_ran { carrier_ok } else { transport_ok };

    PlaneProbe {
        transport_ok,
        carrier_ok,
        applicable: true,
        latency,
        downgraded_from,
    }
}

async fn run_udp_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: crate::config::TransportMode,
    warm_udp_slot: Option<WarmUdpProbeSlot>,
) -> PlaneProbe {
    if !uplink.supports_udp() {
        return PlaneProbe {
            transport_ok: false,
            carrier_ok: false,
            applicable: false,
            latency: None,
            downgraded_from: None,
        };
    }

    let started = Instant::now();
    let mut downgraded_from: Option<TransportMode> = None;
    // Symmetric to the TCP-side WS-elide: when a warm UDP slot already
    // holds a transport at the same effective carrier mode, that pipe is
    // itself proof the UDP-side WS handshake (or QUIC handshake) still
    // works. Re-dialling a fresh handshake here is redundant and pays
    // exactly the cost the warm slot exists to avoid — it dominates
    // the measured UDP probe latency for VLESS uplinks once the DNS
    // sub-probe path is cheap (e.g. local dnsmasq cache on the server).
    let ws_warm_elided = probe.ws.enabled
        && matches!(uplink.transport, UplinkTransport::Vless | UplinkTransport::Ss)
        && warm_udp_slot.as_ref().is_some_and(|slot| {
            use crate::manager::probe::warm_udp::peek_matches;
            peek_matches(slot, effective_udp_mode)
        });
    // ── Carrier-liveness stage (UDP/QUIC handshake to our uplink server) ──
    let (carrier_ok, carrier_probe_ran) = if ws_warm_elided {
        (true, true)
    } else if probe.ws.enabled
        && matches!(uplink.transport, UplinkTransport::Vless | UplinkTransport::Ss)
    {
        match uplink.udp_dial_url() {
            None => {
                warn!(uplink = %uplink.name, "udp probe: uplink missing dial URL");
                return PlaneProbe {
                    transport_ok: false,
                    carrier_ok: false,
                    applicable: true,
                    latency: Some(started.elapsed()),
                    downgraded_from,
                };
            },
            Some(url) => {
                let ws_attempt = run_ws_probe(
                    cache,
                    group,
                    &uplink.name,
                    "udp",
                    url,
                    effective_udp_mode,
                    uplink.fwmark,
                    uplink.combined_ss_kind(SsPathKind::Udp),
                    Arc::clone(&dial_limit),
                    probe.timeout,
                );
                match timeout(
                    probe.timeout,
                    record_attempt(group, &uplink.name, "udp", "ws", ws_attempt),
                )
                .await
                {
                    Ok(Ok(marker)) => {
                        downgraded_from = downgraded_from.or(marker);
                        (true, true)
                    },
                    Ok(Err(_)) | Err(_) => (false, true),
                }
            },
        }
    } else {
        (true, false)
    };

    // ── App / data-path stage (DNS round-trip through the tunnel) ────────
    let app_ok: Option<bool> = if !carrier_ok {
        Some(false)
    } else if let Some(dns_probe) = &probe.dns {
        let attempt = record_attempt(
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
                warm_udp_slot.as_ref(),
            ),
        );
        match timeout(probe.timeout, attempt).await {
            Ok(Ok((ok, marker))) => {
                downgraded_from = downgraded_from.or(marker);
                Some(ok)
            },
            Ok(Err(_)) | Err(_) => Some(false),
        }
    } else {
        None
    };

    let any_probe_ran = carrier_probe_ran || app_ok.is_some();
    let latency = any_probe_ran.then(|| started.elapsed());
    let transport_ok = app_ok.unwrap_or(carrier_ok);
    let carrier_ok = if carrier_probe_ran { carrier_ok } else { transport_ok };

    PlaneProbe {
        transport_ok,
        carrier_ok,
        applicable: true,
        latency,
        downgraded_from,
    }
}
