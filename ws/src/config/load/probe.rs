use std::time::Duration;

use anyhow::{Context, Result};
use tracing::warn;

use outline_uplink::{
    DnsProbeConfig, HttpProbeConfig, ProbeConfig, TcpProbeConfig, TlsProbeConfig,
    TlsProbeTarget, WsProbeConfig,
};

use super::super::schema::ProbeSection;

pub(super) fn load_probe_config(probe: Option<&ProbeSection>) -> Result<ProbeConfig> {
    let http = probe
        .and_then(|p| p.http.as_ref())
        .map(|http| {
            let urls = match (&http.urls, &http.url) {
                (Some(list), _) if !list.is_empty() => list.clone(),
                (_, Some(single)) => vec![single.clone()],
                _ => return Err(anyhow::anyhow!(
                    "[probe.http] requires `url = \"...\"` or `urls = [...]`"
                )),
            };
            HttpProbeConfig::new(urls).context("invalid [probe.http]")
        })
        .transpose()?;
    let dns = probe.and_then(|p| p.dns.as_ref()).map(|dns| DnsProbeConfig {
        server: dns.server.clone(),
        port: dns.port.unwrap_or(53),
        name: dns.name.clone().unwrap_or_else(|| "example.com".to_string()),
    });
    let tcp = probe.and_then(|p| p.tcp.as_ref()).map(|tcp| TcpProbeConfig {
        host: tcp.host.clone(),
        port: tcp.port.unwrap_or(80),
    });
    let tls = probe
        .and_then(|p| p.tls.as_ref())
        .map(|tls| -> Result<TlsProbeConfig> {
            let raw = match (&tls.targets, &tls.target) {
                (Some(list), _) if !list.is_empty() => list.clone(),
                (_, Some(single)) => vec![single.clone()],
                _ => {
                    return Err(anyhow::anyhow!(
                        "[probe.tls] requires `target = \"host:port\"` or `targets = [...]`"
                    ));
                },
            };
            let targets: Result<Vec<TlsProbeTarget>> = raw
                .iter()
                .map(|spec| parse_tls_target(spec))
                .collect();
            TlsProbeConfig::new(targets?).context("invalid [probe.tls]")
        })
        .transpose()?;

    // Defaults chosen to be safe for upstream Shadowsocks stacks that apply
    // per-IP rate limits / replay-filter back-pressure on a burst of fresh
    // handshakes.  Each probe cycle opens at least one fresh WS connection
    // per uplink per enabled sub-probe (ws/http/dns/tcp), and all uplinks
    // are probed in parallel — at interval=30 s with attempts=2 this easily
    // put ~8 simultaneous handshakes on the wire every 30 s on a 2-uplink
    // deployment, which was observed in the field to overlap bursty
    // real-user traffic and cause cascading chunk-0 "Connection reset
    // without closing handshake" failures.  The larger defaults spread that
    // load out by ~4× while still detecting uplink failures inside a
    // couple of minutes.
    let interval_secs = probe.and_then(|p| p.interval_secs).unwrap_or(120);
    let attempts = probe.and_then(|p| p.attempts).unwrap_or(1).max(1);
    if interval_secs < 60 {
        warn!(
            probe_interval_secs = interval_secs,
            "probe interval below 60 s: frequent probe handshakes can trip upstream rate limits \
             and cause spurious chunk-0 failures; consider 120 s unless you know the upstream \
             tolerates it"
        );
    }
    if attempts > 1 {
        warn!(
            probe_attempts = attempts,
            "probe.attempts > 1 multiplies handshakes per cycle; min_failures already gates noisy \
             failover — consider leaving attempts=1 unless the link is intrinsically flaky"
        );
    }
    Ok(ProbeConfig {
        interval: Duration::from_secs(interval_secs),
        timeout: Duration::from_secs(probe.and_then(|p| p.timeout_secs).unwrap_or(10)),
        max_concurrent: probe.and_then(|p| p.max_concurrent).unwrap_or(4).max(1),
        max_dials: probe.and_then(|p| p.max_dials).unwrap_or(2).max(1),
        min_failures: probe.and_then(|p| p.min_failures).unwrap_or(3).max(1),
        attempts,
        ws: WsProbeConfig {
            enabled: probe
                .and_then(|p| p.ws.as_ref())
                .and_then(|ws| ws.enabled)
                .unwrap_or(false),
        },
        http,
        dns,
        tcp,
        tls,
    })
}

/// Parse a `"host:port"` (or bare `"host"`) probe target. Bare host defaults
/// to port 443 — the natural choice for a TLS-handshake probe. IPv6 literals
/// must be bracketed (`[::1]:443`); the bracket-aware split happens before
/// the `:` lookup so unbracketed `::1:443` would be rejected as an invalid
/// host, which mirrors what the operator likely meant.
fn parse_tls_target(spec: &str) -> Result<TlsProbeTarget> {
    let (host, port_opt) = if let Some(rest) = spec.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("tls probe target {spec:?} has unbalanced `[`"))?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        if after.is_empty() {
            (host, None)
        } else {
            let port_str = after
                .strip_prefix(':')
                .ok_or_else(|| anyhow::anyhow!("tls probe target {spec:?}: expected `:port` after `]`"))?;
            (host, Some(port_str))
        }
    } else if let Some((host, port_str)) = spec.rsplit_once(':') {
        (host.to_string(), Some(port_str))
    } else {
        (spec.to_string(), None)
    };

    let port = match port_opt {
        Some(s) => s
            .parse::<u16>()
            .with_context(|| format!("tls probe target {spec:?}: invalid port {s:?}"))?,
        None => 443,
    };
    if host.is_empty() {
        return Err(anyhow::anyhow!("tls probe target {spec:?}: empty host"));
    }
    Ok(TlsProbeTarget { host, port })
}
