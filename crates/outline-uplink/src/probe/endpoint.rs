//! Endpoint-reachability short-circuit for the probe loop.
//!
//! The normal escalation path treats every failure as potentially
//! carrier-specific: a wire first walks its downgrade stack (`h3 → h2 → h1`,
//! each rank held for `mode_downgrade_secs`), then the chain rotates to the
//! next wire, and only a fully-exhausted round may flip uplink health. That is
//! the right shape when a *carrier* is being blocked — and exactly the wrong
//! shape when the host itself is gone: every wire of the uplink usually dials
//! the same `host:port`, so the whole walk is a slow rediscovery of one fact,
//! with each step paying the full `probe.timeout` (a blackholed SYN never
//! comes back with an RST).
//!
//! This module answers that one fact directly and cheaply: a bare TCP connect
//! against each distinct endpoint of the uplink, run concurrently, with a
//! deadline far below `probe.timeout`. When every endpoint fails, the caller
//! may declare the uplink down without walking anything.
//!
//! Deliberately *not* a health signal on its own: a completed TCP handshake
//! says nothing about the carrier or the tunnel behind it, so a reachable
//! endpoint only means "keep probing normally". The check is one-directional —
//! it can condemn, never absolve.

use std::collections::HashSet;
use std::time::Duration;

use futures_util::future::join_all;
use tokio::time::{Instant, timeout};
use url::Url;

use outline_transport::{DnsCache, connect_tcp_socket, resolve_host_with_preference};

use crate::config::UplinkConfig;

/// One dial target of an uplink: where a wire connects, plus the egress knobs
/// needed to get there the way real traffic would.
///
/// The network options are part of the identity, not decoration: a fallback
/// wire carrying its own `fwmark` / `ipv6_first` reaches the same `host:port`
/// over a different route, so it deserves its own connect rather than being
/// deduplicated away behind the primary's verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) ipv6_first: bool,
    pub(crate) fwmark: Option<u32>,
}

impl Endpoint {
    pub(crate) fn label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Distinct endpoints across every wire of `uplink` (primary + fallbacks,
/// both planes), keeping only URLs whose scheme satisfies `keep`. Wire order
/// is preserved — primary first, then each fallback — so both the log line
/// and the `last_error` chip read the way the operator wrote the config.
///
/// The single place that knows how to enumerate where an uplink dials —
/// reachability wants every wire, the certificate check wants the TLS ones
/// (`wire_tls_endpoints`), and neither should have to be taught again about a
/// future URL field.
pub(crate) fn wire_endpoints(uplink: &UplinkConfig, keep: impl Fn(&str) -> bool) -> Vec<Endpoint> {
    let mut seen: HashSet<Endpoint> = HashSet::new();
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut push = |url: Option<&Url>, ipv6_first: bool, fwmark: Option<u32>| {
        if let Some(url) = url
            && keep(url.scheme())
            && let Some(host) = url.host_str()
            && let Some(port) = url.port_or_known_default()
        {
            let endpoint = Endpoint {
                host: host.to_string(),
                port,
                ipv6_first,
                fwmark,
            };
            if seen.insert(endpoint.clone()) {
                endpoints.push(endpoint);
            }
        }
    };
    push(uplink.tcp_dial_url(), uplink.ipv6_first, uplink.fwmark);
    push(uplink.udp_dial_url(), uplink.ipv6_first, uplink.fwmark);
    for fallback in &uplink.fallbacks {
        push(fallback.tcp_dial_url(), fallback.ipv6_first, fallback.fwmark);
        push(fallback.udp_dial_url(), fallback.ipv6_first, fallback.fwmark);
    }
    endpoints
}

/// Every endpoint of the uplink, whatever the carrier — the reachability
/// check dials a socket, and a socket does not care about the scheme on top.
fn uplink_endpoints(uplink: &UplinkConfig) -> Vec<Endpoint> {
    wire_endpoints(uplink, |_| true)
}

/// The subset that presents a TLS certificate. Plain `ws`/`http` and raw
/// Shadowsocks wires carry none, so a pure-Shadowsocks uplink yields nothing
/// and the cert-check loop skips it.
#[cfg(feature = "cert-check")]
pub(crate) fn wire_tls_endpoints(uplink: &UplinkConfig) -> Vec<Endpoint> {
    wire_endpoints(uplink, |scheme| matches!(scheme, "wss" | "https"))
}

/// Bare TCP connect against one endpoint, bounded by `deadline` end to end
/// (resolution included — a host that stopped resolving is unreachable for
/// this purpose too).
///
/// Recorded under `probe="endpoint"` so the check's own cost and outcome are
/// visible next to the regular sub-probes.
async fn endpoint_reachable(
    cache: &DnsCache,
    group: &str,
    uplink: &str,
    endpoint: &Endpoint,
    deadline: Duration,
) -> bool {
    let started = Instant::now();
    let reachable = timeout(deadline, async {
        let addrs = resolve_host_with_preference(
            cache,
            &endpoint.host,
            endpoint.port,
            "endpoint reachability check",
            endpoint.ipv6_first,
        )
        .await
        .ok()?;
        for addr in addrs.iter() {
            if connect_tcp_socket(*addr, endpoint.fwmark).await.is_ok() {
                return Some(());
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .is_some();
    outline_metrics::record_probe(group, uplink, "tcp", "endpoint", reachable, started.elapsed());
    reachable
}

/// Run the reachability check across every endpoint of `uplink` concurrently.
///
/// Returns `Some(labels)` — a comma-separated `host:port` list for logs and
/// `last_error` — only when *all* of them failed; `None` when at least one
/// answered, or when the uplink has no dial URL to check at all. The
/// all-or-nothing rule is what keeps a partially-broken uplink (one dead
/// fallback host among several) on the normal per-wire path.
pub(crate) async fn unreachable_uplink_endpoints(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    deadline: Duration,
) -> Option<String> {
    let endpoints = uplink_endpoints(uplink);
    if endpoints.is_empty() {
        return None;
    }
    let verdicts = join_all(
        endpoints
            .iter()
            .map(|endpoint| endpoint_reachable(cache, group, &uplink.name, endpoint, deadline)),
    )
    .await;
    if verdicts.iter().any(|reachable| *reachable) {
        return None;
    }
    let labels: Vec<String> = endpoints.iter().map(Endpoint::label).collect();
    Some(labels.join(", "))
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
