//! Periodic per-uplink TLS certificate-expiry check.
//!
//! Opens a direct (non-tunnel) TLS connection to each uplink endpoint via
//! [`outline_transport::cert_check`], reads the leaf certificate's `notAfter`,
//! and records the soonest expiry across the uplink's wires into
//! [`UplinkStatus::cert_not_after_unix_ms`]. The control topology / dashboard
//! and a Prometheus gauge surface it so an operator is warned *before* an
//! expired cert silently breaks the uplink — every wire of an uplink shares
//! the same endpoint certificate, so expiry takes the whole uplink down at
//! once.
//!
//! Deliberately separate from the data-path probe loop: this is a low-rate
//! background check that dials the uplink server directly (rather than
//! validating an external SNI *through* the tunnel) and never contends the
//! probe semaphore or feeds the probe / runtime health signals.

#[cfg(feature = "cert-check")]
use std::collections::HashSet;
#[cfg(feature = "cert-check")]
use std::time::Duration;

#[cfg(feature = "cert-check")]
use tokio::time::sleep;
#[cfg(feature = "cert-check")]
use tracing::{debug, warn};

#[cfg(feature = "cert-check")]
use crate::config::UplinkConfig;
use crate::types::UplinkManager;

/// How often the loop re-reads every uplink's endpoint certificates.
/// Certificates rotate on the order of weeks/months, so a slow cadence keeps
/// the proactive warning fresh at negligible cost.
#[cfg(feature = "cert-check")]
const CERT_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// A distinct TLS endpoint an uplink dials, with the egress knobs needed to
/// reach it the same way real traffic would.
#[cfg(feature = "cert-check")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertEndpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) fwmark: Option<u32>,
    pub(crate) ipv6_first: bool,
}

/// Collect the unique `wss`/`https` endpoints an uplink dials across every
/// wire (primary + fallbacks), deduped by `(host, port)`. Plain `ws`/`http`
/// and Shadowsocks wires carry no TLS certificate and contribute nothing — so
/// a pure-Shadowsocks uplink yields an empty list and is skipped by the loop.
#[cfg(feature = "cert-check")]
pub(crate) fn uplink_tls_endpoints(uplink: &UplinkConfig) -> Vec<CertEndpoint> {
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    let mut endpoints = Vec::new();
    let total_wires = 1 + uplink.fallbacks.len();
    for wire_index in 0..total_wires {
        let Some(view) = uplink.wire_view(wire_index) else {
            continue;
        };
        for url in [view.tcp_dial_url(), view.udp_dial_url()].into_iter().flatten() {
            if !matches!(url.scheme(), "wss" | "https") {
                continue;
            }
            let Some(host) = url.host_str() else {
                continue;
            };
            let port = url.port_or_known_default().unwrap_or(443);
            if seen.insert((host.to_string(), port)) {
                endpoints.push(CertEndpoint {
                    host: host.to_string(),
                    port,
                    fwmark: view.fwmark,
                    ipv6_first: view.ipv6_first,
                });
            }
        }
    }
    endpoints
}

impl UplinkManager {
    /// Spawn the background cert-check loop: one pass immediately, then every
    /// [`CERT_CHECK_INTERVAL`], until shutdown.
    #[cfg(feature = "cert-check")]
    pub fn spawn_cert_check_loop(&self) {
        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            manager.check_all_certs().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(CERT_CHECK_INTERVAL) => {}
                }
                manager.check_all_certs().await;
            }
        });
    }

    /// No-op when cert checking is compiled out (e.g. router builds): the
    /// status field stays `None` and nothing pulls the X.509 parser. Keeps
    /// the bootstrap / registry call sites unconditional.
    #[cfg(not(feature = "cert-check"))]
    pub fn spawn_cert_check_loop(&self) {}

    /// One cert-check pass over every uplink. For each uplink, read the
    /// `notAfter` of every distinct TLS endpoint and record the soonest into
    /// status. Endpoints that fail to handshake are logged and skipped; if
    /// *all* of an uplink's endpoints fail this cycle the stored value is left
    /// untouched (a transient DNS / network blip must not erase a known
    /// expiry).
    #[cfg(feature = "cert-check")]
    async fn check_all_certs(&self) {
        for index in 0..self.inner.uplinks.len() {
            let (name, endpoints) = {
                let uplink = &self.inner.uplinks[index];
                (uplink.name.clone(), uplink_tls_endpoints(uplink))
            };
            if endpoints.is_empty() {
                continue;
            }
            let mut soonest: Option<u64> = None;
            for ep in &endpoints {
                match outline_transport::cert_check::fetch_leaf_cert_not_after_unix_ms(
                    &self.inner.dns_cache,
                    &ep.host,
                    ep.port,
                    ep.fwmark,
                    ep.ipv6_first,
                )
                .await
                {
                    Ok(ms) => soonest = Some(soonest.map_or(ms, |cur| cur.min(ms))),
                    Err(error) => warn!(
                        uplink = %name,
                        host = %ep.host,
                        port = ep.port,
                        error = %format!("{error:#}"),
                        "cert-check: failed to read endpoint certificate"
                    ),
                }
            }
            if let Some(ms) = soonest {
                self.inner.with_status_mut(index, |status| {
                    status.cert_not_after_unix_ms = Some(ms);
                });
                debug!(
                    uplink = %name,
                    not_after_unix_ms = ms,
                    endpoints = endpoints.len(),
                    "cert-check: recorded uplink certificate expiry"
                );
            }
        }
    }
}

#[cfg(all(test, feature = "cert-check"))]
#[path = "cert_check/tests/cert_check.rs"]
mod tests;
