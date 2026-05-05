//! Warm-probe keepalive loop.
//!
//! Periodically tickles the cached probe pipes for VLESS uplinks (see
//! [`super::warm_udp`] / [`super::warm_tcp`]) so the server-side state
//! that makes them cheap — UDP NAT entry, HTTP keep-alive socket, WS
//! framing — survives the gap between regular probe cycles even when
//! `probe.interval` exceeds the upstream idle timeout.
//!
//! An empty slot is a no-op: keepalive never dials. The next regular
//! probe cycle is responsible for filling the slot fresh. Failed
//! keepalive ticks drop the cached pipe so the next regular probe also
//! re-dials cleanly.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;
use tracing::debug;

use crate::config::UplinkTransport;
use crate::probe::dns::build_dns_query;
use crate::probe::http::build_http_probe_request;
use crate::types::UplinkManager;

use super::warm_tcp;
use super::warm_udp;

impl UplinkManager {
    /// Spawn the warm-probe keepalive task.
    ///
    /// Cheap when there is nothing to do: an idle slot returns
    /// immediately, a non-VLESS uplink is skipped without locking
    /// anything. Disabled entirely when
    /// `load_balancing.warm_probe_keepalive_interval` is `None`.
    pub fn spawn_warm_probe_keepalive_loop(&self) {
        let interval = match self.inner.load_balancing.warm_probe_keepalive_interval {
            Some(d) if !d.is_zero() => d,
            _ => return,
        };
        // Run only when the regular HTTP/DNS probes are configured —
        // there is no point keeping a slot warm that no probe ever
        // populates.
        let probe = self.inner.probe.clone();
        if probe.dns.is_none() && probe.http.is_none() {
            return;
        }
        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(interval) => {}
                }
                manager.tick_warm_probe_keepalive(&probe).await;
            }
        });
    }

    async fn tick_warm_probe_keepalive(&self, probe: &crate::config::ProbeConfig) {
        // Pre-build the wire payloads once per tick: every uplink uses
        // the same probe configuration, and the build cost is dominated
        // by a few small allocations rather than the round-trip itself.
        let dns_query: Option<Arc<Vec<u8>>> = probe
            .dns
            .as_ref()
            .map(|cfg| Arc::new(build_dns_query(&cfg.name)));
        let http_request: Option<Arc<Vec<u8>>> = probe.http.as_ref().and_then(|cfg| {
            let host = cfg.url.host_str()?;
            let port = cfg.url.port_or_known_default().unwrap_or(80);
            let mut path = if cfg.url.path().is_empty() {
                "/".to_string()
            } else {
                cfg.url.path().to_string()
            };
            if let Some(q) = cfg.url.query() {
                path.push('?');
                path.push_str(q);
            }
            Some(Arc::new(build_http_probe_request(host, port, &path).into_bytes()))
        });

        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            if !matches!(uplink.transport, UplinkTransport::Vless) {
                continue;
            }
            // UDP keepalive.
            if let Some(query) = dns_query.as_ref() {
                let slot = self.inner.warm_udp_probe_slot(index);
                let kept = tokio::time::timeout(
                    keepalive_per_tick_timeout(probe.timeout),
                    warm_udp::keepalive_tick(slot, query),
                )
                .await
                .unwrap_or(false);
                debug!(
                    uplink = %uplink.name,
                    transport = "udp",
                    probe = "warm_keepalive",
                    kept,
                    "warm UDP probe keepalive tick"
                );
            }
            // TCP keepalive.
            if let Some(request) = http_request.as_ref() {
                let slot = self.inner.warm_tcp_probe_slot(index);
                let kept = tokio::time::timeout(
                    keepalive_per_tick_timeout(probe.timeout),
                    warm_tcp::keepalive_tick(slot, request),
                )
                .await
                .unwrap_or(false);
                debug!(
                    uplink = %uplink.name,
                    transport = "tcp",
                    probe = "warm_keepalive",
                    kept,
                    "warm TCP probe keepalive tick"
                );
            }
        }
    }
}

/// Cap each per-slot keepalive at the configured probe timeout (or 5 s
/// when the probe has no timeout). Stops a wedged warm transport from
/// blocking other uplinks' keepalives in the same tick.
fn keepalive_per_tick_timeout(probe_timeout: Duration) -> Duration {
    if probe_timeout.is_zero() {
        Duration::from_secs(5)
    } else {
        probe_timeout
    }
}
