//! Per-wire probe walks for multi-wire uplinks.
//!
//! The default probe path always targets the **primary** wire of an uplink
//! (see [`UplinkConfig::tcp_dial_url`] / [`UplinkConfig::udp_dial_url`] —
//! both ignore `active_wire` and `fallbacks`). This module adds a follow-up
//! probe pass that targets the currently-active **fallback** wire whenever
//! primary has just been observed unhealthy, so:
//!
//! * `last_any_wire_success` (the liveness override consulted by
//!   `selection_health` and `compute_health_effective`) gets stamped from
//!   the probe path — not just from a successful client dial. This lifts the
//!   passive-uplink dead-zone where, with no client traffic flowing through
//!   the uplink, the fallback wire never had a chance to prove itself.
//! * The dashboard / Prometheus `tcp_health_effective` flips green for an
//!   uplink whose primary is probe-dead but whose fallback is reachable —
//!   matching what selection sees, even when the uplink is currently passive
//!   and carrying no client sessions.
//!
//! Bypasses warm-standby slots (those are keyed on the parent's primary wire
//! shape) and skips parent-level penalty / cooldown bookkeeping — that
//! scoring state is sized for the primary's traffic patterns. The
//! fallback-wire probe DOES feed its measured latency into a per-wire RTT
//! EWMA slot (`PerTransportStatus::fallback_rtt_ewma`), so cross-uplink
//! scoring against the active wire ranks this uplink by the wire actually
//! carrying traffic, not by primary's stale (or now-broken) measurement.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use outline_transport::DnsCache;

use crate::config::{ProbeConfig, UplinkConfig};

use super::super::super::probe::probe_uplink;
use super::super::super::types::{TransportKind, Uplink, UplinkManager};

/// Decide which fallback wire to probe in this cycle. Returns `None` when
/// the uplink has no fallbacks or no fallback should be probed.
///
/// The wire we want is whichever one new sessions would actually land on if
/// they came in right now: that is `active_wire` when it is on a fallback,
/// or the first fallback (`1`) when `active_wire` is still `0` because the
/// failure streak has not yet reached `min_failures`. Probing the latter
/// case anyway means an uplink whose primary is failing from the very first
/// probe (no streak built up yet) still gets its fallback validated within
/// the same cycle, so `effective_health` flips green without a long
/// streak-accrual delay.
fn target_wire_for_fallback_probe(
    uplink: &UplinkConfig,
    active_wire_tcp: u8,
    active_wire_udp: u8,
) -> Option<usize> {
    if uplink.fallbacks.is_empty() {
        return None;
    }
    let max_active = active_wire_tcp.max(active_wire_udp) as usize;
    let target = max_active.max(1);
    if target > uplink.fallbacks.len() {
        // Shouldn't happen — `active_wire` is bounded by total wires — but
        // be defensive against future changes that might race against
        // configuration reloads.
        return None;
    }
    Some(target)
}

impl UplinkManager {
    /// Run a probe against the active fallback wire of `uplink`, after
    /// the primary probe has been observed unhealthy this cycle. Stamps
    /// `last_any_wire_success` for each transport that the fallback-wire
    /// probe verifies as reachable.
    ///
    /// The caller decides whether the primary outcome warrants a
    /// fallback walk; this function is the executor and is a no-op when
    /// the uplink has no fallbacks (so single-wire uplinks pay no cost
    /// even if the caller is sloppy with the gate).
    pub(crate) async fn run_fallback_wire_probe(
        &self,
        index: usize,
        uplink: &Uplink,
        dns_cache: Arc<DnsCache>,
        probe: ProbeConfig,
        dial_limit: Arc<Semaphore>,
    ) {
        if uplink.fallbacks.is_empty() {
            return;
        }
        let (active_tcp, active_udp) = {
            let status = self.inner.read_status(index);
            (status.tcp.active_wire, status.udp.active_wire)
        };
        let Some(wire_index) = target_wire_for_fallback_probe(uplink, active_tcp, active_udp)
        else {
            return;
        };
        let Some(wire_view) = uplink.wire_view(wire_index) else {
            return;
        };

        let effective_tcp_mode = wire_view.tcp_dial_mode();
        let effective_udp_mode = wire_view.udp_dial_mode();

        let total_wires = 1 + uplink.fallbacks.len();
        let wire_index_u8 = u8::try_from(wire_index).unwrap_or(u8::MAX);

        let result = match timeout(
            probe.timeout.saturating_mul(2).saturating_add(std::time::Duration::from_secs(1)),
            probe_uplink(
                &dns_cache,
                &self.inner.group_name,
                &wire_view,
                &probe,
                dial_limit,
                effective_tcp_mode,
                effective_udp_mode,
                None,
                None,
            ),
        )
        .await
        {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                debug!(
                    uplink = %uplink.name,
                    wire_index,
                    error = %error,
                    "fallback-wire probe failed",
                );
                // The active fallback wire failed at the probe-machinery
                // level (handshake error / TLS reject / etc.). Without this,
                // a passive uplink whose fallback silently breaks would
                // stay pinned to the dead wire forever — neither the dial
                // loop (no traffic to drive `record_wire_outcome`) nor the
                // primary probe (still pointing at wire 0) sees the
                // failure. Feeding the outcome through `record_wire_outcome`
                // reuses the existing per-wire streak machinery: when
                // `min_failures` consecutive fallback-wire probes fail,
                // the active wire advances to the next wire in the chain,
                // mirroring how a real client dial would push it forward.
                self.record_wire_outcome(index, TransportKind::Tcp, wire_index_u8, false, total_wires);
                if uplink.supports_udp() {
                    self.record_wire_outcome(index, TransportKind::Udp, wire_index_u8, false, total_wires);
                }
                return;
            },
            Err(_) => {
                warn!(
                    uplink = %uplink.name,
                    wire_index,
                    "fallback-wire probe timed out",
                );
                self.record_wire_outcome(index, TransportKind::Tcp, wire_index_u8, false, total_wires);
                if uplink.supports_udp() {
                    self.record_wire_outcome(index, TransportKind::Udp, wire_index_u8, false, total_wires);
                }
                return;
            },
        };

        let now = Instant::now();
        let alpha = self.inner.load_balancing.rtt_ewma_alpha;
        self.inner.with_status_mut(index, |status| {
            if result.tcp_ok {
                status.tcp.last_any_wire_success = Some(now);
                // Per-wire RTT EWMA: feed the fallback-wire probe latency
                // into this wire's slot so cross-uplink scoring uses the
                // wire that's actually carrying traffic, not primary's
                // (now-stale) measurement.
                status
                    .tcp
                    .record_fallback_wire_latency(wire_index_u8, result.tcp_latency, alpha);
            }
            if result.udp_applicable && result.udp_ok {
                status.udp.last_any_wire_success = Some(now);
                status
                    .udp
                    .record_fallback_wire_latency(wire_index_u8, result.udp_latency, alpha);
            }
        });
        // Per-transport outcome of the fallback-wire probe. `record_wire_outcome`
        // increments `active_wire_streak` on `success=false` when the failed
        // wire matches the current active wire and resets it on any success;
        // when the streak crosses `min_failures` it advances `active_wire`
        // to the next wire in the chain. This is the only path that moves
        // sticky off a fallback wire on a passive uplink (no client traffic
        // to drive `record_wire_outcome` from the dial path).
        self.record_wire_outcome(index, TransportKind::Tcp, wire_index_u8, result.tcp_ok, total_wires);
        if result.udp_applicable {
            self.record_wire_outcome(index, TransportKind::Udp, wire_index_u8, result.udp_ok, total_wires);
        }
        debug!(
            uplink = %uplink.name,
            wire_index,
            tcp_ok = result.tcp_ok,
            udp_ok = result.udp_ok,
            udp_applicable = result.udp_applicable,
            "fallback-wire probe completed",
        );
    }
}

#[cfg(test)]
#[path = "tests/wire.rs"]
mod tests;
