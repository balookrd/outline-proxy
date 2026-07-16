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
use tokio::time::timeout;
use tracing::{debug, warn};

use outline_transport::DnsCache;

use crate::config::{ProbeConfig, UplinkConfig};

use super::super::super::probe::probe_uplink;
use super::super::super::types::{TransportKind, Uplink, UplinkManager};

/// One plane's (TCP or UDP) fallback-wire probe result, as far as that
/// wire's carrier-descent slot is concerned.
///
/// The two flags are deliberately a struct rather than positional `bool`s:
/// they mean opposite halves of the split 7196a62d drew — `carrier_ok` is
/// the handshake to *our* uplink server (the only thing allowed to move the
/// cascade), `site_ok` is reachability of a real edge *through* the tunnel
/// (health and rotation only) — and transposing them at a call site would
/// silently resurrect that bug.
pub(super) struct WireProbePlane {
    /// The carrier this probe actually asked for: the wire's effective mode.
    pub(super) dialed_mode: crate::config::TransportMode,
    pub(super) carrier_ok: bool,
    pub(super) site_ok: bool,
    pub(super) downgraded_from: Option<crate::config::TransportMode>,
}

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
    /// Advance this wire's own probe streaks (a success zeroes the failure
    /// streak and vice versa), lazily creating the slot.
    ///
    /// These are per-wire on purpose: `PerTransportStatus::consecutive_*`
    /// count the *primary* probe's outcomes, so reusing them would let
    /// primary's failures gate a fallback's descent and primary's successes
    /// walk a fallback's cap up.
    fn bump_wire_probe_streak(
        &self,
        index: usize,
        transport: TransportKind,
        wire_index: u8,
        success: bool,
    ) {
        if wire_index == 0 {
            return;
        }
        let slot_idx = (wire_index - 1) as usize;
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            while per.fallback_mode_downgrades.len() <= slot_idx {
                per.fallback_mode_downgrades
                    .push(crate::manager::status::ModeDowngradeSlot::default());
            }
            let slot = &mut per.fallback_mode_downgrades[slot_idx];
            if success {
                slot.probe_failures = 0;
                slot.probe_successes = slot.probe_successes.saturating_add(1);
            } else {
                slot.probe_successes = 0;
                slot.probe_failures = slot.probe_failures.saturating_add(1);
            }
        });
    }

    /// Feed one plane's fallback-wire probe result into that wire's
    /// carrier-descent slot.
    ///
    /// `dialed_mode` is the carrier this probe actually asked for — the
    /// wire's *effective* mode, i.e. its cap when one is installed. Passing
    /// the configured mode instead would pin the cascade one rank below
    /// configured forever: every cycle would re-derive the same first step
    /// and the cap would never reach the floor that releases wire rotation.
    ///
    /// Three outcomes, in precedence order:
    ///
    /// * the dial silently fell back (`downgraded_from`) — record it
    ///   against the rank actually requested;
    /// * the carrier handshake failed — descend one rank below what was
    ///   dialed, and tick this wire's probe-failure streak (which gates
    ///   further descent at the capped rank);
    /// * carrier up and the probe reached its target (`site_ok`) — count a
    ///   success for this wire and let the walk-up claw a rank back.
    ///
    /// A live carrier with a failed target (`carrier_ok && !site_ok`) is
    /// deliberately inert here: that is the exit leg, not the carrier — the
    /// distinction 7196a62d drew. It does not tick either streak, so it can
    /// neither push the cap down nor walk it up.
    fn note_fallback_wire_carrier_outcome(
        &self,
        index: usize,
        transport: TransportKind,
        wire_index: u8,
        plane: WireProbePlane,
    ) {
        use crate::manager::mode_downgrade::ModeDowngradeTrigger;

        if let Some(requested) = plane.downgraded_from {
            self.bump_wire_probe_streak(index, transport, wire_index, false);
            self.extend_mode_downgrade_for_wire(
                index,
                transport,
                wire_index,
                ModeDowngradeTrigger::SilentTransportFallback(requested),
            );
        } else if !plane.carrier_ok {
            self.bump_wire_probe_streak(index, transport, wire_index, false);
            self.extend_mode_downgrade_for_wire(
                index,
                transport,
                wire_index,
                ModeDowngradeTrigger::ProbeTransportFailure(plane.dialed_mode),
            );
        } else if plane.site_ok {
            self.bump_wire_probe_streak(index, transport, wire_index, true);
            self.walk_up_mode_downgrade_for_wire(index, transport, wire_index);
        }
    }

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

        let total_wires = 1 + uplink.fallbacks.len();
        let wire_index_u8 = u8::try_from(wire_index).unwrap_or(u8::MAX);
        // Dial what a real session on this wire would dial: the wire's own
        // effective carrier, i.e. its cap while one is installed. Probing the
        // configured rank instead would both misreport this wire's health
        // (a doomed handshake at a rank traffic no longer uses) and stall the
        // cascade — every cycle's failure would re-derive the same one-step
        // cap, so it could never reach the floor that releases wire rotation.
        let effective_tcp_mode = self.effective_tcp_mode_for_wire(index, wire_index_u8).await;
        let effective_udp_mode = self.effective_udp_mode_for_wire(index, wire_index_u8).await;

        let result = match timeout(
            probe
                .timeout
                .saturating_mul(2)
                .saturating_add(std::time::Duration::from_secs(1)),
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
                self.record_wire_outcome(
                    index,
                    TransportKind::Tcp,
                    wire_index_u8,
                    false,
                    total_wires,
                );
                if uplink.supports_udp() {
                    self.record_wire_outcome(
                        index,
                        TransportKind::Udp,
                        wire_index_u8,
                        false,
                        total_wires,
                    );
                }
                return;
            },
            Err(_) => {
                warn!(
                    uplink = %uplink.name,
                    wire_index,
                    "fallback-wire probe timed out",
                );
                self.record_wire_outcome(
                    index,
                    TransportKind::Tcp,
                    wire_index_u8,
                    false,
                    total_wires,
                );
                if uplink.supports_udp() {
                    self.record_wire_outcome(
                        index,
                        TransportKind::Udp,
                        wire_index_u8,
                        false,
                        total_wires,
                    );
                }
                return;
            },
        };

        let alpha = self.inner.load_balancing.rtt_ewma_alpha;
        self.inner.with_status_mut(index, |status| {
            if result.tcp_ok {
                // Per-wire RTT EWMA: feed the fallback-wire probe latency
                // into this wire's slot so cross-uplink scoring uses the
                // wire that's actually carrying traffic, not primary's
                // (now-stale) measurement. The any-wire liveness stamp is
                // applied via `mark_wire_data_proven` below.
                status
                    .tcp
                    .record_fallback_wire_latency(wire_index_u8, result.tcp_latency, alpha);
            }
            if result.udp_applicable && result.udp_ok {
                status
                    .udp
                    .record_fallback_wire_latency(wire_index_u8, result.udp_latency, alpha);
            }
        });
        // Carrier bookkeeping for this wire's own descent stack. Kept
        // strictly separate from the health/rotation bookkeeping below, and
        // keyed on `*_carrier_ok` — NOT `*_ok` — for the same reason the
        // primary path is: the cascade rewrites the outer carrier between us
        // and the uplink server, so only a failure of *that* handshake may
        // drive it. A dead exit leg fails `*_ok` while `*_carrier_ok` stays
        // true; capping there would strand this wire on a slower carrier
        // without touching the problem, which lives past the uplink server.
        //
        // Without this, a fallback wire's carrier stack never moved: the
        // dial path only writes the slot when a dial actually falls back,
        // and nothing else here fed the descent machinery. That left
        // `wire_is_at_carrier_floor` reading a configured-rank slot forever,
        // so under `shuffle_wires` this probe could never rotate off a wire
        // whose carrier is broken — the very case it exists to catch on a
        // passive uplink.
        self.note_fallback_wire_carrier_outcome(
            index,
            TransportKind::Tcp,
            wire_index_u8,
            WireProbePlane {
                dialed_mode: effective_tcp_mode,
                carrier_ok: result.tcp_carrier_ok,
                site_ok: result.tcp_ok,
                downgraded_from: result.tcp_downgraded_from,
            },
        );
        if result.udp_applicable {
            self.note_fallback_wire_carrier_outcome(
                index,
                TransportKind::Udp,
                wire_index_u8,
                WireProbePlane {
                    dialed_mode: effective_udp_mode,
                    carrier_ok: result.udp_carrier_ok,
                    site_ok: result.udp_ok,
                    downgraded_from: result.udp_downgraded_from,
                },
            );
        }
        // Per-transport outcome of the fallback-wire probe. A success here
        // reached the probe's external target, so it is *proven delivery*, not
        // a bare handshake: `mark_wire_data_proven` stamps the any-wire liveness
        // timestamp and resets the `shuffle_wires` round counter. A failure
        // feeds `record_wire_outcome`, which increments `active_wire_streak`
        // when the failed wire matches the current active wire and, once the
        // streak crosses `min_failures`, advances `active_wire` to the next wire
        // in the chain. This is the only path that moves sticky off a fallback
        // wire on a passive uplink (no client traffic to drive the dial path).
        if result.tcp_ok {
            self.mark_wire_data_proven(index, TransportKind::Tcp);
        } else {
            self.record_wire_outcome(index, TransportKind::Tcp, wire_index_u8, false, total_wires);
        }
        if result.udp_applicable {
            if result.udp_ok {
                self.mark_wire_data_proven(index, TransportKind::Udp);
            } else {
                self.record_wire_outcome(
                    index,
                    TransportKind::Udp,
                    wire_index_u8,
                    false,
                    total_wires,
                );
            }
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
