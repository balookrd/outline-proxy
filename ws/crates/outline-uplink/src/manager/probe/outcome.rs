use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{LoadBalancingConfig, UplinkTransport, TransportMode};

use super::super::super::penalty::{add_penalty, update_rtt_ewma};
use super::super::super::types::{TransportKind, Uplink, UplinkManager};
use super::super::status::PerTransportStatus;
use super::super::mode_downgrade::ModeDowngradeTrigger;

#[derive(Debug)]
pub(crate) struct ProbeOutcome {
    pub(crate) tcp_ok: bool,
    /// false when the uplink has no `udp_ws_url` — means "UDP not applicable",
    /// not "UDP probe failed".  Health and standby tracking are skipped in
    /// this case so that Grafana shows empty (unknown) rather than red (0).
    pub(crate) udp_ok: bool,
    pub(crate) udp_applicable: bool,
    pub(crate) tcp_latency: Option<Duration>,
    pub(crate) udp_latency: Option<Duration>,
    /// `Some(requested)` when any TCP probe sub-attempt produced a stream
    /// at a lower mode than asked for (host-level `ws_mode_cache` clamp or
    /// inline H3→H2/H1 fallback inside `connect_websocket_with_resume`).
    /// `None` when the dial path matched the requested mode. Surfaced from
    /// the probe layer so the manager mirrors the downgrade into the
    /// per-uplink `mode_downgrade_until` window even when the probe itself
    /// succeeded — without this, `effective_*_ws_mode` would silently lag
    /// behind the actual transport state.
    pub(crate) tcp_downgraded_from: Option<TransportMode>,
    pub(crate) udp_downgraded_from: Option<TransportMode>,
}

fn record_transport_failure(
    status: &mut PerTransportStatus,
    now: Instant,
    min_failures: u32,
    load_balancing: &LoadBalancingConfig,
) {
    status.consecutive_successes = 0;
    status.consecutive_failures = status.consecutive_failures.saturating_add(1);
    if status.consecutive_failures >= min_failures {
        status.healthy = Some(false);
        add_penalty(&mut status.penalty, now, load_balancing);
    }
}

/// Symmetric pair of `record_transport_success`'s early-failback block:
/// when the probe (which always targets the primary wire in this
/// iteration) has failed `min_failures` consecutive times AND the
/// uplink has at least one fallback configured AND the active wire is
/// still primary, advance `active_wire` to the first fallback and pin
/// it for `pin_duration`.
///
/// Critical for `active_passive` groups where the *passive* uplinks
/// receive probes but no client traffic — without this, their
/// `active_wire` state machine never moves (only dial-loop failures
/// drive it through `record_wire_outcome`), so the very first session
/// after the passive uplink gets promoted to active would still try
/// the dead primary and only learn through chunk-0 stall.
///
/// Skipped when `total_wires <= 1` (single-wire uplinks have nowhere
/// to advance) or `active_wire != 0` (already on a fallback — the
/// dial loop's per-wire state machine owns further transitions).
///
/// Returns `true` iff `active_wire` actually transitioned from 0 to 1
/// in this call. The caller uses this to schedule a warm-standby drain:
/// the pool today only ever holds primary-wire sockets, and once we've
/// declared primary failed enough to flip active away, those sockets
/// are stale-suspect.
fn advance_active_wire_on_probe_failure(
    status: &mut PerTransportStatus,
    total_wires: usize,
    min_failures: u32,
    now: Instant,
    pin_duration: std::time::Duration,
) -> bool {
    if total_wires <= 1 {
        return false;
    }
    if status.active_wire != 0 {
        return false;
    }
    if status.consecutive_failures < min_failures.max(1) {
        return false;
    }
    status.active_wire = 1;
    status.active_wire_pinned_until = Some(now + pin_duration);
    status.active_wire_streak = 0;
    true
}

fn record_transport_success(status: &mut PerTransportStatus, min_failures: u32) {
    status.consecutive_failures = 0;
    status.consecutive_successes = status.consecutive_successes.saturating_add(1);
    status.healthy = Some(true);
    // Probe confirms the data path works again: drop any data-plane failure
    // streak so a fresh burst is required before another health flip.
    status.consecutive_runtime_failures = 0;
    // Only clear runtime-failure cooldown when the probe confirms the transport is
    // healthy. Clearing unconditionally would make a recently-failed uplink
    // immediately eligible again, causing oscillation under load.
    status.cooldown_until = None;

    // Early failback: if the active wire on this transport is currently
    // pinned to a fallback (because primary failed enough recent dials)
    // and the probe — which always targets the primary wire in this
    // iteration — has now succeeded `min_failures` consecutive times, the
    // primary wire has demonstrably recovered. Snap `active_wire` back to
    // primary immediately instead of waiting for the auto-failback timer
    // to expire (`mode_downgrade_duration`, default 60 s).
    //
    // The same `min_failures` knob doubles as the "stability" threshold
    // for failback (mirroring the existing `auto_failback` logic in
    // strict mode in candidates.rs): one operator-facing knob, one
    // mental model — N consecutive probe outcomes are needed in either
    // direction (failure to flip down, success to flip back).
    if status.active_wire != 0 && status.consecutive_successes >= min_failures.max(1) {
        status.active_wire = 0;
        status.active_wire_pinned_until = None;
        status.active_wire_streak = 0;
    }
}

fn needs_h3_recovery(
    status: &PerTransportStatus,
    effective_mode: TransportMode,
    uplink_transport: UplinkTransport,
    uplink_ws_mode: TransportMode,
    now: Instant,
) -> bool {
    effective_mode == TransportMode::WsH2
        && uplink_transport == UplinkTransport::Ws
        && uplink_ws_mode == TransportMode::WsH3
        && status.mode_downgrade_until.is_some_and(|t| t > now)
}

impl UplinkManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn process_probe_ok(
        &self,
        index: usize,
        uplink: &Uplink,
        result: ProbeOutcome,
        effective_tcp_mode: TransportMode,
        effective_udp_mode: TransportMode,
        h3_tcp_recovery: &mut Vec<(usize, Uplink)>,
        h3_udp_recovery: &mut Vec<(usize, Uplink)>,
    ) -> (bool, bool) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let rtt_ewma_alpha = self.inner.load_balancing.rtt_ewma_alpha;
        let load_balancing = self.inner.load_balancing.clone();
        let pin_duration = self.inner.load_balancing.mode_downgrade_duration;
        // Total wires on this uplink: 1 (primary) + configured fallbacks.
        // Used to gate probe-driven active-wire advance: only move active
        // off primary when there's at least one fallback to move to.
        let uplink_total_wires = 1 + uplink.fallbacks.len();
        let mut needs_h3_tcp_recovery = false;
        let mut needs_h3_udp_recovery = false;
        // Capture transitions so we can fire the warm-standby drain after
        // the sync status critical section ends (drain is async).
        let mut tcp_transitioned_to_fallback = false;
        let mut udp_transitioned_to_fallback = false;
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            status.tcp.latency = result.tcp_latency;
            status.udp.latency = result.udp_latency;
            update_rtt_ewma(&mut status.tcp.rtt_ewma, result.tcp_latency, rtt_ewma_alpha);
            update_rtt_ewma(&mut status.udp.rtt_ewma, result.udp_latency, rtt_ewma_alpha);
            if !result.tcp_ok {
                record_transport_failure(&mut status.tcp, now, min_failures, &load_balancing);
                // Probe-driven failover: when the primary wire has failed
                // `min_failures` consecutive probes and a fallback exists,
                // advance `active_wire` so the next session that lands on
                // this uplink lands on the fallback directly. Critical for
                // active_passive groups where the passive uplinks get
                // probed but no client traffic; without this their
                // `active_wire` state machine never moves (only dial-loop
                // failures drive it through `record_wire_outcome`), so the
                // first session after promotion would still try the dead
                // primary and only learn through chunk-0 stall.
                tcp_transitioned_to_fallback = advance_active_wire_on_probe_failure(
                    &mut status.tcp,
                    uplink_total_wires,
                    min_failures,
                    now,
                    pin_duration,
                );
            } else {
                record_transport_success(&mut status.tcp, min_failures);
                // Do NOT clear h3_tcp_downgrade_until here.  The probe uses the
                // effective (possibly downgraded) WS mode, so a successful probe
                // only confirms H2 connectivity during a downgrade window — it does
                // not prove that H3 is healthy again.  Instead, schedule an H3
                // recovery re-probe below to confirm H3 liveness explicitly.
                needs_h3_tcp_recovery = needs_h3_recovery(
                    &status.tcp,
                    effective_tcp_mode,
                    uplink.transport,
                    uplink.tcp_mode,
                    now,
                );
            }
            if result.udp_applicable {
                if !result.udp_ok {
                    record_transport_failure(&mut status.udp, now, min_failures, &load_balancing);
                    udp_transitioned_to_fallback = advance_active_wire_on_probe_failure(
                        &mut status.udp,
                        uplink_total_wires,
                        min_failures,
                        now,
                        pin_duration,
                    );
                } else {
                    record_transport_success(&mut status.udp, min_failures);
                    // Schedule UDP H3 recovery re-probe — mirror of the TCP
                    // path.  Successful H2 probe doesn't prove H3 is back, so
                    // verify it explicitly below.
                    needs_h3_udp_recovery = needs_h3_recovery(
                        &status.udp,
                        effective_udp_mode,
                        uplink.transport,
                        uplink.udp_mode,
                        now,
                    );
                }
            }
            if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                status.last_error = None;
            }
        });
        // Drain warm-standby pools when active just moved off primary as a
        // result of probe-confirmed failure. Spawned tasks because we're
        // outside the sync `with_status_mut` closure but still inside a
        // `pub(crate) fn` (not async), and `drain_standby_pool` is async.
        // `try_current` guards the unit-test path that drives
        // `process_probe_ok` from a sync `#[test]` body without a tokio
        // runtime; in production this is always called from the probe
        // scheduler on a tokio task.
        let runtime_present = tokio::runtime::Handle::try_current().is_ok();
        if tcp_transitioned_to_fallback && runtime_present {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.drain_standby_pool(index, TransportKind::Tcp).await;
            });
        }
        if udp_transitioned_to_fallback && runtime_present {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.drain_standby_pool(index, TransportKind::Udp).await;
            });
        }
        // Route transport-level probe failures through the unified H3 downgrade
        // helper (no-op for non-WS / non-H3 uplinks).  This prevents flapping:
        // without downgrade, intermittent H3 probe failures alternate pass/fail
        // and churn active-passive selection every cycle; with H2 downgrade, the
        // next probe uses the stable H2 path and H3 is only retried after the
        // window expires or a recovery re-probe confirms liveness.
        if !result.tcp_ok {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::ProbeTransportFailure,
            );
        }
        if result.udp_applicable && !result.udp_ok {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeTransportFailure,
            );
        }
        // The probe layer reports a "silent" downgrade when it succeeded but
        // the underlying dial was clamped/fallen-back below the requested
        // mode (host-level `ws_mode_cache` or inline H3→H2/H1 retry inside
        // `connect_websocket_with_resume`). Without this, `tcp_ok=true`
        // would mask the fact that H3 is unreachable, leaving
        // `effective_*_ws_mode` stuck on H3 forever while every actual probe
        // and user dial silently rides H2.
        if let Some(requested) = result.tcp_downgraded_from {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::SilentTransportFallback(requested),
            );
        }
        if let Some(requested) = result.udp_downgraded_from {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::SilentTransportFallback(requested),
            );
        }
        if needs_h3_tcp_recovery {
            h3_tcp_recovery.push((index, uplink.clone()));
        }
        if needs_h3_udp_recovery {
            h3_udp_recovery.push((index, uplink.clone()));
        }
        let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
            let s = self.inner.read_status(index);
            (
                s.tcp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
                s.udp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
            )
        };
        debug!(
            uplink = %uplink.name,
            tcp_healthy = result.tcp_ok,
            udp_healthy = result.udp_ok,
            tcp_latency_ms = result.tcp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            udp_latency_ms = result.udp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            tcp_rtt_ewma_ms,
            udp_rtt_ewma_ms,
            "uplink probe succeeded"
        );
        let refill_tcp = result.tcp_ok;
        // When UDP is not configured for this uplink, leave the standby pool
        // alone (don't clear it, don't refill it).
        let refill_udp = result.udp_applicable && result.udp_ok;
        (refill_tcp, refill_udp)
    }

    pub(crate) fn process_probe_err(&self, index: usize, uplink: &Uplink, error: anyhow::Error) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let load_balancing = self.inner.load_balancing.clone();
        let error_text = format!("{error:#}");
        let pin_duration = self.inner.load_balancing.mode_downgrade_duration;
        let uplink_total_wires = 1 + uplink.fallbacks.len();
        // Capture transitions for post-critical-section side effects (warm-
        // standby pool drain). Same pattern as `process_probe_ok`.
        let mut tcp_transitioned_to_fallback = false;
        let mut udp_transitioned_to_fallback = false;
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            record_transport_failure(&mut status.tcp, now, min_failures, &load_balancing);
            // Mirror `process_probe_ok`'s probe-driven active-wire advance.
            // Without this, a probe that errors out (WS handshake timeout,
            // 404 on the XHTTP URL, TLS failure — anything that aborts the
            // probe machinery itself before producing a `ProbeOutcome`)
            // never flips `active_wire` even after `min_failures`
            // consecutive errors, so a passive uplink whose primary is
            // reachable enough to handshake but broken at the application
            // layer would stay pinned to wire 0 forever — defeating the
            // failover for the most common real-world failure mode (server
            // disabled XHTTP but kept TLS / HTTPS responding).
            tcp_transitioned_to_fallback = advance_active_wire_on_probe_failure(
                &mut status.tcp,
                uplink_total_wires,
                min_failures,
                now,
                pin_duration,
            );
            // Only penalise UDP when it is actually configured.  The probe Err
            // path is usually a TCP connect failure; penalising UDP here when
            // there is no udp_ws_url would permanently mark UDP unhealthy for
            // TCP-only uplinks.
            if uplink.supports_udp() {
                record_transport_failure(&mut status.udp, now, min_failures, &load_balancing);
                udp_transitioned_to_fallback = advance_active_wire_on_probe_failure(
                    &mut status.udp,
                    uplink_total_wires,
                    min_failures,
                    now,
                    pin_duration,
                );
            }
            status.last_error = Some(error_text.clone());
        });
        // Same standby-drain side effect as `process_probe_ok` — entries in
        // the pool are primary-wire-shaped and become stale once active
        // moves off primary.
        let runtime_present = tokio::runtime::Handle::try_current().is_ok();
        if tcp_transitioned_to_fallback && runtime_present {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.drain_standby_pool(index, TransportKind::Tcp).await;
            });
        }
        if udp_transitioned_to_fallback && runtime_present {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.drain_standby_pool(index, TransportKind::Udp).await;
            });
        }
        // Probe-level failure (ws connect / timeout).  Same H3 downgrade logic
        // as the tcp_ok=false case above; helper is a no-op for non-WS/non-H3.
        self.extend_mode_downgrade(
            index,
            TransportKind::Tcp,
            ModeDowngradeTrigger::ProbeConnectFailure(&error),
        );
        if uplink.supports_udp() {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeConnectFailure(&error),
            );
        }
        warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
    }
}
