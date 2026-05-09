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

/// Decide whether a primary-wire probe failure should *not* drive any of the
/// escalation paths (`record_transport_failure`,
/// `advance_active_wire_on_probe_failure`, `extend_mode_downgrade(... Probe*)`)
/// because `active_wire` is already on a fallback that is demonstrably
/// carrying traffic.
///
/// The default probe path always targets the primary wire
/// ([`UplinkConfig::tcp_dial_url`] / `udp_dial_url` ignore `active_wire`),
/// so a primary that is permanently broken — for example because DPI started
/// dropping the configured carrier — produces a probe failure on every cycle
/// even after the system has already shifted `active_wire` to wire 1 and
/// real user traffic is flowing through the fallback. Without this gate
/// each cycle re-stamps:
///
///   * `consecutive_failures` (eventually flipping `healthy = false` for an
///     uplink that is actually delivering traffic),
///   * a fresh `mode_downgrade` window (capping the dispatcher to a lower
///     carrier on every probe interval indefinitely, even though the
///     fallback wire neither needs the cap nor fails on it),
///
/// producing the visible "primary still broken, sticky on fallback, traffic
/// fine, but `mode_downgrade` window glows forever" pattern.
///
/// Returns `true` (skip escalation) when:
///   * `active_wire != 0` — sticky has already moved off primary;
///   * `runtime_failure_window` is non-zero (a zero window disables decay
///     altogether — operators who pin that explicitly want eternal
///     accumulation, so we honour it);
///   * `last_any_wire_success` was stamped within the window — proof that
///     *some* wire (active fallback, validated by `run_fallback_wire_probe`,
///     or any successful user-flow dial) is delivering. The fallback-wire
///     probe walk runs whenever the primary outcome is failing
///     ([scheduler.rs:257](crate::manager::probe::scheduler)), so the
///     stamp is kept fresh as long as the fallback is actually reachable.
///
/// Whenever any of those is missing, the legacy escalation path runs as
/// before — primary is the only signal we trust.
fn should_skip_primary_probe_escalation(
    status: &PerTransportStatus,
    runtime_failure_window: Duration,
    now: Instant,
) -> bool {
    if status.active_wire == 0 {
        return false;
    }
    if runtime_failure_window.is_zero() {
        return false;
    }
    status
        .last_any_wire_success
        .is_some_and(|t| now.saturating_duration_since(t) < runtime_failure_window)
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
    // Pin expiry only clears the pin — it does NOT force active back to
    // primary. The previous behaviour produced a periodic
    // `0 → 1 → 2 → 0 → 1 → 2 → …` cycle whenever primary stayed broken:
    // every pin window, active was snapped to 0, the next probe failure
    // re-advanced to 1, the dial path eventually moved sticky from 1 to
    // 2 again, the next pin window snapped back to 0, and so on. Real
    // user-flows kept getting steered through known-broken wires once
    // per pin window. Auto-failback to primary now belongs solely to
    // `record_transport_success`'s early-failback block, which fires
    // when probe genuinely confirms primary recovered — not on a
    // wall-clock timer.
    if let Some(until) = status.active_wire_pinned_until {
        if until <= now {
            status.active_wire_pinned_until = None;
            status.active_wire_streak = 0;
        }
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

fn record_transport_success(
    status: &mut PerTransportStatus,
    min_failures: u32,
    grace_window: Duration,
) {
    let now = Instant::now();
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
    // Probe success in the post-recovery grace window resets the
    // grace's absorbed-attempts counter AND renews the grace
    // deadline. The counter reset converts an isolated flap (1 fail
    // every N minutes with successes between) from "monotonic drift
    // toward release" into "effectively absorbed forever". The
    // deadline renewal addresses the pattern observed in the field:
    // VLESS-mux idle disconnects (`ws upstream read idle for 300s`)
    // produce a runtime-error spike every 1-3 minutes, far apart
    // enough that the wall-clock grace window expires between them.
    // Renewing the deadline on each successful probe (typical probe
    // interval = 10 s) keeps the gate alive across these wide gaps
    // as long as **some** carrier-health signal is still positive.
    // A pure-fail streak — neither probe success nor recovery
    // success arriving — lets the deadline genuinely expire and
    // descent triggers re-install the cap.
    if status
        .last_recovery_success_at
        .is_some_and(|t| now.duration_since(t) < grace_window)
    {
        status.post_recovery_grace_descent_attempts = 0;
        status.last_recovery_success_at = Some(now);
    }

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

/// Whether to schedule a carrier-recovery re-probe for this uplink: the
/// regular probe just succeeded against the **capped** carrier (the
/// downgrade window's `effective_mode`), so confirming the configured
/// carrier is back requires an explicit attempt at the higher rank.
///
/// Covers both families:
/// * WS (`UplinkTransport::Ws`) configured at `WsH3` — capped to `WsH2`.
///   Recovery probes `WsH3` and clears the cap when it answers.
/// * VLESS+XHTTP (`UplinkTransport::Vless`) configured at `XhttpH3` —
///   capped to `XhttpH2` or `XhttpH1`; recovery probes `XhttpH3`.
/// * VLESS+XHTTP configured at `XhttpH2` — capped to `XhttpH1`; recovery
///   probes `XhttpH2`.
///
/// Returns `false` while [`PerTransportStatus::recovery_probe_cooldown_until`]
/// is active — the configured carrier just failed a recovery attempt
/// and re-running it on the next probe cycle would oscillate the cap
/// between cleared and re-installed states (each clear lets the next
/// regular probe target configured, which on a flaky configured carrier
/// re-fails, descent re-installs the cap, etc.). Cooldown is cleared
/// by a successful recovery (which clears the cap outright) and by
/// `clear_mode_downgrade`.
///
/// Without the VLESS+XHTTP arms the cap could only fall through TTL
/// expiry, which (combined with `extend_mode_downgrade` re-firing on
/// every cycle's H2 probe failure) traps real traffic on `XhttpH1` for
/// `mode_downgrade_duration` at a time even when the H2 carrier is
/// actually healthy.
fn needs_carrier_recovery(
    status: &PerTransportStatus,
    effective_mode: TransportMode,
    uplink_transport: UplinkTransport,
    uplink_configured_mode: TransportMode,
    now: Instant,
) -> bool {
    if status.mode_downgrade_until.is_none_or(|t| t <= now) {
        return false;
    }
    if status.recovery_probe_cooldown_until.is_some_and(|t| t > now) {
        return false;
    }
    match (uplink_transport, uplink_configured_mode) {
        (UplinkTransport::Ws, TransportMode::WsH3) => matches!(
            effective_mode,
            TransportMode::WsH2 | TransportMode::WsH1
        ),
        (UplinkTransport::Ws, TransportMode::WsH2) => effective_mode == TransportMode::WsH1,
        (UplinkTransport::Vless, TransportMode::XhttpH3) => matches!(
            effective_mode,
            TransportMode::XhttpH2 | TransportMode::XhttpH1
        ),
        (UplinkTransport::Vless, TransportMode::XhttpH2) => {
            effective_mode == TransportMode::XhttpH1
        },
        _ => false,
    }
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
        // Mirror of the grace window length computed inside
        // `extend_mode_downgrade` — kept in sync there. Used by
        // `record_transport_success` to renew the grace deadline on
        // every successful probe while the gate is open.
        let grace_window = pin_duration.saturating_mul(2);
        // Total wires on this uplink: 1 (primary) + configured fallbacks.
        // Used to gate probe-driven active-wire advance: only move active
        // off primary when there's at least one fallback to move to.
        let uplink_total_wires = 1 + uplink.fallbacks.len();
        // Capture transitions so we can fire the warm-standby drain after
        // the sync status critical section ends (drain is async).
        let mut tcp_transitioned_to_fallback = false;
        let mut udp_transitioned_to_fallback = false;
        let runtime_failure_window = load_balancing.runtime_failure_window;
        // Snapshot the gate *before* the mutation closure so the
        // `extend_mode_downgrade` branches below (which run outside the
        // status lock) see the same decision the in-closure branches did.
        let (tcp_skip_escalation, udp_skip_escalation) = {
            let s = self.inner.read_status(index);
            (
                should_skip_primary_probe_escalation(&s.tcp, runtime_failure_window, now),
                should_skip_primary_probe_escalation(&s.udp, runtime_failure_window, now),
            )
        };
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            status.tcp.latency = result.tcp_latency;
            status.udp.latency = result.udp_latency;
            update_rtt_ewma(&mut status.tcp.rtt_ewma, result.tcp_latency, rtt_ewma_alpha);
            update_rtt_ewma(&mut status.udp.rtt_ewma, result.udp_latency, rtt_ewma_alpha);
            if !result.tcp_ok {
                if !tcp_skip_escalation {
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
                }
            } else {
                record_transport_success(&mut status.tcp, min_failures, grace_window);
            }
            if result.udp_applicable {
                if !result.udp_ok {
                    if !udp_skip_escalation {
                        record_transport_failure(&mut status.udp, now, min_failures, &load_balancing);
                        udp_transitioned_to_fallback = advance_active_wire_on_probe_failure(
                            &mut status.udp,
                            uplink_total_wires,
                            min_failures,
                            now,
                            pin_duration,
                        );
                    }
                } else {
                    record_transport_success(&mut status.udp, min_failures, grace_window);
                }
            }
            if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                status.last_error = None;
            }
        });
        // Reactive walk-up: a successful probe at the **capped** carrier
        // bumps `consecutive_successes`. When that counter crosses
        // `min_failures`, lift the cap one rank toward configured (or
        // clear it if already adjacent). Done before deciding whether
        // a recovery re-probe is needed, so the recovery push reflects
        // the post-walk-up state — otherwise we'd schedule a recovery
        // probe against a cap that walk-up already cleared.
        if result.tcp_ok {
            self.walk_up_mode_downgrade(index, TransportKind::Tcp);
        }
        if result.udp_applicable && result.udp_ok {
            self.walk_up_mode_downgrade(index, TransportKind::Udp);
        }
        // Recompute carrier-recovery need from the post-walk-up state.
        // The regular probe runs at the effective (capped) carrier, so
        // its success only confirms the fallback rank — `run_h3_recovery_probes`
        // tests the configured carrier directly to drop the cap early.
        let (needs_h3_tcp_recovery, needs_h3_udp_recovery) = {
            let s = self.inner.read_status(index);
            let tcp = result.tcp_ok
                && needs_carrier_recovery(
                    &s.tcp,
                    effective_tcp_mode,
                    uplink.transport,
                    uplink.tcp_dial_mode(),
                    now,
                );
            let udp = result.udp_applicable
                && result.udp_ok
                && needs_carrier_recovery(
                    &s.udp,
                    effective_udp_mode,
                    uplink.transport,
                    uplink.udp_dial_mode(),
                    now,
                );
            (tcp, udp)
        };
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
        // Route transport-level probe failures through the unified
        // mode-downgrade helper. Covers both families (WS+H3 → H2 and
        // VLESS+XHTTP H3 → H2 → H1); a no-op for transports the
        // helper doesn't know how to step down (Shadowsocks, WS+H1).
        // The helper's `min_failures` descent gate keeps a single
        // flaky probe at the capped carrier from immediately stepping
        // the cap further down — a streak is required before each
        // descent. Recovery probes (above) plus the reactive walk-up
        // path together restore the cap as soon as the capped carrier
        // proves stable again.
        if !result.tcp_ok && !tcp_skip_escalation {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::ProbeTransportFailure(effective_tcp_mode),
            );
        }
        if result.udp_applicable && !result.udp_ok && !udp_skip_escalation {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeTransportFailure(effective_udp_mode),
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

    pub(crate) fn process_probe_err(
        &self,
        index: usize,
        uplink: &Uplink,
        error: anyhow::Error,
        effective_tcp_mode: crate::config::TransportMode,
        effective_udp_mode: crate::config::TransportMode,
    ) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures as u32;
        let load_balancing = self.inner.load_balancing.clone();
        let error_text = format!("{error:#}");
        let pin_duration = self.inner.load_balancing.mode_downgrade_duration;
        let uplink_total_wires = 1 + uplink.fallbacks.len();
        let runtime_failure_window = load_balancing.runtime_failure_window;
        let (tcp_skip_escalation, udp_skip_escalation) = {
            let s = self.inner.read_status(index);
            (
                should_skip_primary_probe_escalation(&s.tcp, runtime_failure_window, now),
                should_skip_primary_probe_escalation(&s.udp, runtime_failure_window, now),
            )
        };
        // Capture transitions for post-critical-section side effects (warm-
        // standby pool drain). Same pattern as `process_probe_ok`.
        let mut tcp_transitioned_to_fallback = false;
        let mut udp_transitioned_to_fallback = false;
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            if !tcp_skip_escalation {
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
            }
            // Only penalise UDP when it is actually configured.  The probe Err
            // path is usually a TCP connect failure; penalising UDP here when
            // there is no udp_ws_url would permanently mark UDP unhealthy for
            // TCP-only uplinks.
            if uplink.supports_udp() && !udp_skip_escalation {
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
        if !tcp_skip_escalation {
            self.extend_mode_downgrade(
                index,
                TransportKind::Tcp,
                ModeDowngradeTrigger::ProbeConnectFailure(&error, effective_tcp_mode),
            );
        }
        if uplink.supports_udp() && !udp_skip_escalation {
            self.extend_mode_downgrade(
                index,
                TransportKind::Udp,
                ModeDowngradeTrigger::ProbeConnectFailure(&error, effective_udp_mode),
            );
        }
        warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
    }
}
