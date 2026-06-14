//! Single source of truth for the per-uplink mode-downgrade window.
//!
//! The window is family-aware: it covers the WS chain (`H3` → `H2`,
//! raw `QUIC` → `H2`) and the XHTTP chain (`XhttpH3` → `XhttpH2`,
//! `XhttpH2` → `XhttpH1`). Four independent events can (re)set the
//! slot's downgrade window: runtime traffic failure, probe transport
//! failure, probe connect failure, and a recovery re-probe that failed
//! to confirm recovery. All of them go through
//! [`UplinkManager::extend_mode_downgrade`] so the guard conditions
//! (Ws/Vless transport, downgrade-eligible mode), the "set or extend —
//! never shorten" rule, and the "log once per window start" rule live
//! in exactly one place.
//!
//! Multi-step downgrades (`XhttpH3` → `XhttpH2` → `XhttpH1`) converge
//! over consecutive dials: each fallback observed by the dispatcher
//! lowers the slot's cap by one family rank, never raising it inside an
//! active window. After two dials the cap reaches the deepest fallback
//! the chain can produce, so probe / refill / fresh-dial paths stop
//! paying the doomed handshake cost for the broken upper carriers.
//!
//! This module is the *driver*: it owns the config-derived guards
//! (transport family, `carrier_downgrade` opt-out, ladder lookups), the
//! warm-probe invalidation and the logging. The slot bookkeeping itself
//! (window, cap, cooldown, grace budget, recovery streak) lives in
//! [`super::carrier_descent_state::CarrierDescentState`], one instance
//! per `(uplink, transport)` on
//! [`PerTransportStatus::descent`](super::status::PerTransportStatus::descent).

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{TransportMode, UplinkTransport};

use super::super::types::{TransportKind, UplinkManager};
pub(crate) use super::carrier_descent::is_carrier_floor_mode;
use super::carrier_descent::{family, one_step_down, rank};
use super::carrier_descent_state::{DescentDecision, DescentTrigger, WalkUpOutcome};

/// Why a downgrade window is being set or extended.  Controls the log
/// message and level emitted when the call starts a *new* window (silent
/// when it extends one that is already active).
pub(crate) enum ModeDowngradeTrigger<'a> {
    /// Real traffic observed a transport-level failure on an H3 session.
    RuntimeFailure(&'a anyhow::Error),
    /// Probe task completed but the per-transport check failed
    /// (e.g. `tcp_ok=false` in `ProbeOutcome`). Carries the **effective**
    /// mode the probe actually attempted — when a downgrade window is
    /// active the probe runs against the capped carrier (e.g. `xhttp_h2`
    /// after a previous `xhttp_h3 → xhttp_h2` cap), not the configured
    /// one. Threading the actually-failed carrier through here lets the
    /// monotonic downward cap continue (`xhttp_h2 → xhttp_h1`) instead
    /// of stalling at the first downgrade step forever.
    ProbeTransportFailure(TransportMode),
    /// Probe task itself errored out (ws connect failure, timeout).
    /// Carries the effective mode that was attempted — same reasoning as
    /// [`Self::ProbeTransportFailure`].
    ProbeConnectFailure(&'a anyhow::Error, TransportMode),
    /// Explicit H3 recovery re-probe failed to confirm H3 liveness.
    RecoveryReprobeFail,
    /// A dial succeeded but at a lower mode than requested — the host-level
    /// `ws_mode_cache` clamp or inline H3→H2/H1 fallback inside
    /// `connect_transport` silently produced a downgraded
    /// stream. Carries the originally-requested mode for the log message.
    /// Fired from probe / refill / fresh-dial / mux paths so the per-uplink
    /// `mode_downgrade_until` window stays in sync with the actually-dialable
    /// transport even when the operation itself reports success.
    SilentTransportFallback(TransportMode),
}

impl UplinkManager {
    /// Set or extend the H3→H2 downgrade window for `(index, transport)`.
    ///
    /// No-op when the uplink is not a WS transport or its WS mode for this
    /// transport is not H3.  The deadline is only advanced (never shortened),
    /// so a fresh trigger with a shorter configured duration cannot cut an
    /// already-longer window short.
    ///
    /// A log line is emitted only when this call *starts* a new window
    /// (previous deadline absent or expired).  Extensions inside an active
    /// window are silent, except [`ModeDowngradeTrigger::RecoveryReprobeFail`]
    /// which still emits a debug breadcrumb when it actually advances the
    /// deadline (preserves the pre-refactor recovery log).
    pub(crate) fn extend_mode_downgrade(
        &self,
        index: usize,
        transport: TransportKind,
        trigger: ModeDowngradeTrigger<'_>,
    ) {
        let uplink = &self.inner.uplinks[index];
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        // Operator-opt-out of the per-wire `h3 → h2 → h1` carrier
        // cascade. When this uplink has `carrier_downgrade = false`,
        // no descent window is installed: failures keep firing
        // `extend_mode_downgrade` from upstream callers (dial /
        // runtime / probe paths), but the cap state never changes and
        // `wire_is_at_carrier_floor` reports the wire as "at floor"
        // for the wire-rotation gate, so the next wire (or the next
        // uplink) is tried immediately. Useful when intermediate
        // ranks are known-useless on this uplink (DPI drops the
        // whole upstream regardless of HTTP version, for example).
        if !uplink.carrier_downgrade {
            return;
        }
        let configured_mode = match transport {
            TransportKind::Tcp => uplink.tcp_dial_mode(),
            TransportKind::Udp => uplink.udp_dial_mode(),
        };
        // The "what just failed" mode: explicit for `SilentTransportFallback`
        // (which carries the originally-requested carrier from the dial
        // result), otherwise the configured dial mode — probe and runtime
        // triggers don't carry their own mode field, but for those triggers
        // the failure is by definition on the configured carrier.
        let failed_mode = match &trigger {
            ModeDowngradeTrigger::SilentTransportFallback(requested) => *requested,
            ModeDowngradeTrigger::ProbeTransportFailure(attempted)
            | ModeDowngradeTrigger::ProbeConnectFailure(_, attempted) => *attempted,
            _ => configured_mode,
        };
        // Map the failed carrier to the carrier the next dial should
        // try. Returning `None` here means the failed carrier is already
        // the deepest fallback in its family — there is nothing left to
        // cap to, so skip the window update entirely.
        let new_cap = match one_step_down(failed_mode) {
            Some(cap) => cap,
            None => return,
        };
        // Sanity gate: cap must be a real downgrade relative to the
        // configured mode and live in the same family. This catches
        // two bogus shapes:
        //
        // * A `SilentTransportFallback(WsH3)` trigger fired against an
        //   uplink configured at `WsH2` (or below) would otherwise
        //   *raise* the effective mode from `WsH1` to `WsH2`.
        // * A cross-family trigger (an `XhttpH3` failure note arriving
        //   on a `WsH3`-configured uplink) would clamp the WS uplink
        //   to an XHTTP carrier the dispatcher cannot dial.
        //
        // Both indicate a wiring bug somewhere upstream; the right
        // response is to ignore the trigger rather than mis-park the
        // uplink.
        //
        // Comparing against `configured_mode` (rather than `failed_mode`)
        // here is important: under multi-step downgrades the failed mode
        // may already be a previous cap (`xhttp_h2`), and the new cap
        // (`xhttp_h1`) ranks below configured (`xhttp_h3`) — so the
        // multi-step `xhttp_h3 → h2 → h1` walk is admitted, while a
        // mis-wired cross-family or above-configured trigger is still
        // rejected.
        if family(new_cap) != family(configured_mode) || rank(new_cap) >= rank(configured_mode) {
            return;
        }

        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let probe_trigger = matches!(
            trigger,
            ModeDowngradeTrigger::ProbeTransportFailure(_)
                | ModeDowngradeTrigger::ProbeConnectFailure(_, _)
        );
        let probe_min_failures = self.inner.probe.min_failures.max(1) as u32;
        let is_recovery_fail = matches!(trigger, ModeDowngradeTrigger::RecoveryReprobeFail);

        // The slot owns the window/cap/grace bookkeeping (see
        // `CarrierDescentState::apply_descent_trigger` for the gating
        // rules); this driver feeds it the trigger shape plus the
        // probe-owned failure streak, and resets the probe-owned
        // success streak when the cap moves — `walk_up_mode_downgrade`
        // must observe a fresh `min_failures`-long streak of successes
        // against the **new** rank before lifting it again.
        let decision = self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            let decision = per.descent.apply_descent_trigger(DescentTrigger {
                now,
                duration,
                new_cap,
                failed_mode,
                probe_trigger,
                is_recovery_fail,
                probe_min_failures,
                probe_consecutive_failures: per.consecutive_failures,
            });
            if let DescentDecision::Applied(applied) = &decision
                && applied.cap_changed
            {
                per.consecutive_successes = 0;
            }
            decision
        });
        let applied = match decision {
            // Absorbed by the post-recovery grace window: the cap was
            // not re-installed, nothing to log or invalidate.
            DescentDecision::AbsorbedByGrace => return,
            DescentDecision::Applied(applied) => applied,
        };
        let newly_started = applied.newly_started;
        let advances_deadline = applied.advances_deadline;
        let updated_cap = applied.updated_cap;

        if advances_deadline || applied.cap_changed || is_recovery_fail {
            // The cached probe transport (if any) was dialled with the
            // old effective mode; the next probe will request the new
            // capped carrier, so a stale cached transport would either
            // mismatch and be discarded anyway or — worse — keep the
            // probe pinned to the failing carrier. Clear it now so the
            // refresh is unambiguous.
            match transport {
                TransportKind::Udp => {
                    super::probe::warm_udp::clear(self.inner.warm_udp_probe_slot(index));
                },
                TransportKind::Tcp => {
                    super::probe::warm_tcp::clear(self.inner.warm_tcp_probe_slot(index));
                },
            }
        }

        let downgrade_secs = duration.as_secs();
        let kind_label = match transport {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
        };
        if newly_started {
            match &trigger {
                ModeDowngradeTrigger::RuntimeFailure(err) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} runtime error on {failed_mode}, capping carrier to {updated_cap}"
                ),
                ModeDowngradeTrigger::ProbeTransportFailure(_) => warn!(
                    uplink = %uplink.name,
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} probe failed on {failed_mode}, capping carrier to {updated_cap} for next probe cycle"
                ),
                ModeDowngradeTrigger::ProbeConnectFailure(err, _) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} probe connection failed on {failed_mode}, capping carrier to {updated_cap}"
                ),
                ModeDowngradeTrigger::RecoveryReprobeFail => debug!(
                    uplink = %uplink.name,
                    kind = ?transport,
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "advanced carrier still unreachable, starting downgrade window after recovery probe"
                ),
                ModeDowngradeTrigger::SilentTransportFallback(requested) => warn!(
                    uplink = %uplink.name,
                    requested_mode = %requested,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} dial silently fell back from {requested}, syncing per-uplink downgrade window to {updated_cap}"
                ),
            }
        } else if matches!(trigger, ModeDowngradeTrigger::RecoveryReprobeFail) && advances_deadline
        {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                failed_mode = %failed_mode,
                capped_to = %updated_cap,
                downgrade_secs,
                "advanced carrier still unreachable after recovery probe, extending downgrade window"
            );
        }
    }

    /// Public entry-point for dial-time fallback: a synchronous QUIC (or H3)
    /// dial just failed, so mark the downgrade window the same way a runtime
    /// failure would.  The next call to `effective_*_mode` will return the
    /// one-step-down carrier (`WsH2` for `WsH3` / `Quic`,
    /// `XhttpH2` for `XhttpH3`, `XhttpH1` for `XhttpH2`) for the rest of
    /// the window.
    pub fn note_advanced_mode_dial_failure(
        &self,
        index: usize,
        transport: TransportKind,
        error: &anyhow::Error,
    ) {
        self.extend_mode_downgrade(index, transport, ModeDowngradeTrigger::RuntimeFailure(error));
    }

    /// Public entry-point for callers that observe a transport-level WS-mode
    /// downgrade after a *successful* dial — the `ws_mode_cache` clamped the
    /// requested mode or `connect_transport` ran an inline
    /// fallback. Distinct from `note_advanced_mode_dial_failure` so the log
    /// reflects "silent fallback" rather than "runtime error", which makes
    /// the operational signal accurate when this fires from the probe loop,
    /// the standby-refill loop, or fresh-dial paths.
    pub fn note_silent_transport_fallback(
        &self,
        index: usize,
        transport: TransportKind,
        requested: TransportMode,
    ) {
        self.extend_mode_downgrade(
            index,
            transport,
            ModeDowngradeTrigger::SilentTransportFallback(requested),
        );
    }

    /// Wire-aware variant of [`Self::note_silent_transport_fallback`]: when
    /// `wire_index == 0`, identical to the primary entry-point; when
    /// `wire_index >= 1`, the downgrade observation is stored against
    /// `fallback_mode_downgrades[wire_index - 1]` instead of primary's
    /// slot. Used by fallback-wire dial paths so a fallback that observes
    /// (e.g.) `XhttpH3 → XhttpH2` doesn't mis-park the primary's mode
    /// while still letting subsequent dials of the same fallback wire
    /// honour the cap.
    ///
    /// Reuses the same family/rank logic as the primary path: the cap
    /// must be in the same family as the wire's configured mode and rank
    /// strictly below it (cross-family or upward triggers are dropped).
    pub fn note_silent_transport_fallback_for_wire(
        &self,
        index: usize,
        transport: TransportKind,
        wire_index: u8,
        requested: TransportMode,
    ) {
        if wire_index == 0 {
            self.note_silent_transport_fallback(index, transport, requested);
            return;
        }
        let slot_idx = (wire_index - 1) as usize;
        let uplink = &self.inner.uplinks[index];
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return;
        };
        let configured_mode = match transport {
            TransportKind::Tcp => fallback.tcp_dial_mode(),
            TransportKind::Udp => fallback.udp_dial_mode(),
        };
        let new_cap = match one_step_down(requested) {
            Some(cap) => cap,
            None => return,
        };
        if family(new_cap) != family(configured_mode) || rank(new_cap) >= rank(configured_mode) {
            return;
        }
        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let new_until = now + duration;
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            // Lazy-extend the per-wire vec; entries default to (None, None).
            while per.fallback_mode_downgrades.len() <= slot_idx {
                per.fallback_mode_downgrades
                    .push(super::status::ModeDowngradeSlot::default());
            }
            let slot = &mut per.fallback_mode_downgrades[slot_idx];
            let window_active = slot.until.is_some_and(|t| t > now);
            // Monotonically-downward cap update mirroring primary's rule:
            // an in-window re-trigger must not raise the ceiling.
            let updated_cap = match slot.capped_to {
                Some(prev)
                    if window_active
                        && family(prev) == family(new_cap)
                        && rank(prev) < rank(new_cap) =>
                {
                    prev
                },
                _ => new_cap,
            };
            slot.until = Some(new_until);
            slot.capped_to = Some(updated_cap);
        });
        debug!(
            uplink = %uplink.name,
            transport = ?transport,
            wire_index,
            requested = %requested,
            capped_to = %new_cap,
            duration_secs = duration.as_secs(),
            "fallback wire mode-downgrade window opened"
        );
    }

    /// Read the effective TCP / UDP mode for a specific wire on this uplink:
    /// configured mode for that wire, capped by any active downgrade window
    /// in the wire's slot. Wire 0 reuses the existing primary path; wire >= 1
    /// reads `fallback_mode_downgrades[wire_index - 1]`. Out-of-range wires
    /// return their configured mode unchanged (no slot, no downgrade).
    pub async fn effective_tcp_mode_for_wire(
        &self,
        index: usize,
        wire_index: u8,
    ) -> crate::config::TransportMode {
        if wire_index == 0 {
            return self.effective_tcp_mode(index).await;
        }
        let uplink = &self.inner.uplinks[index];
        let slot_idx = (wire_index - 1) as usize;
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return uplink.tcp_dial_mode();
        };
        let configured = fallback.tcp_dial_mode();
        if !matches!(fallback.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        wire_capped_or_configured(&status.tcp, slot_idx, configured)
    }

    /// UDP counterpart to [`Self::effective_tcp_mode_for_wire`].
    pub async fn effective_udp_mode_for_wire(
        &self,
        index: usize,
        wire_index: u8,
    ) -> crate::config::TransportMode {
        if wire_index == 0 {
            return self.effective_udp_mode(index).await;
        }
        let uplink = &self.inner.uplinks[index];
        let slot_idx = (wire_index - 1) as usize;
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return uplink.udp_dial_mode();
        };
        let configured = fallback.udp_dial_mode();
        if !matches!(fallback.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        wire_capped_or_configured(&status.udp, slot_idx, configured)
    }

    /// Walk the active mode-downgrade cap up by one carrier rank when
    /// the regular probe has succeeded against the capped (effective)
    /// carrier `min_failures` times in a row. Used as the
    /// reactive-recovery counterpart to the configured-carrier
    /// recovery probe: while `run_h3_recovery_probes` tests the
    /// configured carrier directly, this path lets the system claw
    /// back **intermediate** ranks when only the capped carrier has
    /// been confirmed healthy by the ordinary probe loop.
    ///
    /// Behaviour:
    /// * No active window or no cap set → no-op.
    /// * Counter `consecutive_successes < min_failures` → no-op (the
    ///   regular probe success increments the counter, so this builds
    ///   up over `min_failures` cycles before each step).
    /// * Otherwise the cap moves one rank up via [`one_step_up`]
    ///   **only when the new rank is still strictly below configured**.
    ///   The final hop from `one-step-below-configured` to configured
    ///   is owned by the configured-carrier recovery probe alone
    ///   ([`Self::run_h3_recovery_probes`]) — promoting the cap there
    ///   from the regular probe loop would let an intermittent
    ///   configured carrier oscillate the cap every `interval +
    ///   min_failures*interval` cycles (a probe success at H2 walks
    ///   the cap up, the next probe targets H3 and fails, descent
    ///   sets cap=H2, walk-up succeeds again on the next H2 success
    ///   streak, …). Recovery probes specifically test the
    ///   configured rank, so leaving the top-step exclusively to them
    ///   keeps the cap pinned at the deepest stable rank when
    ///   configured is genuinely intermittent.
    /// * The success counter is reset on each step so the next step
    ///   requires a fresh `min_failures` streak.
    ///
    /// Without this path the cap could only fall through TTL expiry,
    /// which in combination with `extend_mode_downgrade` re-firing on
    /// every cycle's H2 probe failure traps real traffic on the
    /// deepest fallback for `mode_downgrade_duration` at a stretch
    /// even when the capped carrier itself is healthy.
    pub(crate) fn walk_up_mode_downgrade(&self, index: usize, transport: TransportKind) {
        let uplink = &self.inner.uplinks[index];
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        let configured_mode = match transport {
            TransportKind::Tcp => uplink.tcp_dial_mode(),
            TransportKind::Udp => uplink.udp_dial_mode(),
        };
        let min_successes = self.inner.probe.min_failures.max(1) as u32;
        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;

        // Outcome captured inside the critical section so the log can
        // run after the lock is released — `tracing` macros allocate
        // and we'd rather not hold the status lock across that. The
        // walk itself (streak gate, hold-below-configured arm, the
        // defensive cross-family clear) lives on the slot; this driver
        // resets the probe-owned success streak and invalidates the
        // warm probe transport whenever the cap actually moved.
        let outcome = self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            let outcome = per.descent.walk_up(
                now,
                duration,
                configured_mode,
                min_successes,
                per.consecutive_successes,
            );
            if !matches!(outcome, WalkUpOutcome::NoOp) {
                per.consecutive_successes = 0;
                // The cached probe transport (if any) was dialled at the
                // old cap; clear it so the next probe refreshes against
                // the walked-up carrier. Skip in the hold-at-pre-configured
                // arm — cap didn't move there, the warm pipe is still valid.
                match transport {
                    TransportKind::Udp => {
                        super::probe::warm_udp::clear(self.inner.warm_udp_probe_slot(index));
                    },
                    TransportKind::Tcp => {
                        super::probe::warm_tcp::clear(self.inner.warm_tcp_probe_slot(index));
                    },
                }
            }
            outcome
        });

        let kind_label = match transport {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
        };
        match outcome {
            WalkUpOutcome::NoOp => {},
            WalkUpOutcome::Cleared { from } => debug!(
                uplink = %uplink.name,
                kind = ?transport,
                from = %from,
                configured = %configured_mode,
                "{kind_label} mode-downgrade cap cleared by walk-up — capped carrier confirmed healthy"
            ),
            WalkUpOutcome::SteppedUp { from, to } => debug!(
                uplink = %uplink.name,
                kind = ?transport,
                from = %from,
                to = %to,
                "{kind_label} mode-downgrade cap walked up after consecutive successes on capped carrier"
            ),
        }
    }

    /// Clear the downgrade window for `(index, transport)`. Resets the
    /// deadline, the cap, the recovery-probe cooldown, the recovery
    /// success streak, and the post-recovery grace counter so the
    /// next dial returns to the configured mode and the next descent
    /// → recovery cycle starts clean. Stamps `last_recovery_success_at`
    /// so `extend_mode_downgrade` can apply the post-recovery grace
    /// window. Called by the reactive walk-up's defensive clear arms
    /// and indirectly via [`Self::note_recovery_probe_success`] once
    /// the streak threshold is met.
    pub(crate) fn clear_mode_downgrade(&self, index: usize, transport: TransportKind) {
        let now = Instant::now();
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => status.tcp.descent.clear_and_open_grace(now),
            TransportKind::Udp => status.udp.descent.clear_and_open_grace(now),
        });
    }

    /// Threshold (consecutive successful recovery probes) required
    /// before the cap is cleared. A single recovery success only
    /// proves handshake-level connectivity to the configured carrier;
    /// on uplinks where the data plane is flaky (server emits stream
    /// errors after handshake completes — the `xhttp/h3 stream-one
    /// downlink ended` pattern in the field) the cap would otherwise
    /// clear after every cap install and immediately re-install on
    /// the next descent trigger, producing a permanent `H3 ↔ H2` flap.
    /// Two consecutive recovery successes (separated by at least
    /// `probe.interval`) raise the bar enough to break the flap.
    const RECOVERY_SUCCESS_STREAK_THRESHOLD: u32 = 2;

    /// Record a successful configured-carrier recovery probe. The
    /// cap is cleared **only** when the streak counter reaches
    /// [`Self::RECOVERY_SUCCESS_STREAK_THRESHOLD`] consecutive
    /// successes; before that, this is a tentative-success record.
    /// On a flaky configured carrier this filters out the
    /// "handshake works once, data plane breaks" cycle that drives
    /// visible flapping.
    pub(crate) fn note_recovery_probe_success(&self, index: usize, transport: TransportKind) {
        // shuffle_wires "stay on the capped carrier" gate. With the
        // vertical cascade (xhttp_h3 → xhttp_h2 → xhttp_h1) the operator
        // explicitly wants traffic to settle at the deepest working
        // carrier on the current wire before any rotation away from
        // it. A handshake-only recovery probe on the *configured*
        // carrier (e.g. xhttp_h3) routinely succeeds even when real
        // data-plane traffic still fails (the production case in the
        // log this branch was built for); clearing the cap on that
        // signal yanks user-flows back onto the broken configured
        // carrier and re-triggers the same descent on the next
        // failure, looping at the upper rank instead of walking
        // down. With `shuffle_wires = true` we therefore refuse to
        // clear the cap from this path entirely — the cap can still
        // expire naturally via its window deadline (default 60 s,
        // controlled by `mode_downgrade_secs`).
        let shuffle_wires = self.inner.uplinks[index].shuffle_wires;
        let new_streak = self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            per.descent.note_recovery_success_streak()
        });
        let should_clear = new_streak >= Self::RECOVERY_SUCCESS_STREAK_THRESHOLD && !shuffle_wires;
        let uplink = &self.inner.uplinks[index];
        let kind_label = match transport {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
        };
        if shuffle_wires && new_streak >= Self::RECOVERY_SUCCESS_STREAK_THRESHOLD {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                streak = new_streak,
                "{kind_label} recovery probe streak met but shuffle_wires = true: \
                 leaving cap in place so the vertical carrier cascade keeps walking \
                 the wire down to its floor before rotating to the next wire"
            );
        }
        if should_clear {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                streak = new_streak,
                "{kind_label} recovery probe streak met — clearing downgrade window"
            );
            self.clear_mode_downgrade(index, transport);
        } else {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                streak = new_streak,
                threshold = Self::RECOVERY_SUCCESS_STREAK_THRESHOLD,
                "{kind_label} recovery probe tentatively succeeded — awaiting another consecutive success before clearing cap"
            );
        }
    }
}

/// Mirror of `capped_or_configured` (in standby/mod.rs) but for a
/// fallback wire's per-wire slot in `fallback_mode_downgrades`.
/// Returns the cap when the per-wire window is active and the cap is
/// set; falls back to the configured mode in any other case (no slot,
/// expired window, missing cap — defensive).
fn wire_capped_or_configured(
    status: &super::status::PerTransportStatus,
    slot_idx: usize,
    configured: TransportMode,
) -> TransportMode {
    let now = Instant::now();
    let Some(slot) = status.fallback_mode_downgrades.get(slot_idx) else {
        return configured;
    };
    match (slot.until, slot.capped_to) {
        (Some(until), Some(cap)) if until > now => cap,
        _ => configured,
    }
}

/// Synchronous "is the wire at the floor of its carrier-downgrade
/// stack?" helper, callable from inside an already-held
/// `with_status_mut` closure — `record_wire_outcome` needs this gate
/// without re-entering the per-uplink status lock that
/// [`UplinkManager::effective_tcp_mode_for_wire`] /
/// [`UplinkManager::effective_udp_mode_for_wire`] take.
///
/// Mirrors the dispatch logic of the async helpers: wire 0 reads the
/// primary cap on `status.<transport>`; wire ≥ 1 reads
/// `fallback_mode_downgrades[wire - 1]`. Returns:
///
/// * `true` when the wire's family is **not** Ws/XHTTP (Shadowsocks,
///   raw VLESS) — those carriers have no descent stack, so the gate
///   should never block wire-rotation on them;
/// * `true` when the wire's effective mode is the floor of its family
///   (`WsH1` or `XhttpH1`) — no further descent possible;
/// * `false` otherwise.
///
/// The wire's *configured* mode comes from the parent uplink's
/// primary fields (wire 0) or the matching
/// `UplinkConfig::fallbacks[wire - 1]` entry. The *effective* mode is
/// the cap when an in-window downgrade is installed, else the
/// configured mode.
pub(crate) fn wire_is_at_carrier_floor(
    uplink: &crate::config::UplinkConfig,
    status: &super::status::PerTransportStatus,
    transport: TransportKind,
    wire_index: u8,
) -> bool {
    // Operator-opt-out of the vertical cascade: when this uplink has
    // `carrier_downgrade = false`, every wire counts as "at the floor"
    // for the rotation gate. The matching `extend_mode_downgrade` guard
    // also no-ops, so no descent window is installed and the wire's
    // effective mode is always the configured one — there is nothing
    // to walk down, the gate must release.
    if !uplink.carrier_downgrade {
        return true;
    }
    if wire_index == 0 {
        let (family_transport, configured) = match transport {
            TransportKind::Tcp => (uplink.transport, uplink.tcp_dial_mode()),
            TransportKind::Udp => (uplink.transport, uplink.udp_dial_mode()),
        };
        // Only WS / VLESS families participate in the carrier-downgrade
        // stack (see `extend_mode_downgrade` guard). Any other transport
        // family counts as "at floor" so wire-rotation is not held back
        // (kept defensive: the transport enum is WS / VLESS today).
        if !matches!(
            family_transport,
            crate::config::UplinkTransport::Ss | crate::config::UplinkTransport::Vless
        ) {
            return true;
        }
        let effective = status.descent.active_cap(Instant::now()).unwrap_or(configured);
        return is_carrier_floor_mode(effective);
    }
    let slot_idx = (wire_index - 1) as usize;
    let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
        return true;
    };
    if !matches!(
        fallback.transport,
        crate::config::UplinkTransport::Ss | crate::config::UplinkTransport::Vless
    ) {
        return true;
    }
    let configured = match transport {
        TransportKind::Tcp => fallback.tcp_dial_mode(),
        TransportKind::Udp => fallback.udp_dial_mode(),
    };
    let effective = wire_capped_or_configured(status, slot_idx, configured);
    is_carrier_floor_mode(effective)
}
