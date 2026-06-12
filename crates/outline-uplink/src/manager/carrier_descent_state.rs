//! Per-(uplink, transport) carrier-descent slot state.
//!
//! Companion to the state-free transition table in
//! [`super::carrier_descent`]: that module owns *which* carrier follows
//! which, this one owns the bookkeeping of a single descent slot — the
//! downgrade window, the cap, the recovery cooldown, the post-recovery
//! grace budget and the recovery success streak. Every transition is a
//! method, so the pairing invariant (window deadline and cap are set and
//! cleared together) and the counter-reset rules live in exactly one
//! place instead of being spread over ad-hoc field writes.
//!
//! The slot deliberately does **not** own the probe streak counters
//! (`consecutive_failures` / `consecutive_successes` on
//! [`super::status::PerTransportStatus`]) — those belong to the probe
//! machinery and are shared with health gating. Methods that need them
//! take the current value as a parameter; callers reset them based on
//! the returned outcome.
//!
//! Driven by [`super::mode_downgrade`], which keeps the config-derived
//! guards (transport family, `carrier_downgrade` opt-out, ladder
//! lookups), the warm-probe-slot invalidation and all logging.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::TransportMode;

use super::carrier_descent::{family, one_step_up, rank};

/// One descent slot: the primary wire of one `(uplink, transport)` pair.
///
/// `until` / `capped_to` move together: either both are `Some` (a window
/// is installed) or both are `None`. An expired-but-set window counts as
/// inactive for every read path ([`Self::window_active`],
/// [`Self::active_cap`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct CarrierDescentState {
    /// Deadline of the downgrade window. While in the future,
    /// connections must use [`Self::capped_to`] instead of the
    /// configured carrier.
    until: Option<Instant>,
    /// Family-aware ceiling for the window — what `effective_*_mode`
    /// returns while [`Self::until`] is in the future. Updates
    /// monotonically downward inside an active window.
    capped_to: Option<TransportMode>,
    /// Cooldown after a failed configured-carrier recovery re-probe.
    /// While in the future, no new recovery probe is scheduled.
    recovery_probe_cooldown_until: Option<Instant>,
    /// Timestamp of the most recent successful configured-carrier
    /// recovery (or grace renewal). Anchors the post-recovery grace
    /// window that absorbs isolated descent triggers right after a
    /// recovery cleared the cap.
    last_recovery_success_at: Option<Instant>,
    /// Descent triggers absorbed by the post-recovery grace window
    /// since the last clear / cap install. Releases the gate when it
    /// reaches the operator's `min_failures`.
    post_recovery_grace_descent_attempts: u32,
    /// Consecutive successful configured-carrier recovery probes. The
    /// cap is cleared only when this reaches the caller's streak
    /// threshold.
    recovery_probe_success_streak: u32,
}

/// Inputs for one descent trigger, precomputed by the caller from the
/// trigger kind, the config and the ladder ([`super::carrier_descent`]).
pub(crate) struct DescentTrigger {
    pub(crate) now: Instant,
    /// Configured `mode_downgrade_duration`; also seeds the 2× grace
    /// window length.
    pub(crate) duration: Duration,
    /// The carrier the next dial should be capped to (already one step
    /// below the failed mode, family/rank-validated by the caller).
    pub(crate) new_cap: TransportMode,
    /// The carrier that actually failed (for the at-cap probe gate).
    pub(crate) failed_mode: TransportMode,
    /// Whether the trigger came from the probe loop (probe failures are
    /// gated on the probe streak; runtime / silent-fallback triggers
    /// descend immediately).
    pub(crate) probe_trigger: bool,
    /// Whether the trigger is a failed configured-carrier recovery
    /// re-probe (parks the recovery cooldown, resets the streak).
    pub(crate) is_recovery_fail: bool,
    /// Operator's `probe.min_failures`, already clamped to >= 1.
    pub(crate) probe_min_failures: u32,
    /// Current probe failure streak (owned by the probe machinery).
    pub(crate) probe_consecutive_failures: u32,
}

/// Outcome of [`CarrierDescentState::apply_descent_trigger`].
pub(crate) enum DescentDecision {
    /// The post-recovery grace window absorbed the trigger: the cap was
    /// **not** re-installed, the grace budget was charged and the grace
    /// deadline slid forward.
    AbsorbedByGrace,
    /// The window/cap state was evaluated (and possibly updated) — the
    /// flags tell the caller what changed for logging and warm-probe
    /// invalidation.
    Applied(DescentApplied),
}

pub(crate) struct DescentApplied {
    /// The call started a new window (no previous deadline, or the
    /// previous one had already expired).
    pub(crate) newly_started: bool,
    /// The deadline moved forward ("set or extend — never shorten").
    pub(crate) advances_deadline: bool,
    /// The cap value changed (first install or a step further down).
    pub(crate) cap_changed: bool,
    /// The cap now in effect.
    pub(crate) updated_cap: TransportMode,
}

/// Outcome of [`CarrierDescentState::walk_up`].
pub(crate) enum WalkUpOutcome {
    /// Nothing to do: no active window, streak not met, or the next
    /// rank up is owned by the configured-carrier recovery probe.
    NoOp,
    /// The cap was dropped entirely (cross-family defensive clear, or
    /// the cap was already at the family's top).
    Cleared { from: TransportMode },
    /// The cap moved one rank up and the window was refreshed.
    SteppedUp { from: TransportMode, to: TransportMode },
}

impl CarrierDescentState {
    /// Deadline of the downgrade window, raw (`Some` even when already
    /// expired). Use [`Self::window_active`] for the time-gated check.
    pub(crate) fn until(&self) -> Option<Instant> {
        self.until
    }

    /// Cap value, raw (`Some` even when the window has expired). Use
    /// [`Self::active_cap`] for the time-gated effective value.
    pub(crate) fn capped_to(&self) -> Option<TransportMode> {
        self.capped_to
    }

    /// `true` while the downgrade window deadline is in the future.
    pub(crate) fn window_active(&self, now: Instant) -> bool {
        self.until.is_some_and(|t| t > now)
    }

    /// The cap to apply right now: `Some` only when the window is
    /// active **and** the cap is set; `None` otherwise (no window,
    /// expired window, or — defensively — a missing cap).
    pub(crate) fn active_cap(&self, now: Instant) -> Option<TransportMode> {
        match (self.until, self.capped_to) {
            (Some(until), Some(cap)) if until > now => Some(cap),
            _ => None,
        }
    }

    /// `true` while the recovery-probe cooldown deadline is in the
    /// future (a configured-carrier recovery attempt recently failed).
    pub(crate) fn recovery_cooldown_active(&self, now: Instant) -> bool {
        self.recovery_probe_cooldown_until.is_some_and(|t| t > now)
    }

    #[cfg(test)]
    pub(crate) fn recovery_probe_cooldown_until(&self) -> Option<Instant> {
        self.recovery_probe_cooldown_until
    }

    /// Timestamp anchoring the post-recovery grace window.
    #[cfg(test)]
    pub(crate) fn last_recovery_success_at(&self) -> Option<Instant> {
        self.last_recovery_success_at
    }

    #[cfg(test)]
    pub(crate) fn grace_attempts(&self) -> u32 {
        self.post_recovery_grace_descent_attempts
    }

    #[cfg(test)]
    pub(crate) fn recovery_streak(&self) -> u32 {
        self.recovery_probe_success_streak
    }

    /// Apply one descent trigger to the slot. The caller has already
    /// validated the trigger against the config and the ladder (same
    /// family, `new_cap` strictly below configured) — this method owns
    /// the window/cap/grace bookkeeping:
    ///
    /// * the post-recovery grace gate (cap currently `None`) absorbs
    ///   the trigger, charges the budget and slides the grace anchor;
    /// * the at-cap probe gate holds the cap in place until the probe
    ///   failure streak reaches `min_failures`;
    /// * otherwise the cap updates monotonically downward inside an
    ///   active window and the deadline only ever moves forward;
    /// * a cap change invalidates the grace budget and the recovery
    ///   streak; a failed recovery re-probe parks the recovery
    ///   cooldown and resets the streak.
    ///
    /// The caller must reset the (probe-owned) `consecutive_successes`
    /// counter when [`DescentApplied::cap_changed`] is reported, and
    /// invalidate warm probe transports when the state mutated
    /// (`advances_deadline || cap_changed || is_recovery_fail`).
    pub(crate) fn apply_descent_trigger(&mut self, trigger: DescentTrigger) -> DescentDecision {
        let DescentTrigger {
            now,
            duration,
            new_cap,
            failed_mode,
            probe_trigger,
            is_recovery_fail,
            probe_min_failures,
            probe_consecutive_failures,
        } = trigger;
        let new_until = now + duration;

        let prev_until = self.until;
        let prev_cap = self.capped_to;
        let window_active = prev_until.is_some_and(|t| t > now);
        let newly_started = prev_until.is_none_or(|t| t < now);
        let advances_deadline = prev_until.is_none_or(|t| t < new_until);

        // Min-failures gate for further descent (cap currently set):
        // when a **probe** trigger arrives in an already-capped window
        // and the failed mode is the same as (or below) the current
        // cap — i.e. the probe tested the capped carrier and failed —
        // hold the cap in place until the probe failure streak reaches
        // `min_failures`. Without this a single flaky probe at the
        // capped rank pushes the cap one step deeper for a full TTL
        // even when the capped carrier is mostly healthy. Limited to
        // probe triggers because the streak is the probe-only counter;
        // runtime / silent-fallback triggers are stronger real-traffic
        // signals and descend immediately.
        let probe_at_or_below_cap = match prev_cap {
            Some(prev) => {
                window_active
                    && family(prev) == family(failed_mode)
                    && rank(failed_mode) <= rank(prev)
            },
            None => false,
        };
        let descent_gated_at_cap = probe_trigger
            && probe_consecutive_failures < probe_min_failures
            && probe_at_or_below_cap;

        // Post-recovery grace gate (cap currently None): a recovery
        // probe recently cleared the cap. The grace window absorbs
        // descent triggers so an isolated post-clear flap doesn't
        // immediately re-install the cap:
        //
        // 1. Window length = 2 × `duration` — covers the common "one
        //    flaky probe every 70-90 s" pattern a single window misses.
        // 2. Renewable on absorbed attempts — each absorbed trigger
        //    slides the anchor forward, so the window stays alive as
        //    long as descent signals arrive less than the window apart.
        // 3. Budget = `min_failures` absorbed attempts without an
        //    intervening success (successes reset the counter via
        //    [`Self::renew_grace_if_active`]) — a real all-fail streak
        //    still releases the gate and re-installs the cap.
        let grace_window = duration.saturating_mul(2);
        let in_post_recovery_grace = self
            .last_recovery_success_at
            .is_some_and(|t| now.duration_since(t) < grace_window);
        let grace_gate_active = prev_cap.is_none()
            && in_post_recovery_grace
            && self.post_recovery_grace_descent_attempts < probe_min_failures;
        if grace_gate_active {
            self.post_recovery_grace_descent_attempts =
                self.post_recovery_grace_descent_attempts.saturating_add(1);
            self.last_recovery_success_at = Some(now);
            return DescentDecision::AbsorbedByGrace;
        }

        // Cap update rule: monotonically downward inside an active
        // window — an in-window re-trigger at a higher rank must not
        // raise the ceiling. Outside an active window the previous cap
        // is stale, so always overwrite. The at-cap gate above pins the
        // cap in place while probe failures haven't stacked yet (the
        // deadline still refreshes so the window survives until the
        // gate releases).
        let updated_cap = match prev_cap {
            Some(prev) if descent_gated_at_cap => prev,
            Some(prev)
                if window_active
                    && family(prev) == family(new_cap)
                    && rank(prev) < rank(new_cap) =>
            {
                prev
            },
            _ => new_cap,
        };

        let cap_changed = prev_cap != Some(updated_cap);
        if advances_deadline || cap_changed || is_recovery_fail {
            if advances_deadline {
                self.until = Some(new_until);
            }
            self.capped_to = Some(updated_cap);
            if cap_changed {
                // Cap is back in place — the post-recovery grace window
                // is implicitly over; the next clear starts a fresh
                // budget. Any recovery streak accumulated for the
                // previous cap is moot — descent invalidated its
                // premise.
                self.post_recovery_grace_descent_attempts = 0;
                self.recovery_probe_success_streak = 0;
            }
            if is_recovery_fail {
                // A failed recovery probe restarts the streak and parks
                // the cooldown so the next recovery push waits out the
                // window instead of re-running every probe cycle on a
                // flaky configured carrier.
                self.recovery_probe_success_streak = 0;
                self.recovery_probe_cooldown_until = Some(new_until);
            }
        }

        DescentDecision::Applied(DescentApplied {
            newly_started,
            advances_deadline,
            cap_changed,
            updated_cap,
        })
    }

    /// Walk the active cap one rank up after the probe loop confirmed
    /// the capped carrier healthy `min_successes` times in a row
    /// (`consecutive_successes` is the probe-owned counter, passed in
    /// by the caller). The hop onto the configured rank itself is owned
    /// by the configured-carrier recovery probe — walking there from
    /// here would let an intermittent configured carrier oscillate the
    /// cap, so the step below configured holds ([`WalkUpOutcome::NoOp`]).
    ///
    /// The caller must reset `consecutive_successes` and invalidate the
    /// warm probe transport on [`WalkUpOutcome::Cleared`] /
    /// [`WalkUpOutcome::SteppedUp`] (the hold arm keeps both valid).
    pub(crate) fn walk_up(
        &mut self,
        now: Instant,
        duration: Duration,
        configured_mode: TransportMode,
        min_successes: u32,
        consecutive_successes: u32,
    ) -> WalkUpOutcome {
        let Some(prev_cap) = self.capped_to else {
            return WalkUpOutcome::NoOp;
        };
        if self.until.is_none_or(|t| t <= now) {
            return WalkUpOutcome::NoOp;
        }
        if consecutive_successes < min_successes {
            return WalkUpOutcome::NoOp;
        }
        // Defensive: a cross-family cap shouldn't exist alongside the
        // current configured family (the descent path enforces same-
        // family writes), but if it does we'd rather clear it than
        // mis-walk into the wrong chain.
        if family(prev_cap) != family(configured_mode) {
            self.clear_window_keep_grace_anchor();
            return WalkUpOutcome::Cleared { from: prev_cap };
        }
        match one_step_up(prev_cap) {
            None => {
                // Already at the family's top — nothing higher to walk
                // to. Drop the cap; configured carrier is the ceiling.
                self.clear_window_keep_grace_anchor();
                WalkUpOutcome::Cleared { from: prev_cap }
            },
            Some(next) if rank(next) >= rank(configured_mode) => {
                // The final hop is the recovery probe's alone — hold.
                WalkUpOutcome::NoOp
            },
            Some(next) => {
                self.capped_to = Some(next);
                // Refresh the deadline so the new rank gets a full
                // window's worth of probe cycles to prove itself before
                // the natural TTL fires.
                self.until = Some(now + duration);
                WalkUpOutcome::SteppedUp { from: prev_cap, to: next }
            },
        }
    }

    /// Walk-up's clear: drops the window, the cooldown and the grace
    /// budget but does **not** stamp a fresh grace anchor — the cap was
    /// lifted by ordinary probe successes on the capped carrier, not by
    /// a configured-carrier recovery, so no post-recovery grace opens.
    fn clear_window_keep_grace_anchor(&mut self) {
        self.until = None;
        self.capped_to = None;
        self.recovery_probe_cooldown_until = None;
        self.post_recovery_grace_descent_attempts = 0;
    }

    /// Full clear after a confirmed configured-carrier recovery (or an
    /// explicit reset): drops the window, the cooldown and both
    /// counters, and stamps `last_recovery_success_at` so the
    /// post-recovery grace window opens with a fresh budget.
    pub(crate) fn clear_and_open_grace(&mut self, now: Instant) {
        self.until = None;
        self.capped_to = None;
        self.recovery_probe_cooldown_until = None;
        self.last_recovery_success_at = Some(now);
        self.post_recovery_grace_descent_attempts = 0;
        self.recovery_probe_success_streak = 0;
    }

    /// Wipe the window when the active wire changes: the new wire's
    /// carrier stack is independent and starts at the configured rank.
    /// Keeps the grace anchor and budget — wire rotation is not a
    /// recovery event.
    pub(crate) fn reset_window_for_wire_change(&mut self) {
        self.until = None;
        self.capped_to = None;
        self.recovery_probe_success_streak = 0;
        self.recovery_probe_cooldown_until = None;
    }

    /// Probe success inside the post-recovery grace window resets the
    /// absorbed-attempts budget AND renews the grace anchor, so an
    /// isolated flap with successes between stays absorbed indefinitely
    /// while a pure-fail streak still releases. No-op when the grace
    /// window has already expired (or never opened).
    pub(crate) fn renew_grace_if_active(&mut self, now: Instant, grace_window: Duration) {
        if self
            .last_recovery_success_at
            .is_some_and(|t| now.duration_since(t) < grace_window)
        {
            self.post_recovery_grace_descent_attempts = 0;
            self.last_recovery_success_at = Some(now);
        }
    }

    /// Record one successful configured-carrier recovery probe.
    /// Returns the new streak value; the clear decision (threshold,
    /// `shuffle_wires` hold) stays with the caller. When no window is
    /// installed at all (a previous success in this cycle already
    /// cleared it), resets the streak and reports `0` — a stray
    /// duplicate success must not double-stamp grace.
    pub(crate) fn note_recovery_success_streak(&mut self) -> u32 {
        if self.capped_to.is_none() && self.until.is_none() {
            self.recovery_probe_success_streak = 0;
            return 0;
        }
        self.recovery_probe_success_streak = self.recovery_probe_success_streak.saturating_add(1);
        self.recovery_probe_success_streak
    }

    /// Test seam: install a window directly so tests can pre-stage a
    /// "previously degraded" slot without converging through synthetic
    /// failures.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn seed_window(&mut self, until: Instant, cap: TransportMode) {
        self.until = Some(until);
        self.capped_to = Some(cap);
    }
}

#[cfg(test)]
#[path = "tests/carrier_descent_state.rs"]
mod tests;
