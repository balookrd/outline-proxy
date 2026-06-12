use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::config::TransportMode;

const WINDOW: Duration = Duration::from_secs(60);

/// Baseline runtime-style trigger: not from the probe loop, not a
/// recovery re-probe, operator threshold of 2.
fn runtime_trigger(now: Instant, new_cap: TransportMode, failed: TransportMode) -> DescentTrigger {
    DescentTrigger {
        now,
        duration: WINDOW,
        new_cap,
        failed_mode: failed,
        probe_trigger: false,
        is_recovery_fail: false,
        probe_min_failures: 2,
        probe_consecutive_failures: 0,
    }
}

fn applied(decision: DescentDecision) -> DescentApplied {
    match decision {
        DescentDecision::Applied(applied) => applied,
        DescentDecision::AbsorbedByGrace => panic!("expected Applied, got AbsorbedByGrace"),
    }
}

#[test]
fn fresh_state_has_no_window() {
    let state = CarrierDescentState::default();
    let now = Instant::now();
    assert!(!state.window_active(now));
    assert!(state.active_cap(now).is_none());
    assert!(!state.recovery_cooldown_active(now));
}

#[test]
fn first_trigger_installs_window_and_cap() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    let outcome = applied(state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    )));
    assert!(outcome.newly_started);
    assert!(outcome.advances_deadline);
    assert!(outcome.cap_changed);
    assert_eq!(outcome.updated_cap, TransportMode::XhttpH2);
    assert!(state.window_active(now));
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH2));
    assert_eq!(state.until(), Some(now + WINDOW));
}

#[test]
fn in_window_retrigger_never_raises_cap() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    // Walk to the family floor first: H3 fail caps to H2, H2 fail caps to H1.
    state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    ));
    state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH1,
        TransportMode::XhttpH2,
    ));
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH1));
    // A repeat H3-failure trigger inside the window must not raise the
    // ceiling back to H2.
    let outcome = applied(state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    )));
    assert!(!outcome.cap_changed);
    assert_eq!(outcome.updated_cap, TransportMode::XhttpH1);
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH1));
}

#[test]
fn probe_gate_holds_cap_until_min_failures() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    ));
    // Probe failure at the capped rank with a streak below min_failures:
    // the cap holds, the deadline still refreshes.
    let later = now + Duration::from_secs(10);
    let outcome = applied(state.apply_descent_trigger(DescentTrigger {
        probe_trigger: true,
        probe_consecutive_failures: 1,
        ..runtime_trigger(later, TransportMode::XhttpH1, TransportMode::XhttpH2)
    }));
    assert!(!outcome.cap_changed, "gated probe failure must hold the cap");
    assert!(outcome.advances_deadline);
    assert_eq!(state.active_cap(later), Some(TransportMode::XhttpH2));
    // Once the streak reaches min_failures the same trigger descends.
    let outcome = applied(state.apply_descent_trigger(DescentTrigger {
        probe_trigger: true,
        probe_consecutive_failures: 2,
        ..runtime_trigger(later, TransportMode::XhttpH1, TransportMode::XhttpH2)
    }));
    assert!(outcome.cap_changed);
    assert_eq!(state.active_cap(later), Some(TransportMode::XhttpH1));
}

#[test]
fn runtime_trigger_descends_at_cap_without_streak() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    ));
    // Runtime (non-probe) failure on the capped carrier descends
    // immediately — the at-cap gate only applies to probe triggers.
    let outcome = applied(state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH1,
        TransportMode::XhttpH2,
    )));
    assert!(outcome.cap_changed);
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH1));
}

#[test]
fn grace_absorbs_then_releases_on_budget() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.clear_and_open_grace(now);
    // min_failures = 2: the gate absorbs triggers while the budget is
    // below the threshold, i.e. the first two (0 -> 1 -> 2)…
    for expected_attempts in 1..=2 {
        let absorbed = state.apply_descent_trigger(runtime_trigger(
            now,
            TransportMode::XhttpH2,
            TransportMode::XhttpH3,
        ));
        assert!(matches!(absorbed, DescentDecision::AbsorbedByGrace));
        assert!(state.active_cap(now).is_none());
        assert_eq!(state.grace_attempts(), expected_attempts);
    }
    // …the third (budget exhausted) releases and installs the cap.
    let released = applied(state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    )));
    assert!(released.cap_changed);
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH2));
    // Cap install resets the grace budget for the next cycle.
    assert_eq!(state.grace_attempts(), 0);
}

#[test]
fn grace_renewal_resets_budget_and_slides_anchor() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.clear_and_open_grace(now);
    state.apply_descent_trigger(runtime_trigger(
        now,
        TransportMode::XhttpH2,
        TransportMode::XhttpH3,
    ));
    assert_eq!(state.grace_attempts(), 1);
    // A probe success inside the grace window resets the budget and
    // re-stamps the anchor, so absorption continues.
    let later = now + Duration::from_secs(30);
    state.renew_grace_if_active(later, WINDOW.saturating_mul(2));
    assert_eq!(state.grace_attempts(), 0);
    assert_eq!(state.last_recovery_success_at(), Some(later));
    // Outside the grace window the renewal is a no-op.
    let mut expired = CarrierDescentState::default();
    expired.renew_grace_if_active(later, WINDOW);
    assert!(expired.last_recovery_success_at().is_none());
}

#[test]
fn walk_up_steps_one_rank_and_holds_below_configured() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.seed_window(now + WINDOW, TransportMode::XhttpH1);
    // Streak below the threshold: no-op.
    let held = state.walk_up(now, WINDOW, TransportMode::XhttpH3, 2, 1);
    assert!(matches!(held, WalkUpOutcome::NoOp));
    // Streak met: one step up, window refreshed.
    let stepped = state.walk_up(now, WINDOW, TransportMode::XhttpH3, 2, 2);
    assert!(matches!(
        stepped,
        WalkUpOutcome::SteppedUp {
            from: TransportMode::XhttpH1,
            to: TransportMode::XhttpH2
        }
    ));
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH2));
    // One rank below configured: the final hop belongs to the recovery
    // probe, so walk-up holds.
    let held = state.walk_up(now, WINDOW, TransportMode::XhttpH3, 2, 2);
    assert!(matches!(held, WalkUpOutcome::NoOp));
    assert_eq!(state.active_cap(now), Some(TransportMode::XhttpH2));
}

#[test]
fn walk_up_clears_cross_family_cap() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.seed_window(now + WINDOW, TransportMode::XhttpH2);
    let outcome = state.walk_up(now, WINDOW, TransportMode::WsH3, 2, 2);
    assert!(matches!(outcome, WalkUpOutcome::Cleared { from: TransportMode::XhttpH2 }));
    assert!(state.active_cap(now).is_none());
    assert!(state.until().is_none());
}

#[test]
fn wire_change_reset_keeps_grace_anchor() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.clear_and_open_grace(now);
    // Exhaust the grace budget (two absorbed at min_failures = 2), then
    // the third trigger installs the cap.
    for _ in 0..3 {
        state.apply_descent_trigger(runtime_trigger(
            now,
            TransportMode::XhttpH2,
            TransportMode::XhttpH3,
        ));
    }
    assert!(state.active_cap(now).is_some());
    state.reset_window_for_wire_change();
    assert!(state.active_cap(now).is_none());
    assert!(state.until().is_none());
    assert_eq!(state.recovery_streak(), 0);
    assert!(!state.recovery_cooldown_active(now));
    // The grace anchor survives a wire rotation — rotation is not a
    // recovery event and must not reopen (or close) the grace window.
    assert_eq!(state.last_recovery_success_at(), Some(now));
}

#[test]
fn recovery_streak_counts_only_while_window_installed() {
    let mut state = CarrierDescentState::default();
    // No window at all: the streak resets and reports zero.
    assert_eq!(state.note_recovery_success_streak(), 0);
    let now = Instant::now();
    state.seed_window(now + WINDOW, TransportMode::WsH2);
    assert_eq!(state.note_recovery_success_streak(), 1);
    assert_eq!(state.note_recovery_success_streak(), 2);
}

#[test]
fn recovery_fail_parks_cooldown_and_resets_streak() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.seed_window(now + WINDOW, TransportMode::WsH2);
    assert_eq!(state.note_recovery_success_streak(), 1);
    let outcome = applied(state.apply_descent_trigger(DescentTrigger {
        is_recovery_fail: true,
        ..runtime_trigger(now, TransportMode::WsH2, TransportMode::WsH3)
    }));
    // Same cap re-written: not a change, but the recovery bookkeeping
    // still ran.
    assert!(!outcome.cap_changed);
    assert!(state.recovery_cooldown_active(now));
    assert_eq!(state.recovery_streak(), 0);
}

#[test]
fn clear_and_open_grace_resets_everything_and_stamps_anchor() {
    let mut state = CarrierDescentState::default();
    let now = Instant::now();
    state.seed_window(now + WINDOW, TransportMode::WsH2);
    state.note_recovery_success_streak();
    state.clear_and_open_grace(now);
    assert!(state.until().is_none());
    assert!(state.capped_to().is_none());
    assert!(!state.recovery_cooldown_active(now));
    assert_eq!(state.grace_attempts(), 0);
    assert_eq!(state.recovery_streak(), 0);
    assert_eq!(state.last_recovery_success_at(), Some(now));
}
