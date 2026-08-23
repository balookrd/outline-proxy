use std::time::Duration;

use super::*;

/// The default has to survive untouched: it is what every deployment that never
/// sets the knob keeps running with, and the hand-tuned constants it replaced
/// were 10 s for a fresh dial and 7 s for opening an H3 stream.
#[test]
fn defaults_match_the_constants_they_replaced() {
    assert_eq!(DEFAULT_DIAL_TIMEOUT, Duration::from_secs(10));
    assert_eq!(h3_stream_from(DEFAULT_DIAL_TIMEOUT), Duration::from_secs(7));
}

/// A too-small value is the dangerous direction — it turns every handshake into
/// a failure — so it is clamped rather than honoured.
#[test]
fn a_dial_budget_below_the_floor_is_clamped() {
    assert_eq!(clamp_dial_timeout(Duration::from_millis(200)), MIN_DIAL_TIMEOUT);
    assert_eq!(clamp_dial_timeout(Duration::ZERO), MIN_DIAL_TIMEOUT);
}

/// Past the ceiling the bound stops bounding anything, so it is capped too.
#[test]
fn a_dial_budget_above_the_ceiling_is_clamped() {
    assert_eq!(clamp_dial_timeout(Duration::from_secs(600)), MAX_DIAL_TIMEOUT);
}

/// Everything in between is taken as written.
#[test]
fn a_dial_budget_within_range_is_kept() {
    let edge_class = Duration::from_secs(45);
    assert_eq!(clamp_dial_timeout(edge_class), edge_class);
}

/// The H3 stream bound scales with the connect bound instead of staying pinned
/// at 7 s — the point of raising the knob on a 2 G link is that *every* stage of
/// the dial gets more room.
#[test]
fn the_h3_stream_bound_scales_with_the_dial_budget() {
    assert_eq!(h3_stream_from(Duration::from_secs(60)), Duration::from_secs(42));
    // …and never collapses to nothing at the floor.
    assert!(h3_stream_from(MIN_DIAL_TIMEOUT) >= Duration::from_secs(1));
}

/// The whole point of the atomic: a phone that starts on Wi-Fi and walks into a
/// 2G cell has to widen the bound without the tunnel being torn down.
///
/// Serialised with the reset test below — they share process-wide state, and
/// Rust runs tests in parallel by default.
#[test]
fn the_budget_can_be_re_sized_and_reset() {
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    set_dial_timeout(Some(Duration::from_secs(60)));
    assert_eq!(fresh_connect_timeout(), Duration::from_secs(60));
    assert_eq!(h3_open_stream_timeout(), Duration::from_secs(42));

    // Walking back onto a fast link restores the default rather than leaving the
    // wide bound behind, where it would slow every failover down.
    set_dial_timeout(None);
    assert_eq!(fresh_connect_timeout(), DEFAULT_DIAL_TIMEOUT);

    // Out-of-range values are clamped on this path too.
    set_dial_timeout(Some(Duration::from_millis(1)));
    assert_eq!(fresh_connect_timeout(), MIN_DIAL_TIMEOUT);
    set_dial_timeout(None);
}

/// `init_dial_timeout(None)` is the "config said nothing" case and must not
/// disturb a budget an embedder already installed.
#[test]
fn config_silence_does_not_clear_an_installed_budget() {
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    set_dial_timeout(Some(Duration::from_secs(30)));
    init_dial_timeout(None);
    assert_eq!(fresh_connect_timeout(), Duration::from_secs(30));
    set_dial_timeout(None);
}

/// Guards the process-wide budget for the two tests that mutate it.
static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
