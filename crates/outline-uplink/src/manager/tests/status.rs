//! The scoring projection ([`SelectionView`]) must answer every selection
//! question exactly as the full [`UplinkStatus`] it was copied from.
//!
//! Candidate building copies this view out from under the status lock instead of
//! cloning the whole status. The risk that buys is silent divergence: drop a
//! field from the projection (the per-wire EWMA slots are the dangerous one —
//! they used to ride along inside the cloned `Vec`s) and selection keeps working
//! while quietly ranking uplinks by a stale primary RTT. These tests pin the two
//! views together on a status that exercises every input the scoring path reads.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::{RoutingScope, TransportMode};
use crate::selection::{
    cooldown_active, cooldown_remaining, effective_health, effective_latency, score_latency,
    scoring_base_latency, selection_score,
};
use crate::tests::lb;
use crate::types::TransportKind;

use super::super::status::{PenaltyState, PerTransportStatus, UplinkStatus};

/// A status with every scoring input populated: the active wire is a fallback
/// (so `base_latency` must come from the per-wire EWMA slot, not primary's), a
/// failure penalty is decaying, a carrier-descent window is open (which adds
/// `failure_penalty_max` on top of the penalty) and a cooldown is running.
fn loaded_status(now: Instant) -> UplinkStatus {
    let mut tcp = PerTransportStatus {
        healthy: Some(true),
        latency: Some(Duration::from_millis(10)),
        rtt_ewma: Some(Duration::from_millis(20)),
        penalty: PenaltyState {
            value_secs: 0.75,
            updated_at: Some(now - Duration::from_secs(5)),
        },
        cooldown_until: Some(now + Duration::from_secs(7)),
        consecutive_successes: 3,
        active_wire: 1,
        fallback_rtt_ewma: vec![Some(Duration::from_millis(90))],
        ..PerTransportStatus::default()
    };
    tcp.descent
        .seed_window(now + Duration::from_secs(30), TransportMode::WsH2);

    let udp = PerTransportStatus {
        healthy: Some(false),
        latency: Some(Duration::from_millis(45)),
        rtt_ewma: Some(Duration::from_millis(50)),
        consecutive_successes: 1,
        ..PerTransportStatus::default()
    };

    UplinkStatus {
        tcp,
        udp,
        last_error: Some("upstream closed the data path (Close 1013)".to_string()),
        ..UplinkStatus::default()
    }
}

#[test]
fn selection_view_scores_identically_to_the_full_status() {
    let now = Instant::now();
    let config = lb();
    let status = loaded_status(now);
    let view = status.selection_view(&config, now);

    for transport in [TransportKind::Tcp, TransportKind::Udp] {
        assert_eq!(
            scoring_base_latency(&status, transport),
            scoring_base_latency(&view, transport),
            "{transport:?}: base latency must resolve through the active wire in both views",
        );
        assert_eq!(
            effective_latency(&status, transport, now, &config),
            effective_latency(&view, transport, now, &config),
            "{transport:?}: penalty + descent-window surcharge must match",
        );
        assert_eq!(
            score_latency(&status, 2.0, transport, now, &config),
            score_latency(&view, 2.0, transport, now, &config),
            "{transport:?}: weighted score must match",
        );
        assert_eq!(
            cooldown_active(&status, transport, now),
            cooldown_active(&view, transport, now),
        );
        assert_eq!(
            cooldown_remaining(&status, transport, now),
            cooldown_remaining(&view, transport, now),
        );
        assert_eq!(
            effective_health(&status, transport, now),
            effective_health(&view, transport, now),
        );

        for scope in [
            RoutingScope::Global,
            RoutingScope::PerUplink,
            RoutingScope::PerFlow,
            RoutingScope::PerClient,
        ] {
            assert_eq!(
                selection_score(&status, 2.0, transport, now, &config, scope),
                selection_score(&view, 2.0, transport, now, &config, scope),
                "{transport:?} / {scope:?}: selection score must match",
            );
        }
    }
}

/// The fields the strict-mode gates read straight off the candidate (probe
/// health for the failover reason, the success streak for auto-failback).
#[test]
fn selection_view_carries_the_strict_mode_gate_fields() {
    let now = Instant::now();
    let status = loaded_status(now);
    let view = status.selection_view(&lb(), now);

    assert_eq!(view.tcp.healthy, status.tcp.healthy);
    assert_eq!(view.udp.healthy, status.udp.healthy);
    assert_eq!(view.tcp.consecutive_successes, status.tcp.consecutive_successes);
    assert_eq!(view.udp.consecutive_successes, status.udp.consecutive_successes);
}

/// The projection must follow the active wire: primary's EWMA (20 ms) is stale
/// once `active_wire` has moved to the fallback whose own EWMA is 90 ms. A view
/// that copied `rtt_ewma` instead of resolving `base_latency` would silently
/// score this uplink 4.5× better than it deserves.
#[test]
fn selection_view_base_latency_follows_the_active_wire() {
    let now = Instant::now();
    let view = loaded_status(now).selection_view(&lb(), now);

    assert_eq!(view.tcp.base_latency, Some(Duration::from_millis(90)));
    assert_eq!(view.udp.base_latency, Some(Duration::from_millis(50)));
}

/// The field case: a 0.21 s path losing 3 % must rank behind a clean 0.30 s
/// path once the operator has set a coefficient — this is the ordering that
/// failed to happen on 2026-08-02.
///
/// (3 %, not the round 2 % the loss fixture might suggest at a glance: at
/// k=20 a 2 % loss only inflates 210ms to 294ms, which still trails 300ms —
/// the crossover needs the extra point of loss to actually flip the rank.)
#[test]
fn a_lossy_fast_path_ranks_behind_a_clean_slower_one() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;

    let mut lossy = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(210)),
        ..Default::default()
    };
    lossy.record_wire_loss_window(0, 10_000, 300, 200, 1.0);

    let clean = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(300)),
        ..Default::default()
    };

    assert!(
        lossy.base_latency_with(&config) > clean.base_latency_with(&config),
        "3% loss at k=20 inflates 210ms past a clean 300ms path"
    );
}

/// Cold-start window right after a wire flip: `active_wire` has moved to a
/// fallback with no RTT sample of its own yet, so the base latency falls
/// back to primary's EWMA. That base must be paired with **primary's own**
/// loss slot, not the active (fallback) wire's — mixing them would score a
/// primary latency sample against an unrelated wire's loss verdict. The two
/// wires are given deliberately different loss so a wire mix-up is visible:
/// primary is heavily lossy (40%, clamped to the cap) and the active
/// fallback wire is nearly clean (1%) — a mix-up would produce a barely
/// inflated result instead of a capped one.
#[test]
fn base_latency_with_pairs_a_primary_fallback_with_primarys_own_loss() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;

    let mut status = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(100)),
        active_wire: 1,
        // The active wire's own RTT slot has no sample yet.
        fallback_rtt_ewma: vec![None],
        ..Default::default()
    };
    status.record_wire_loss_window(0, 10_000, 4_000, 200, 1.0); // primary: 40% loss
    status.record_wire_loss_window(1, 10_000, 100, 200, 1.0); // active wire: 1% loss

    // Sanity: `active_wire_loss()` really does report the *other* wire's
    // (1%) verdict here — this test only means something if that verdict is
    // NOT what gets applied.
    assert_eq!(status.active_wire_loss().ratio(), Some(0.01));

    // Primary's 40% loss at k=20 would inflate by 1+20*0.4=9.0, clamped to
    // the 4.0 cap: 100ms * 4.0 = 400ms. The active wire's 1% loss would only
    // inflate by 1+20*0.01=1.2 (120ms) — a mix-up would produce that instead.
    assert_eq!(status.base_latency_with(&config), Some(Duration::from_millis(400)));
}

/// With the shipped default the inflation is inert, so today's ranking is
/// preserved exactly.
#[test]
fn the_default_coefficient_leaves_base_latency_untouched() {
    let config = crate::tests::lb();
    // `lb()` is a hand-written test fixture local to this crate, not the
    // shipped default — the actual default lives in the config loader,
    // `bins/outline-ws-rust/src/config/load/balancing.rs`
    // (`loss_latency_penalty_k.unwrap_or(0.0)`), which this crate cannot
    // import (it is a dependency of that binary, not the reverse). This
    // assertion pins the fixture to the value the loader defaults to, so
    // the test's premise ("with the shipped default...") stays honest if
    // the two ever drift apart.
    assert_eq!(config.loss_latency_penalty_k, 0.0);

    let mut status = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(210)),
        ..Default::default()
    };
    status.record_wire_loss_window(0, 10_000, 5_000, 200, 1.0);

    assert_eq!(status.base_latency_with(&config), Some(Duration::from_millis(210)));
}

/// Loss without a latency sample must not invent one: an uplink that has never
/// been measured stays unranked rather than being handed a fabricated score.
#[test]
fn loss_alone_does_not_synthesise_a_latency() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;

    let mut status = PerTransportStatus::default();
    status.record_wire_loss_window(0, 10_000, 500, 200, 1.0);

    assert_eq!(status.base_latency_with(&config), None);
}

/// `reset_wire_loss` clears exactly the named wire's verdict — a lossy
/// uplink that stops carrying traffic must read as "not measured" again
/// (see [`crate::loss::LossEwma::reset`]), but resetting the primary must
/// not disturb an unrelated fallback wire's own, still-current verdict.
#[test]
fn reset_wire_loss_clears_only_the_named_wire() {
    let mut status = PerTransportStatus::default();
    status.record_wire_loss_window(0, 1_000, 100, 200, 1.0);
    status.record_wire_loss_window(1, 1_000, 100, 200, 1.0);

    status.reset_wire_loss(0);

    assert_eq!(status.carrier_loss.ratio(), None, "primary's verdict is cleared");
    assert_eq!(
        status.fallback_carrier_loss[0].ratio(),
        Some(0.1),
        "an unrelated fallback wire must be untouched"
    );

    status.reset_wire_loss(1);
    assert_eq!(status.fallback_carrier_loss[0].ratio(), None, "the fallback resets too");
}
