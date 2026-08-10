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
use crate::rtt::RttEwma;
use crate::selection::{
    TransportStatusView, cooldown_active, cooldown_remaining, effective_health, effective_latency,
    score_latency, scoring_base_latency, selection_score,
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
        rtt_ewma: RttEwma::measured(Duration::from_millis(20), now),
        penalty: PenaltyState {
            value_secs: 0.75,
            updated_at: Some(now - Duration::from_secs(5)),
        },
        cooldown_until: Some(now + Duration::from_secs(7)),
        consecutive_successes: 3,
        active_wire: 1,
        fallback_rtt_ewma: vec![RttEwma::measured(Duration::from_millis(90), now)],
        ..PerTransportStatus::default()
    };
    tcp.descent
        .seed_window(now + Duration::from_secs(30), TransportMode::WsH2);

    let udp = PerTransportStatus {
        healthy: Some(false),
        latency: Some(Duration::from_millis(45)),
        rtt_ewma: RttEwma::measured(Duration::from_millis(50), now),
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
    let now = Instant::now();
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;

    let mut lossy = PerTransportStatus {
        rtt_ewma: RttEwma::measured(Duration::from_millis(210), now),
        ..Default::default()
    };
    lossy.record_wire_loss_window(0, 10_000, 300, 200, 1.0);

    let clean = PerTransportStatus {
        rtt_ewma: RttEwma::measured(Duration::from_millis(300), now),
        ..Default::default()
    };

    assert!(
        lossy.base_latency_with(&config, now) > clean.base_latency_with(&config, now),
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
    let now = Instant::now();
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;

    let mut status = PerTransportStatus {
        rtt_ewma: RttEwma::measured(Duration::from_millis(100), now),
        active_wire: 1,
        // The active wire's own RTT slot has no sample yet.
        fallback_rtt_ewma: vec![RttEwma::default()],
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
    assert_eq!(status.base_latency_with(&config, now), Some(Duration::from_millis(400)));
}

/// With the shipped default the inflation is inert, so today's ranking is
/// preserved exactly.
#[test]
fn the_default_coefficient_leaves_base_latency_untouched() {
    let now = Instant::now();
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
        rtt_ewma: RttEwma::measured(Duration::from_millis(210), now),
        ..Default::default()
    };
    status.record_wire_loss_window(0, 10_000, 5_000, 200, 1.0);

    assert_eq!(status.base_latency_with(&config, now), Some(Duration::from_millis(210)));
}

/// Loss without a latency sample must not invent one: an uplink that has never
/// been measured stays unranked rather than being handed a fabricated score.
#[test]
fn loss_alone_does_not_synthesise_a_latency() {
    let now = Instant::now();
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;

    let mut status = PerTransportStatus::default();
    status.record_wire_loss_window(0, 10_000, 500, 200, 1.0);

    assert_eq!(status.base_latency_with(&config, now), None);
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

/// The 2026-08-10 shape: `active_wire` is on a fallback whose slot holds a
/// four-second sample taken while the carrier was broken, primary's slot has
/// since been re-measured healthy, and nothing refreshes the fallback slot
/// because ranking keeps the uplink starved of the traffic that would.
///
/// Fresh, that stale sample must still rank the uplink exactly as badly as it
/// does today — this is the "a carrier that just failed does not get waved
/// back in" half. It is only with age that it gives ground.
#[test]
fn a_stale_active_wire_slot_fades_toward_the_next_link() {
    let config = crate::tests::lb();
    let halflife = config.rtt_ewma_halflife;
    let now = Instant::now();

    let broken = Duration::from_millis(4_000);
    let healthy = Duration::from_millis(250);
    let status_at = |measured_at| PerTransportStatus {
        active_wire: 1,
        fallback_rtt_ewma: vec![RttEwma::measured(broken, measured_at)],
        rtt_ewma: RttEwma::measured(healthy, now),
        ..Default::default()
    };

    assert_eq!(
        status_at(now).base_latency_with(&config, now),
        Some(broken),
        "a just-measured slot ranks at full strength, decay or no decay",
    );

    let one_halflife = status_at(now - halflife)
        .base_latency_with(&config, now)
        .expect("a measured uplink stays ranked");
    let midpoint = (broken + healthy) / 2;
    assert!(
        one_halflife.abs_diff(midpoint) < Duration::from_millis(5),
        "at one half-life the slot carries half the weight: expected ~{midpoint:?}, got \
         {one_halflife:?}",
    );

    assert_eq!(
        status_at(now - halflife * crate::rtt::EXPIRY_HALFLIVES).base_latency_with(&config, now),
        Some(healthy),
        "past the expiry horizon ranking is left with primary's own measurement",
    );
}

/// Decay fades toward the next *measured* link, never toward zero. A slot that
/// is the only measurement this uplink has keeps its full weight however old
/// it is: discarding it would drop the uplink out of ranking entirely, which
/// claims far more than "this number is old".
#[test]
fn decay_never_ranks_an_uplink_better_than_something_measured() {
    let config = crate::tests::lb();
    let now = Instant::now();
    let ancient = now - config.rtt_ewma_halflife * 100;

    let only_measurement = PerTransportStatus {
        active_wire: 1,
        fallback_rtt_ewma: vec![RttEwma::measured(Duration::from_millis(4_000), ancient)],
        ..Default::default()
    };

    assert_eq!(
        only_measurement.base_latency_with(&config, now),
        Some(Duration::from_millis(4_000)),
        "with nothing behind it in the chain, an old slot is still the best evidence there is",
    );
}

/// The off switch: `rtt_ewma_halflife = 0` must reproduce pre-decay ranking
/// bit for bit, however old the slot is.
#[test]
fn zero_halflife_restores_the_abrupt_chain() {
    let mut config = crate::tests::lb();
    config.rtt_ewma_halflife = Duration::ZERO;
    let now = Instant::now();

    let status = PerTransportStatus {
        active_wire: 1,
        fallback_rtt_ewma: vec![RttEwma::measured(
            Duration::from_millis(4_000),
            now - Duration::from_secs(86_400),
        )],
        rtt_ewma: RttEwma::measured(Duration::from_millis(250), now),
        ..Default::default()
    };

    assert_eq!(
        status.base_latency_with(&config, now),
        Some(Duration::from_millis(4_000)),
        "with decay off the first link with a value wins outright",
    );
    assert_eq!(
        status.base_latency_with(&config, now),
        TransportStatusView::base_latency(&status),
        "and it agrees with the config-free chain, which never decays",
    );
}

/// Each link is inflated by the loss verdict of the wire **it** came from,
/// and that survives the blend: a half-faded slot must land halfway between
/// the two *inflated* values, not between the raw ones. Getting this wrong
/// would apply the active wire's loss to primary's latency once the blend
/// starts mixing them.
#[test]
fn blending_keeps_each_links_loss_attributed_to_its_own_wire() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;
    let now = Instant::now();

    let mut status = PerTransportStatus {
        active_wire: 1,
        fallback_rtt_ewma: vec![RttEwma::measured(
            Duration::from_millis(200),
            now - config.rtt_ewma_halflife,
        )],
        rtt_ewma: RttEwma::measured(Duration::from_millis(100), now),
        ..Default::default()
    };
    status.record_wire_loss_window(0, 10_000, 1_000, 200, 1.0); // primary: 10% loss
    status.record_wire_loss_window(1, 10_000, 500, 200, 1.0); // active wire: 5% loss

    // Active wire: 200ms × (1 + 20×0.05) = 400ms. Primary: 100ms × (1 +
    // 20×0.10) = 300ms. At one half-life the blend is their midpoint, 350ms.
    // Swapping the two verdicts would give 200×3.0 = 600 and 100×2.0 = 200,
    // blending to 400ms instead.
    let ranked = status.base_latency_with(&config, now).expect("both links measured");
    assert!(
        ranked.abs_diff(Duration::from_millis(350)) < Duration::from_millis(5),
        "expected the midpoint of each link's own inflated value (~350ms), got {ranked:?}",
    );
}
