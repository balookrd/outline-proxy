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
    let view = status.selection_view();

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
    let view = status.selection_view();

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
    let view = loaded_status(now).selection_view();

    assert_eq!(view.tcp.base_latency, Some(Duration::from_millis(90)));
    assert_eq!(view.udp.base_latency, Some(Duration::from_millis(50)));
}
