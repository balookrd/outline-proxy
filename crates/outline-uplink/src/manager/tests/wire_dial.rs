//! The wire loop's contract, which is easy to get subtly wrong in two ways:
//! a failure *after* the dial (the SS handshake, say) must retire the wire
//! just as a failed dial does, and exhausting the chain must surface one
//! error without any intermediate parent-level runtime failure — otherwise
//! one broken carrier flaps the whole uplink out of the candidate set.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, anyhow};

use crate::manager::wire_dial::WireAttempt;
use crate::types::TransportKind;

use super::sample_manager_with_three_fallbacks;

#[tokio::test]
async fn a_build_failure_advances_the_chain_just_like_a_dial_failure() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;
    let attempts = Arc::new(AtomicUsize::new(0));

    let seen = Arc::clone(&attempts);
    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, move |wire| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                if wire == 3 {
                    Ok(WireAttempt::Built(wire))
                } else {
                    // Stands in for an SS handshake that fails after a
                    // perfectly successful dial.
                    Err(anyhow!("handshake failed on wire {wire}"))
                }
            }
        })
        .await;

    let (value, wire) = result.expect("wire 3 succeeds");
    assert_eq!(value, 3);
    assert_eq!(wire, 3, "the winning wire is reported to the caller");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        4,
        "every wire is tried once, in order, until one builds"
    );
}

#[tokio::test]
async fn exhausting_every_wire_yields_one_error() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    let error = result.expect_err("no wire can build");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("all wires failed"),
        "the caller needs one error it can attribute to the uplink, got: {rendered}"
    );
}

#[tokio::test]
async fn a_single_wire_failure_carries_no_all_wires_failed_wrapper() {
    // Gate-off (and any uplink with no fallbacks) only ever attempts wire 0,
    // so its failure must surface exactly as it did before this loop existed
    // — not wrapped in a context meant for a genuine multi-wire exhaustion.
    // That wrapper doubles the uplink name into the error text and, worse,
    // becomes the metric `detail` label (see
    // `normalize_other_runtime_failure_detail`), burying the real cause.
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, false, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    let error = result.expect_err("the only wire tried fails");
    let rendered = format!("{error:#}");
    assert_eq!(
        rendered, "wire 0 is down",
        "a single-wire attempt must not gain the multi-wire wrapper, got: {rendered}"
    );
}

#[tokio::test]
async fn a_not_applicable_wire_is_skipped_without_recording_an_outcome() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let (value, wire) = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            if wire == 0 {
                Ok(WireAttempt::NotApplicable)
            } else {
                Ok(WireAttempt::Built(wire))
            }
        })
        .await
        .expect("a later wire builds");

    assert_eq!(value, wire);
    assert_ne!(wire, 0);
    assert_eq!(
        manager.wire_outcome_count_for_test(0, TransportKind::Tcp, 0),
        0,
        "a wire that never ran must not move its own state machine"
    );
}

#[tokio::test]
async fn gate_off_records_no_outcome_even_on_failure() {
    // `tun_wire_dial` off means a node is deployed inert: it must be able to
    // fail its only attempt (wire 0) without touching the shared active-wire
    // state machine, because the SOCKS ingress on the same `UplinkManager`
    // reads that state when it builds its own dial order. If gate-off wrote
    // outcomes, a flag documented as inert would change SOCKS's behaviour.
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, false, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    result.expect_err("the only wire tried fails");
    assert_eq!(
        manager.wire_outcome_count_for_test(0, TransportKind::Tcp, 0),
        0,
        "gate-off must not record any outcome, even a failure on wire 0"
    );
}
