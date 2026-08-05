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
