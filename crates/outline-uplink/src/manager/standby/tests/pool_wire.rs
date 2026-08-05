//! The pool is prewarmed on one wire. When the active wire moves — a shuffle
//! reroll, a failover — the pooled carriers belong to a wire nobody is
//! landing on any more. Handing one out would put a flow on a carrier the
//! manager does not consider active, which is precisely the split this whole
//! change removes.

use crate::config::SsPathKind;
use crate::types::TransportKind;

use super::{
    sample_manager_with_combined_ss_fallback, sample_manager_with_three_fallbacks,
    sample_manager_with_three_fallbacks_gate_off,
};

#[tokio::test]
async fn a_pool_filled_on_another_wire_is_drained_rather_than_handed_out() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 2).await;
    assert_eq!(manager.pool_len_for_test(0, TransportKind::Tcp), 2);

    manager.test_set_active_wire(0, TransportKind::Tcp, 2);
    let candidate = manager.tcp_candidates_for_test(0).await;
    let taken = manager.try_take_tcp_standby(&candidate, 2).await;

    assert!(taken.is_none(), "a wire-0 carrier must not serve a wire-2 flow");
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Tcp),
        0,
        "the stale pool is drained so the refill can repopulate on the active wire"
    );
}

#[tokio::test]
async fn asking_for_a_wire_the_pool_does_not_serve_does_not_drain_it() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 0);
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 2).await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let taken = manager.try_take_tcp_standby(&candidate, 3).await;

    assert!(taken.is_none(), "wire 3 is not what the pool holds");
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Tcp),
        2,
        "draining here would fight the refill loop forever: drain, refill on \
         the active wire, drain again on the next take for another wire"
    );
}

#[tokio::test]
async fn the_pool_dials_the_active_wire_on_refill() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 2);

    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;

    assert_eq!(ctx.wire, 2, "refill must prewarm the wire flows will actually land on");
}

/// Gate-inertness: a deployed binary with `tun_wire_dial` off must keep
/// prewarming wire 0 exactly as it does today, no matter what `active_wire`
/// has drifted to underneath it. `shuffle_timer` and wire failover both move
/// `active_wire` regardless of the gate, so reading it unconditionally here
/// would prewarm a wire nothing actually dials and every take would miss.
#[tokio::test]
async fn with_the_gate_off_the_pool_stays_on_wire_zero_regardless_of_active_wire() {
    let manager = sample_manager_with_three_fallbacks_gate_off().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 2);

    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;

    assert_eq!(ctx.wire, 0, "the gate is off: the pool must not follow active_wire");
}

/// The combined-SS discriminator a pool's dials carry must come from the
/// wire actually being prewarmed, not from the parent uplink. A split-path
/// primary alongside a combined-SS fallback makes a regression to the
/// parent's shape observable: that bug would read `None` for the fallback's
/// pool too, silently landing every reused datagram on the wrong server-side
/// relay leg.
#[tokio::test]
async fn the_combined_ss_discriminator_comes_from_the_wire_not_the_parent() {
    let manager = sample_manager_with_combined_ss_fallback().await;

    let primary_ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;
    assert_eq!(
        primary_ctx.combined_ss, None,
        "the split-path primary (wire 0) carries no discriminator"
    );

    manager.test_set_active_wire(0, TransportKind::Tcp, 1);
    let fallback_ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;
    assert_eq!(
        fallback_ctx.combined_ss,
        Some(SsPathKind::Tcp),
        "wire 1 is combined-SS: its pool must dial with the TCP-leg \
         discriminator, not fall through to the split-path parent's None"
    );
}

/// A carrier handed out of a pool that has rolled onto a fallback wire must
/// have its loss probe filed under that wire, not the literal primary slot
/// the take used before the pool could follow rotation. Filing it under `0`
/// would put the loss verdict in a slot nothing reads once `active_wire`
/// moves off primary, and could let a fallback's descent cap primary's.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_pool_take_on_a_fallback_wire_registers_its_loss_probe_under_that_wire() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 2);
    manager.fill_pool_for_test(0, TransportKind::Tcp, 2, 1).await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let taken = manager.try_take_tcp_standby(&candidate, 2).await;

    assert!(
        taken.is_some(),
        "the pool is correctly marked for wire 2 and must hand out its entry"
    );
    assert_eq!(
        manager.registered_loss_probe_wires_for_test(0, TransportKind::Tcp),
        std::collections::HashSet::from([2]),
        "the probe must be filed under wire 2, not the literal primary slot"
    );
}
