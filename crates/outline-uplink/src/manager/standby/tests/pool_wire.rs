//! The pool is prewarmed on one wire. When the active wire moves — a shuffle
//! reroll, a failover — the pooled carriers belong to a wire nobody is
//! landing on any more. Handing one out would put a flow on a carrier the
//! manager does not consider active, which is precisely the split this whole
//! change removes.

use crate::config::SsPathKind;
use crate::types::{TransportKind, UplinkManager};

use super::{
    sample_manager_with_combined_ss_fallback, sample_manager_with_three_fallbacks,
    sample_manager_with_three_fallbacks_and_standby_capacity,
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

/// The drain-on-mismatch branch of `try_take_alive` removes every entry the
/// pool held — the one path that removes *everything* in a single take. Per
/// `try_take_alive`'s own invariant ("a take that removed anything from the
/// pool … schedules exactly ONE background refill"), it must schedule a
/// refill just like the ordinary pop loop does when it discards stale
/// entries. Before the fix it did not: the pool sat cold until the next
/// `WARM_STANDBY_MAINTENANCE_INTERVAL` sweep (15s) — precisely when a
/// rotation, often a failover, is pushing fresh flows at it.
#[tokio::test]
async fn draining_a_pool_filled_on_another_wire_schedules_a_refill() {
    let manager = sample_manager_with_three_fallbacks().await;
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 2).await;
    assert_eq!(
        manager.refill_spawned_count_for_test(0, TransportKind::Tcp),
        0,
        "nothing has asked for a refill yet"
    );

    manager.test_set_active_wire(0, TransportKind::Tcp, 2);
    let candidate = manager.tcp_candidates_for_test(0).await;
    let taken = manager.try_take_tcp_standby(&candidate, 2).await;

    assert!(taken.is_none(), "the pool held wire-0 carriers, not wire-2 ones");
    assert_eq!(manager.pool_len_for_test(0, TransportKind::Tcp), 0, "the drain must empty it");
    assert_eq!(
        manager.refill_spawned_count_for_test(0, TransportKind::Tcp),
        1,
        "a drain that removed everything must schedule exactly one refill, \
         not leave the pool to go cold until the next maintenance sweep"
    );
}

/// `refill` resolves its wire and stamps (or inherits) the pool's marker
/// before it starts dialing. If a rotation lands while that dial is still in
/// flight, a concurrent take can drain-and-restamp the pool for the new wire
/// before the dial completes — so by the time this refill reaches its push
/// site, the marker it is about to check already names a wire it never
/// dialed for. Pushing anyway would let that fresher marker vouch for a
/// carrier this refill dialed under the OLD wire's credentials. On TCP that
/// surfaces as one failed `do_tcp_ss_setup` and a silent fresh-dial retry; on
/// UDP there is no such recovery (see the UDP counterpart below) — the take
/// path builds the datagram transport straight off a pool pop it trusts
/// completely.
#[tokio::test]
async fn a_stream_dialed_before_a_rotation_is_not_pooled_once_the_marker_moves() {
    let manager = sample_manager_with_three_fallbacks_and_standby_capacity(1).await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 2);
    // Mirrors `refill` resolving `ctx.wire` against the wire that was active
    // when it started dialing.
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;
    assert_eq!(ctx.wire, 2, "this refill resolved against wire 2, active when it started");

    // A concurrent take for wire 0 drains (nothing there) and restamps the
    // marker to 0 while `ctx`'s dial is still in flight. `count = 0` stamps
    // the marker without seeding any entries — exactly what a drain of an
    // already-empty pool leaves behind.
    manager.fill_pool_for_test(0, TransportKind::Tcp, 0, 0).await;

    let ws = UplinkManager::dialed_stream_for_test().await;
    let pushed = ctx.try_pool_dialed_stream(ws).await;

    assert!(
        pushed.is_none(),
        "a stream dialed for wire 2 must not be pooled once the marker names wire 0"
    );
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Tcp),
        0,
        "the mismatched carrier must be dropped, not left where a wire-0 take could find it"
    );
}

/// UDP counterpart of the test above. This is the transport where the bug is
/// fatal rather than merely wasteful: `acquire_udp_standby_or_connect` builds
/// `UdpWsTransport::from_websocket` directly off whatever a pool take hands
/// it, with no protocol-level recovery the way a failed TCP setup gets — a
/// carrier dialed for one wire, handed out under another wire's credentials,
/// means every reused datagram is silently dropped.
#[tokio::test]
async fn a_udp_stream_dialed_before_a_rotation_is_not_pooled_once_the_marker_moves() {
    let manager = sample_manager_with_three_fallbacks_and_standby_capacity(1).await;
    manager.test_set_active_wire(0, TransportKind::Udp, 2);
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Udp).await;
    assert_eq!(ctx.wire, 2, "this refill resolved against wire 2, active when it started");

    manager.fill_pool_for_test(0, TransportKind::Udp, 0, 0).await;

    let ws = UplinkManager::dialed_stream_for_test().await;
    let pushed = ctx.try_pool_dialed_stream(ws).await;

    assert!(
        pushed.is_none(),
        "a UDP stream dialed for wire 2 must not be pooled once the marker names wire 0"
    );
    assert_eq!(
        manager.pool_len_for_test(0, TransportKind::Udp),
        0,
        "the mismatched carrier must be dropped, not left where a wire-0 take could find it"
    );
}
