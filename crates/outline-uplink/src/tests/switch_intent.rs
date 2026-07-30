//! Which [`SwitchIntent`] each repoint path publishes, and what that intent
//! means for a live session on the uplink the pointer moved off.
//!
//! The intent replaced a `soft: bool`, which could only say "the operator asked
//! for a soft switch". Everything else — a probe failover, a runtime-failure
//! failover, an auto-failback, the initial selection — published `soft = false`
//! and was therefore indistinguishable from an operator *hard* switch, i.e.
//! from a deliberate decision to abandon those sessions. These tests pin the
//! distinction down at its source, so a future path that repoints the pointer
//! has to say which kind of switch it is.

use rand::SeedableRng as _;

use crate::config::{LoadBalancingConfig, LoadBalancingMode, RoutingScope, TargetAddr};
use crate::types::{SwitchIntent, TransportKind, UplinkManager};

use super::{lb, make_uplink, probe_disabled};

fn strict_manager(shared_resume: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![make_uplink("a", "ws://a.invalid/ws"), make_uplink("b", "ws://b.invalid/ws")],
        probe_disabled(),
        LoadBalancingConfig {
            mode: LoadBalancingMode::ActivePassive,
            routing_scope: RoutingScope::Global,
            shared_resume,
            ..lb()
        },
    )
    .unwrap()
}

#[test]
fn only_an_operator_hard_switch_abandons_sessions_on_a_cluster() {
    assert!(
        !SwitchIntent::OperatorHard.migrates_live_flows(true),
        "a hard switch is a drain: under a mesh a migrated session is relayed \
         back to the very home being drained, so it must abort",
    );
    assert!(SwitchIntent::OperatorSoft.migrates_live_flows(true));
    assert!(
        SwitchIntent::Failover.migrates_live_flows(true),
        "a health failover is not a decision to abandon sessions",
    );
}

#[test]
fn nothing_migrates_off_a_cluster() {
    // No shared resume scope: the new active is a different server with nothing
    // parked for the session, so every intent must abort. Without this the
    // cluster rule above would also be satisfied by "migrate whenever the
    // pointer moves".
    for intent in [SwitchIntent::OperatorHard, SwitchIntent::OperatorSoft, SwitchIntent::Failover] {
        assert!(
            !intent.migrates_live_flows(false),
            "{intent:?} must not migrate off a shared_resume group",
        );
    }
}

#[tokio::test]
async fn an_operator_switch_publishes_the_operator_intent_it_applied() {
    let mgr = strict_manager(true);
    mgr.set_active_uplink_by_name("a", None, false).await.unwrap();
    assert_eq!(mgr.active_uplinks_snapshot().intent, SwitchIntent::OperatorHard);

    let (_index, applied_soft) = mgr.set_active_uplink_by_name("b", None, true).await.unwrap();
    assert!(applied_soft, "a shared_resume group honours the soft request");
    assert_eq!(mgr.active_uplinks_snapshot().intent, SwitchIntent::OperatorSoft);
}

#[tokio::test]
async fn a_soft_request_clamped_off_a_cluster_publishes_a_hard_intent() {
    // The clamp already existed; what matters is that the snapshot reports the
    // *effective* switch, so no consumer tries a migration the group cannot do.
    let mgr = strict_manager(false);
    let (_index, applied_soft) = mgr.set_active_uplink_by_name("b", None, true).await.unwrap();
    assert!(!applied_soft);
    assert_eq!(mgr.active_uplinks_snapshot().intent, SwitchIntent::OperatorHard);
}

#[tokio::test]
async fn a_runtime_failure_failover_publishes_the_failover_intent() {
    let mgr = strict_manager(true);
    mgr.set_active_uplink_by_name("a", None, false).await.unwrap();
    assert_eq!(mgr.active_uplinks_snapshot().intent, SwitchIntent::OperatorHard);

    // Put the active into runtime cooldown and run one strict selection — the
    // path a mass carrier death takes.
    mgr.report_runtime_failure(0, TransportKind::Tcp, &anyhow::anyhow!("carrier died"))
        .await;
    let _ = mgr
        .tcp_candidates(&TargetAddr::Domain("example.com".to_string(), 443))
        .await;

    assert_eq!(
        mgr.active_uplinks_snapshot().tcp_for(true),
        Some(1),
        "the failover moved the pointer",
    );
    assert_eq!(
        mgr.active_uplinks_snapshot().intent,
        SwitchIntent::Failover,
        "a failover must not masquerade as an operator drain",
    );
}

#[tokio::test]
async fn a_scheduled_reselect_carries_the_operators_configured_intent() {
    let mgr = strict_manager(true);
    // The reselect draw only considers probe-healthy candidates; with probing
    // off nothing is healthy and the draw would report `NoCandidate`, leaving
    // the snapshot from `initialize_strict_active_selection` in place — which
    // would make this test pass for the wrong reason.
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr.initialize_strict_active_selection().await;

    let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let outcome = mgr
        .reselect_active_uplink_with_rng("scheduled", false, &mut rng)
        .await;
    assert!(matches!(outcome, crate::ReselectOutcome::Switched { .. }), "got {outcome:?}");
    assert_eq!(
        mgr.active_uplinks_snapshot().intent,
        SwitchIntent::OperatorHard,
        "a hard scheduled reselect is a drain, like an explicit hard switch",
    );

    let outcome = mgr.reselect_active_uplink_with_rng("scheduled", true, &mut rng).await;
    assert!(matches!(outcome, crate::ReselectOutcome::Switched { .. }), "got {outcome:?}");
    assert_eq!(mgr.active_uplinks_snapshot().intent, SwitchIntent::OperatorSoft);
}

/// The pre-switch snapshot must not read as an abandonment: a group that has
/// never repointed publishes no active index at all, so the intent is never
/// consulted — but if it ever is, the default is the conservative one.
#[tokio::test]
async fn the_initial_snapshot_carries_the_default_intent() {
    let mgr = strict_manager(true);
    let snapshot = mgr.active_uplinks_snapshot();
    assert_eq!(snapshot.intent, SwitchIntent::default());
    assert_eq!(snapshot.intent, SwitchIntent::OperatorHard);
    assert_eq!(snapshot.tcp_for(true), None, "nothing is stranded before the first switch");
}
