//! `tun_flows_active` accounting across an uplink migration.
//!
//! The gauge is keyed by `(group, uplink)` and moved by `record_tun_flow_created`
//! / `record_tun_flow_closed`. A tunnelled flow can change uplinks mid-life
//! (soft switch, runtime failover), and until the move was accounted for, the
//! `+1` stayed on the uplink the flow started on while the `-1` landed on the
//! one it ended on — the series drifted apart by one per migration and the
//! destination went negative. Production showed exactly that: `nuxt2 = +177`
//! against `sebek = -177` on one node, and a minimum of -491 over 14 days on
//! another. Direct flows never drifted, because they never migrate.

use std::time::Duration;

use super::test_guard;
use crate::{move_tun_flow_active, record_tun_flow_closed, record_tun_flow_created};

fn active(group: &str, uplink: &str) -> i64 {
    crate::METRICS
        .tun_flows_active
        .with_label_values(&[group, uplink])
        .get()
}

#[test]
fn a_migrated_flow_leaves_no_residue_on_either_uplink() {
    let _guard = test_guard();
    let group = "tun-flow-gauge-migration";

    record_tun_flow_created(group, "alpha");
    assert_eq!(active(group, "alpha"), 1);

    move_tun_flow_active(group, "alpha", "beta");
    assert_eq!(active(group, "alpha"), 0, "the flow no longer sits on the uplink it left");
    assert_eq!(active(group, "beta"), 1, "it is counted on the uplink it moved to");

    record_tun_flow_closed(group, "beta", "test", Duration::from_secs(1));
    assert_eq!(active(group, "alpha"), 0, "no +1 stranded on the original uplink");
    assert_eq!(active(group, "beta"), 0, "and no -1 left behind on the new one");
}

/// Several migrations in a row must still settle at zero — a flow can be moved
/// repeatedly by successive failovers.
#[test]
fn repeated_migrations_still_settle_at_zero() {
    let _guard = test_guard();
    let group = "tun-flow-gauge-repeat";

    record_tun_flow_created(group, "one");
    move_tun_flow_active(group, "one", "two");
    move_tun_flow_active(group, "two", "three");
    move_tun_flow_active(group, "three", "one");
    assert_eq!(active(group, "one"), 1, "back where it started, counted once");
    assert_eq!(active(group, "two"), 0);
    assert_eq!(active(group, "three"), 0);

    record_tun_flow_closed(group, "one", "test", Duration::from_secs(1));
    for uplink in ["one", "two", "three"] {
        assert_eq!(active(group, uplink), 0, "{uplink} settled at zero");
    }
}

/// A no-op move must not touch the gauge: `bind_flow_uplink` re-binds a flow to
/// the uplink it is already on (re-dial of the same target), and double-counting
/// there would drift the series the other way.
#[test]
fn moving_a_flow_onto_its_current_uplink_is_a_no_op() {
    let _guard = test_guard();
    let group = "tun-flow-gauge-noop";

    record_tun_flow_created(group, "same");
    move_tun_flow_active(group, "same", "same");
    assert_eq!(active(group, "same"), 1, "still exactly one flow, not two");

    record_tun_flow_closed(group, "same", "test", Duration::from_secs(1));
    assert_eq!(active(group, "same"), 0);
}
