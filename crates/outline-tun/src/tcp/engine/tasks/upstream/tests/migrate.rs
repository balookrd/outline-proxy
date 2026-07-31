use outline_transport::uplink_replay::ReplayError;

use super::*;

/// The two ways an uplink replay can fail report themselves as distinct metric
/// series.
///
/// They are not two flavours of one problem. `evicted` says the flow's own ring
/// no longer holds bytes the server is still missing — the ring is too small for
/// how far behind that upstream ran, and sizing it is the lever. `ahead` says
/// the server claims to have forwarded bytes the flow never sent — an
/// accounting desync, where sizing anything would change nothing.
///
/// Reporting both on one counter is what made a production run unreadable: 29
/// failures that could have been either, with no way to tell them apart short of
/// re-deploying a debug build onto a live client.
#[test]
fn an_uplink_replay_failure_names_which_side_lost_the_bytes() {
    let evicted = uplink_replay_failure_event(&ReplayError::OffsetEvicted {
        requested: 10,
        oldest_available: 4096,
    });
    let ahead = uplink_replay_failure_event(&ReplayError::OffsetAhead {
        requested: 8192,
        total_sent: 4096,
    });

    assert_eq!(evicted, "carrier_migration_replay_evicted");
    assert_eq!(ahead, "carrier_migration_replay_ahead");
    assert_ne!(evicted, ahead, "the two causes must not share a series");
}
