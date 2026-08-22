use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use super::{CONN_CLASS_LOCAL_DROP, ConnLife, ConnLifeGuard, ConnLifeLevel};

fn life(level: ConnLifeLevel) -> Arc<ConnLife> {
    ConnLife::open(1, "198.51.100.1:443".to_string(), "h3", level, Arc::new(AtomicU64::new(0)))
}

/// A shared (cached) carrier logs its pair at info; a probe connection — one
/// dial per measurement, tens of thousands a day — logs the same pair at debug.
#[test]
fn probe_dials_are_distinguished_from_cached_carriers() {
    assert_eq!(ConnLifeLevel::for_cached(true), ConnLifeLevel::Shared);
    assert_eq!(ConnLifeLevel::for_cached(false), ConnLifeLevel::Probe);
}

/// The defect this guards: the driver task that reports a protocol-level close
/// is wrapped in `AbortOnDrop`, so a locally-dropped connection used to emit an
/// open line and no close line at all (34 515 opens vs 0 closes in 48 h on one
/// production node). Dropping the connection must now produce exactly one close
/// line, classified as a local drop.
#[test]
fn dropping_a_connection_emits_the_missing_close() {
    let life = life(ConnLifeLevel::Shared);
    drop(ConnLifeGuard::new(Arc::clone(&life)));

    // The guard already closed it, so a driver task waking up afterwards adds
    // nothing — the pair stays balanced.
    assert!(!life.close(Some("H3_NO_ERROR"), "h3_no_error", true));
}

/// The mirror case: the driver task observed the real close, so the guard that
/// runs when the last `Arc` goes away must stay silent rather than double-count
/// the same connection.
#[test]
fn a_driver_reported_close_is_not_repeated_on_drop() {
    let life = life(ConnLifeLevel::Shared);
    assert!(life.close(Some("Timeout"), "timeout", true));

    let guard = ConnLifeGuard::new(Arc::clone(&life));
    drop(guard);
    // Nothing left to report: a third observer would also find it closed.
    assert!(!life.close(None, CONN_CLASS_LOCAL_DROP, true));
}

/// A cache entry standing in for a real carrier: the census only asks whether
/// the connection is still open.
struct FakeConn {
    id: u64,
    open: bool,
}

impl super::CachedEntry for FakeConn {
    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_open(&self) -> bool {
        self.open
    }
}

/// The pool census is published straight after the sweep, so it must see the
/// live carriers and none of the dead ones. Reporting a dead entry as an idle
/// carrier would invent endpoints that no longer hold a UDP socket — precisely
/// the number this gauge exists to measure.
#[tokio::test]
async fn census_sees_live_entries_and_not_swept_ones() {
    let registry = super::SharedConnectionRegistry::<u8, FakeConn>::new();
    registry.insert(1, Arc::new(FakeConn { id: 1, open: true })).await;
    registry.insert(2, Arc::new(FakeConn { id: 2, open: false })).await;
    registry.insert(3, Arc::new(FakeConn { id: 3, open: true })).await;

    registry.gc().await;

    let mut ids: Vec<u64> = registry.entries().await.iter().map(|(_, conn)| conn.id).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 3]);
}

use super::{CarrierIdleState, carriers_to_reap};

fn carrier(slot: u8, active: u64, idle_sweeps: u32) -> CarrierIdleState {
    CarrierIdleState { slot, active, idle_sweeps }
}

/// A carrier that is still working is never reaped, however long the pool has
/// been quiet around it.
#[test]
fn busy_carriers_are_never_reaped() {
    let pool = [carrier(0, 3, 99), carrier(1, 1, 99)];
    assert!(carriers_to_reap(&pool, 2, 8).is_empty());
}

/// A brief lull must not cost a connection: dialing one back costs a QUIC and
/// an HTTP/3 handshake on the next session.
#[test]
fn a_short_idle_spell_is_not_enough() {
    let pool = [carrier(0, 0, 7), carrier(1, 0, 3)];
    assert!(carriers_to_reap(&pool, 0, 8).is_empty());
}

/// With the floor already covered by busy carriers, every eligible idle one
/// goes — that is the memory the reaper exists to return.
#[test]
fn idle_carriers_go_once_the_floor_is_covered_by_busy_ones() {
    let pool = [carrier(0, 5, 0), carrier(1, 2, 0), carrier(2, 0, 9), carrier(3, 0, 12)];
    let mut reaped = carriers_to_reap(&pool, 2, 8);
    reaped.sort_unstable();
    assert_eq!(reaped, vec![2, 3]);
}

/// The floor is kept out of the idle carriers themselves when nothing is busy,
/// and what survives is the freshest — the one most likely to be wanted next.
#[test]
fn the_floor_is_kept_from_the_freshest_idle_carriers() {
    let pool = [carrier(0, 0, 20), carrier(1, 0, 9), carrier(2, 0, 40)];
    assert_eq!(
        carriers_to_reap(&pool, 1, 8),
        vec![2, 0],
        "longest-idle first, and slot 1 stays as the warm floor"
    );
}

/// Idle-but-young carriers count towards the floor, so the reaper does not
/// close an old one only for the pool to fall below its floor anyway.
#[test]
fn young_idle_carriers_count_towards_the_floor() {
    let pool = [carrier(0, 0, 2), carrier(1, 0, 30)];
    assert!(
        carriers_to_reap(&pool, 2, 8).is_empty(),
        "slot 0 is idle but young and fills the floor alongside slot 1"
    );
}
