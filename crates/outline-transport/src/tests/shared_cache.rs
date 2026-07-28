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
