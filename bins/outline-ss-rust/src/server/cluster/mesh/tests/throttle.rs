use std::sync::Arc;
use std::time::Duration;

use super::ThrottleRegistry;
use crate::server::transport::throughput_monitor::{ThrottleDetectParams, ThroughputMonitor};

/// A monitor for the tests; `signal()` works regardless of `enabled`.
fn monitor() -> Arc<ThroughputMonitor> {
    ThroughputMonitor::new(ThrottleDetectParams::default())
}

/// Whether `signal()` fired within a short window (the writer's wake-up path).
async fn was_signalled(m: &Arc<ThroughputMonitor>) -> bool {
    tokio::time::timeout(Duration::from_millis(50), m.signal().notified())
        .await
        .is_ok()
}

#[tokio::test]
async fn route_hint_wakes_registered_monitor() {
    let reg = ThrottleRegistry::new();
    let m = monitor();
    let id = [7u8; 16];
    let _guard = reg.register(id, &m);
    assert!(reg.route_hint(&id), "hint should route to a registered session");
    assert!(was_signalled(&m).await, "the monitor's writer should be woken");
}

#[tokio::test]
async fn route_hint_unknown_session_is_noop() {
    let reg = ThrottleRegistry::new();
    assert!(!reg.route_hint(&[0u8; 16]), "unknown session id must not route");
}

#[test]
fn guard_drop_unregisters() {
    let reg = ThrottleRegistry::new();
    let m = monitor();
    let id = [1u8; 16];
    {
        let _g = reg.register(id, &m);
        assert_eq!(reg.len(), 1);
    }
    assert_eq!(reg.len(), 0, "dropping the guard evicts the entry");
    assert!(!reg.route_hint(&id));
}

#[tokio::test]
async fn stale_guard_drop_keeps_fresh_registration() {
    let reg = ThrottleRegistry::new();
    let id = [2u8; 16];
    let m1 = monitor();
    let g1 = reg.register(id, &m1);
    let m2 = monitor();
    let g2 = reg.register(id, &m2); // edge switch: overwrites the entry with m2
    assert_eq!(reg.len(), 1);

    drop(g1); // stale guard: the entry is m2, not m1 — must NOT evict
    assert_eq!(reg.len(), 1, "a stale guard must not evict the fresh entry");
    assert!(reg.route_hint(&id));
    assert!(was_signalled(&m2).await, "the fresh monitor is the one signalled");

    drop(g2);
    assert_eq!(reg.len(), 0);
}

#[test]
fn torn_down_monitor_upgrade_fails() {
    let reg = ThrottleRegistry::new();
    let id = [3u8; 16];
    let m = monitor();
    let g = reg.register(id, &m);
    drop(m); // relay torn down; the guard has not run yet
    assert!(!reg.route_hint(&id), "a dead weak upgrades to None; hint is dropped");
    drop(g);
    assert_eq!(reg.len(), 0);
}
