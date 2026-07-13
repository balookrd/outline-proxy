//! Unit tests for the bounded [`XhttpRegistry`]: the `max_sessions` cap gates
//! creation only (never an existing id), and the relay-task semaphore bounds
//! concurrent `spawn_relay` reservations.

use super::{RelayPermit, XhttpRegistry, XhttpRegistryLimits};

fn limits(max_sessions: usize, max_relay_tasks: usize) -> XhttpRegistryLimits {
    XhttpRegistryLimits { max_sessions, max_relay_tasks }
}

#[test]
fn session_cap_rejects_new_but_serves_existing() {
    let registry = XhttpRegistry::with_limits(limits(2, 0));

    // Two fresh ids fill the registry to the cap.
    let (_a, created_a) = registry.get_or_create("id-aaaa", None).expect("first fits");
    assert!(created_a, "first id is newly created");
    let (_b, created_b) = registry.get_or_create("id-bbbb", None).expect("second fits");
    assert!(created_b, "second id is newly created");

    // A third *new* id is rejected — and left uninserted.
    assert!(
        registry.get_or_create("id-cccc", None).is_none(),
        "new id past the cap is rejected"
    );
    assert!(
        registry.get("id-cccc").is_none(),
        "rejected id must not be inserted into the registry"
    );

    // An already-live id is still served while the registry is full: the cap
    // gates creation only, so a resume / repeat request never 503s.
    let (_a_again, created_again) = registry
        .get_or_create("id-aaaa", None)
        .expect("existing id is served when full");
    assert!(!created_again, "existing id reports created = false");

    // Freeing a slot lets a new id in again.
    registry.remove("id-aaaa");
    let (_c, created_c) = registry
        .get_or_create("id-cccc", None)
        .expect("slot freed, new id fits");
    assert!(created_c, "new id created after a slot was freed");
}

#[test]
fn zero_session_cap_is_unbounded() {
    let registry = XhttpRegistry::with_limits(limits(0, 0));
    for i in 0..1_000 {
        let id = format!("id-{i:04}");
        assert!(
            registry.get_or_create(&id, None).is_some(),
            "unbounded registry admits every fresh id"
        );
    }
}

#[test]
fn relay_semaphore_bounds_concurrent_permits() {
    let registry = XhttpRegistry::with_limits(limits(0, 2));

    let p1 = registry.try_acquire_relay_permit();
    let p2 = registry.try_acquire_relay_permit();
    assert!(matches!(p1, RelayPermit::Acquired(Some(_))), "first permit reserved");
    assert!(matches!(p2, RelayPermit::Acquired(Some(_))), "second permit reserved");

    // Both slots held → the third reservation is refused.
    assert!(
        matches!(registry.try_acquire_relay_permit(), RelayPermit::AtCapacity),
        "third reservation past the ceiling is refused"
    );

    // Releasing one permit frees a slot for the next reservation.
    drop(p1);
    assert!(
        matches!(registry.try_acquire_relay_permit(), RelayPermit::Acquired(Some(_))),
        "a freed slot admits a new reservation"
    );
    drop(p2);
}

#[test]
fn zero_relay_cap_never_blocks() {
    let registry = XhttpRegistry::with_limits(limits(0, 0));
    // No semaphore configured → every reservation succeeds with no permit.
    for _ in 0..1_000 {
        assert!(
            matches!(registry.try_acquire_relay_permit(), RelayPermit::Acquired(None)),
            "unbounded relay cap always admits with no permit"
        );
    }
}
