//! Unit tests for the bounded [`XhttpRegistry`]: the `max_sessions` cap gates
//! creation only (never an existing id), and the relay-task semaphore bounds
//! concurrent `spawn_relay` reservations. Plus the uplink `ready` byte cap:
//! a slow/stuck relay must not let a client grow the in-order queue unbounded.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::{
    RelayPermit, UPLINK_READY_BYTES_CAP, UplinkIngestError, XhttpRegistry, XhttpRegistryLimits,
    XhttpSession,
};

fn limits(max_sessions: usize, max_relay_tasks: usize) -> XhttpRegistryLimits {
    XhttpRegistryLimits { max_sessions, max_relay_tasks }
}

#[test]
fn session_cap_rejects_new_but_serves_existing() {
    let registry = XhttpRegistry::with_limits(limits(2, 0));

    // Two fresh ids fill the registry to the cap.
    let (_a, created_a) = registry.get_or_create("id-aaaa", None, None).expect("first fits");
    assert!(created_a, "first id is newly created");
    let (_b, created_b) = registry.get_or_create("id-bbbb", None, None).expect("second fits");
    assert!(created_b, "second id is newly created");

    // A third *new* id is rejected — and left uninserted.
    assert!(
        registry.get_or_create("id-cccc", None, None).is_none(),
        "new id past the cap is rejected"
    );
    assert!(
        registry.get("id-cccc").is_none(),
        "rejected id must not be inserted into the registry"
    );

    // An already-live id is still served while the registry is full: the cap
    // gates creation only, so a resume / repeat request never 503s.
    let (_a_again, created_again) = registry
        .get_or_create("id-aaaa", None, None)
        .expect("existing id is served when full");
    assert!(!created_again, "existing id reports created = false");

    // Freeing a slot lets a new id in again.
    registry.remove("id-aaaa");
    let (_c, created_c) = registry
        .get_or_create("id-cccc", None, None)
        .expect("slot freed, new id fits");
    assert!(created_c, "new id created after a slot was freed");
}

#[test]
fn zero_session_cap_is_unbounded() {
    let registry = XhttpRegistry::with_limits(limits(0, 0));
    for i in 0..1_000 {
        let id = format!("id-{i:04}");
        assert!(
            registry.get_or_create(&id, None, None).is_some(),
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

/// 64 KiB — a quarter of `UPLINK_READY_BYTES_CAP`, so four frames fill the
/// queue exactly and the fifth crosses the cap.
const CHUNK_BYTES: usize = 64 * 1024;

fn ready_bytes(session: &XhttpSession) -> usize {
    session.uplink.lock().ready_bytes
}

/// Packet-up path: a relay that stops draining must not let a client grow the
/// in-order `ready` queue past its byte cap. Once full, further in-order POSTs
/// are refused with `ReadyFull` (HTTP 503) instead of buffering unbounded, and
/// the refusal is idempotent — the seq is not consumed, so a retry after the
/// relay frees room succeeds.
#[test]
fn packet_up_ready_rejects_when_full_and_stays_bounded() {
    let session = XhttpSession::new(Arc::from("test-session"), None, None);
    let chunk = Bytes::from(vec![0u8; CHUNK_BYTES]);

    // Simulate a stuck relay (nothing ever calls `pop_uplink_ready`) while a
    // valid client keeps POSTing in-order packets.
    let mut accepted = 0u64;
    loop {
        match session.ingest_uplink(accepted, chunk.clone()) {
            Ok(()) => {
                accepted += 1;
                assert!(accepted < 1_000, "ready grew without ever hitting the cap");
            },
            Err(UplinkIngestError::ReadyFull) => break,
            Err(other) => panic!("unexpected uplink error: {other:?}"),
        }
    }

    // The queue is bounded regardless of how long the client kept POSTing.
    assert!(
        ready_bytes(&session) <= UPLINK_READY_BYTES_CAP,
        "ready must stay within the byte cap"
    );
    // `accepted` is the stalled seq: it was refused, so `expected_seq` did not
    // advance past it. Draining one frame frees room, and the retry now fits.
    assert!(session.pop_uplink_ready().is_some(), "a drain must yield the head frame");
    assert!(
        session.ingest_uplink(accepted, chunk.clone()).is_ok(),
        "the refused seq is retryable once the relay frees room"
    );
}

/// Stream-up path: the pump feeds `ingest_uplink_inorder`, which must *park*
/// (not error, not grow the queue) once `ready` is full, so the h2/h3 flow
/// control window stops draining and the client is throttled. The parked push
/// completes as soon as the relay drains a frame.
#[tokio::test]
async fn stream_up_pump_parks_when_ready_full_until_drained() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    let chunk = Bytes::from(vec![0u8; CHUNK_BYTES]);

    // Fill `ready` to exactly the cap (empty-queue admits the first frame, the
    // rest fit up to the cap).
    for _ in 0..(UPLINK_READY_BYTES_CAP / CHUNK_BYTES) {
        session
            .ingest_uplink_inorder(chunk.clone())
            .await
            .expect("fits under the cap");
    }
    assert_eq!(ready_bytes(&session), UPLINK_READY_BYTES_CAP, "ready filled to the cap");

    // The next push must park: `ready` is full and non-empty.
    let parked = tokio::spawn({
        let session = Arc::clone(&session);
        let chunk = chunk.clone();
        async move { session.ingest_uplink_inorder(chunk).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !parked.is_finished(),
        "the pump must park while ready is full, applying back-pressure instead of growing the queue"
    );
    assert!(
        ready_bytes(&session) <= UPLINK_READY_BYTES_CAP,
        "parked push must not grow ready"
    );

    // The relay drains one frame → room frees → the parked push wakes and
    // completes, and the queue is still bounded.
    assert!(session.pop_uplink_ready().is_some(), "drain yields the head frame");
    tokio::time::timeout(Duration::from_secs(1), parked)
        .await
        .expect("parked push must wake within the timeout after a drain")
        .expect("join the push task")
        .expect("the woken push must succeed");
    assert!(ready_bytes(&session) <= UPLINK_READY_BYTES_CAP, "ready stays within the cap");
}

/// Closing the session must wake a parked `ingest_uplink_inorder` so a stuck
/// pump does not leak its task; the woken push observes the close and returns
/// `Closed` rather than hanging forever.
#[tokio::test]
async fn close_wakes_parked_uplink_producer() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None, None));
    let chunk = Bytes::from(vec![0u8; CHUNK_BYTES]);
    for _ in 0..(UPLINK_READY_BYTES_CAP / CHUNK_BYTES) {
        session
            .ingest_uplink_inorder(chunk.clone())
            .await
            .expect("fits under the cap");
    }

    let parked = tokio::spawn({
        let session = Arc::clone(&session);
        let chunk = chunk.clone();
        async move { session.ingest_uplink_inorder(chunk).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!parked.is_finished(), "push parks while ready is full");

    session.close();
    let result = tokio::time::timeout(Duration::from_secs(1), parked)
        .await
        .expect("close must wake the parked push")
        .expect("join the push task");
    assert!(
        matches!(result, Err(UplinkIngestError::Closed)),
        "a push woken by close must report Closed, got {result:?}"
    );
}
