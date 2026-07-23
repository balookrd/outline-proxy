//! Tests for the shared UDP flow-table helpers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tokio::task::yield_now;

use super::{FlowStamp, UdpFlowKey, drain_idle_flows};
use crate::wire::IpVersion;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimal `FlowStamp` stand-in: the table helpers only ever look at the
/// generation counter and the idle stamp, so neither flow type's carrier
/// machinery has to be built to exercise them.
struct TestFlow {
    id: u64,
    last_seen: Instant,
}

impl FlowStamp for TestFlow {
    fn id(&self) -> u64 {
        self.id
    }
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
    fn set_last_seen(&mut self, now: Instant) {
        self.last_seen = now;
    }
}

type TestTable = Arc<RwLock<HashMap<UdpFlowKey, Arc<Mutex<TestFlow>>>>>;

fn flow_key() -> UdpFlowKey {
    UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        local_port: 50000,
        remote_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 1, 14)),
        remote_port: 443,
    }
}

fn stale_stamp(now: Instant) -> Instant {
    now.checked_sub(IDLE_TIMEOUT * 10)
        .expect("test clock far enough past the epoch")
}

/// Regression: the idle sweep must not evict a flow that was re-created under
/// the same key while the sweep sat between its snapshot and its removal pass.
///
/// The real sequence: a reader hits a read error, `close_flow_if_current`
/// removes the flow, the client immediately re-sends on the same 5-tuple and a
/// brand-new flow is inserted under that key. A sweep that removes *by key*
/// then tears down that fresh flow with `reason = idle_timeout` at age ~0,
/// losing its outbound queue and its buffered handshake preface.
#[tokio::test]
async fn idle_sweep_keeps_a_flow_recreated_after_the_snapshot() {
    let now = Instant::now();
    let key = flow_key();
    let flows: TestTable = Arc::new(RwLock::new(HashMap::new()));

    // A genuinely idle flow: the sweep is expected to pick it as a candidate.
    let stale = Arc::new(Mutex::new(TestFlow { id: 1, last_seen: stale_stamp(now) }));
    flows.write().await.insert(key.clone(), Arc::clone(&stale));

    // Holding the per-flow lock parks the sweep inside its candidate loop —
    // exactly the window the race lives in: the map read-lock is already
    // released and the write-lock not yet taken.
    let parked = stale.lock().await;

    let sweep = tokio::spawn({
        let flows = Arc::clone(&flows);
        async move { drain_idle_flows(&flows, IDLE_TIMEOUT, now).await }
    });

    // The sweep's snapshot clones the handle `Arc`; waiting for that clone to
    // appear is what makes the interleaving deterministic rather than timed.
    for _ in 0..1_000 {
        if Arc::strong_count(&stale) >= 3 {
            break;
        }
        yield_now().await;
    }
    assert!(Arc::strong_count(&stale) >= 3, "the sweep never took its snapshot");

    // Meanwhile the real teardown drops the dead flow and the client re-creates
    // it under the same 5-tuple: same key, a different flow entirely.
    let fresh = Arc::new(Mutex::new(TestFlow { id: 2, last_seen: now }));
    flows.write().await.insert(key.clone(), Arc::clone(&fresh));

    drop(parked);
    let removed = sweep.await.expect("sweep task panicked");

    let table = flows.read().await;
    let current = table
        .get(&key)
        .expect("the re-created flow must still be in the table");
    assert!(Arc::ptr_eq(current, &fresh), "the idle sweep evicted the re-created flow");
    assert!(
        removed.iter().all(|handle| !Arc::ptr_eq(handle, &fresh)),
        "the re-created flow must not be handed to the close pipeline",
    );
}

/// Guard for the fix above: an untouched idle flow must still be evicted, and
/// a live one left alone. Re-checking identity may not turn the sweep into a
/// no-op.
#[tokio::test]
async fn idle_sweep_still_evicts_untouched_idle_flows() {
    let now = Instant::now();
    let idle_key = flow_key();
    let live_key = UdpFlowKey { local_port: 50001, ..flow_key() };
    let flows: TestTable = Arc::new(RwLock::new(HashMap::new()));

    let idle = Arc::new(Mutex::new(TestFlow { id: 1, last_seen: stale_stamp(now) }));
    let live = Arc::new(Mutex::new(TestFlow { id: 2, last_seen: now }));
    {
        let mut guard = flows.write().await;
        guard.insert(idle_key.clone(), Arc::clone(&idle));
        guard.insert(live_key.clone(), Arc::clone(&live));
    }

    let removed = drain_idle_flows(&flows, IDLE_TIMEOUT, now).await;

    assert_eq!(removed.len(), 1, "exactly the idle flow must be drained");
    assert!(Arc::ptr_eq(&removed[0], &idle), "the drained handle must be the idle flow's");

    let table = flows.read().await;
    assert!(!table.contains_key(&idle_key), "the idle flow must be gone from the table");
    assert!(table.contains_key(&live_key), "the live flow must survive the sweep");
}
