//! Overflow-eviction selection for the UDP flow tables.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use url::Url;

use super::*;
use crate::SharedTunWriter;
use crate::tcp::engine::tests::build_test_manager_with_urls;
use crate::udp::types::{FlowStamp, drain_idle_flows};
use crate::udp::{TunUdpEngine, UdpFlowKey};
use crate::wire::IpVersion;

struct StampFlow {
    id: u64,
    last_seen: Instant,
    eviction_indexed_at: Instant,
}

impl FlowStamp for StampFlow {
    fn id(&self) -> u64 {
        self.id
    }
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
    fn set_last_seen(&mut self, now: Instant) {
        self.last_seen = now;
    }
    fn eviction_indexed_at(&self) -> Instant {
        self.eviction_indexed_at
    }
    fn set_eviction_indexed_at(&mut self, at: Instant) {
        self.eviction_indexed_at = at;
    }
}

fn flow(id: u64, last_seen: Instant) -> Arc<Mutex<StampFlow>> {
    Arc::new(Mutex::new(StampFlow {
        id,
        last_seen,
        eviction_indexed_at: last_seen,
    }))
}

/// Table plus index, wired the way the engine wires them: every insert is also
/// published to the index.
fn table(
    entries: &[(u32, u64, Instant)],
) -> (HashMap<u32, Arc<Mutex<StampFlow>>>, FlowEvictionIndex<u32>) {
    let index = FlowEvictionIndex::new();
    let mut flows = HashMap::new();
    for &(key, id, last_seen) in entries {
        flows.insert(key, flow(id, last_seen));
        index.upsert(key, id, last_seen);
    }
    (flows, index)
}

#[tokio::test]
async fn evicts_the_least_recently_seen_flow() {
    let base = Instant::now();
    let (mut flows, index) = table(&[
        (1, 1, base + Duration::from_secs(60)),
        (2, 2, base), // least-recently-seen → evicted first
        (3, 3, base + Duration::from_secs(5)),
    ]);

    let (key, _) = evict_oldest_flow(&mut flows, &index).expect("a full table always has a victim");
    assert_eq!(key, 2);
    assert!(!flows.contains_key(&2), "the victim must leave the table");
    assert_eq!(index.len(), 2, "and must leave the index with it");

    // Next-oldest follows, and the index empties exactly with the table.
    assert_eq!(evict_oldest_flow(&mut flows, &index).map(|(k, _)| k), Some(3));
    assert_eq!(evict_oldest_flow(&mut flows, &index).map(|(k, _)| k), Some(1));
    assert!(evict_oldest_flow(&mut flows, &index).is_none());
    assert_eq!(index.len(), 0);
}

#[tokio::test]
async fn empty_table_has_no_victim() {
    let index = FlowEvictionIndex::<u32>::new();
    let mut flows: HashMap<u32, Arc<Mutex<StampFlow>>> = HashMap::new();
    assert!(evict_oldest_flow(&mut flows, &index).is_none());
}

/// Victim selection runs inline on the shared TUN read-loop *while holding the
/// flow-table write lock*, so it must never touch another flow's per-flow lock:
/// one flow busy in its own carrier send would otherwise stall the write lock,
/// and with it every datagram waiting on `flows.read()`. That is the O(n²)
/// amplification a flood of new 5-tuples against a full table used to trigger.
#[tokio::test]
async fn victim_selection_never_waits_on_another_flows_lock() {
    let base = Instant::now();
    let (mut flows, index) = table(&[
        (1, 1, base), // least-recently-seen → the victim
        (2, 2, base + Duration::from_secs(5)),
        (3, 3, base + Duration::from_secs(10)),
    ]);

    // A *newer* flow whose per-flow lock is held by its own task (a carrier send
    // or downlink write in flight). It is not the victim, so selecting one must
    // not depend on that lock being free.
    let busy = Arc::clone(&flows[&3]);
    let _busy_guard = busy.lock().await;

    let victim =
        timeout(Duration::from_millis(250), async { evict_oldest_flow(&mut flows, &index) })
            .await
            .expect("victim selection must not block on another flow's lock");
    assert_eq!(victim.map(|(k, _)| k), Some(1));
}

#[tokio::test]
async fn activity_moves_a_flow_off_the_eviction_head() {
    let base = Instant::now();
    let (mut flows, index) = table(&[(1, 1, base), (2, 2, base + Duration::from_secs(1))]);

    // The oldest flow takes traffic: it must stop being the eviction candidate.
    {
        let handle = Arc::clone(&flows[&1]);
        let mut state = handle.lock().await;
        state.set_last_seen(base + Duration::from_secs(30));
        record_flow_activity(&index, &1, &mut *state);
    }

    assert_eq!(evict_oldest_flow(&mut flows, &index).map(|(k, _)| k), Some(2));
    assert_eq!(evict_oldest_flow(&mut flows, &index).map(|(k, _)| k), Some(1));
}

/// The per-datagram path must not take the index lock on every packet, so a
/// sub-quantum advance deliberately leaves the index entry alone. The staleness
/// it buys is bounded by one quantum — far below the idle timeout that decides
/// which flows are genuinely stale, so ordering against a quiet flow holds.
#[tokio::test]
async fn sub_quantum_activity_does_not_reindex() {
    let base = Instant::now();
    let (mut flows, index) = table(&[(1, 1, base), (2, 2, base + Duration::from_secs(10))]);

    {
        let handle = Arc::clone(&flows[&1]);
        let mut state = handle.lock().await;
        state.set_last_seen(base + Duration::from_millis(999));
        record_flow_activity(&index, &1, &mut *state);
        assert_eq!(
            state.eviction_indexed_at(),
            base,
            "a sub-quantum advance must not re-key the index",
        );
    }

    assert_eq!(
        evict_oldest_flow(&mut flows, &index).map(|(k, _)| k),
        Some(1),
        "the flow stays at the eviction head until its advance clears a quantum",
    );
}

#[tokio::test]
async fn stale_index_entry_is_skipped_rather_than_stalling_eviction() {
    let base = Instant::now();
    let (mut flows, index) = table(&[(1, 1, base), (2, 2, base + Duration::from_secs(5))]);

    // A flow removed straight from the table (a path that forgot to unindex, or
    // a race with a concurrent removal) must not make eviction give up: the
    // stale entry is discarded and the next candidate taken.
    flows.remove(&1);

    assert_eq!(evict_oldest_flow(&mut flows, &index).map(|(k, _)| k), Some(2));
    assert_eq!(index.len(), 0, "the stale entry must be discarded, not left to leak");
}

#[tokio::test]
async fn removal_is_generation_checked() {
    let base = Instant::now();
    let index = FlowEvictionIndex::new();
    index.upsert(1u32, 1, base);

    // A zombie task closing generation 1 after generation 2 took the slot must
    // not unindex the live flow.
    index.upsert(1u32, 2, base + Duration::from_secs(1));
    assert!(!index.remove(&1, 1), "a stale generation must not remove the live entry");
    assert_eq!(index.pop_oldest(), Some((1, 2)));

    // The live generation removes exactly once.
    index.upsert(1u32, 2, base + Duration::from_secs(1));
    assert!(index.remove(&1, 2));
    assert!(!index.remove(&1, 2));
    assert_eq!(index.len(), 0);
}

/// A datagram bump races flow teardown: `bump_last_seen_if_current` drops the
/// table read-lock before it takes the flow's own lock, so a flow can be closed
/// underneath it. Re-indexing it there would put back a key the close path just
/// removed — one leaked entry per race, invisible until eviction happens to pop
/// it. Activity may therefore only *move* an entry that already exists.
#[tokio::test]
async fn activity_on_a_closed_flow_does_not_resurrect_its_index_entry() {
    let base = Instant::now();
    let index = FlowEvictionIndex::new();
    let handle = flow(1, base);
    index.upsert(1u32, 1, base);

    // The close path unindexes and removes the flow from the table…
    assert!(index.remove(&1, 1));

    // …while a reader task, already holding the flow's `Arc`, bumps it.
    {
        let mut state = handle.lock().await;
        state.set_last_seen(base + Duration::from_secs(5));
        record_flow_activity(&index, &1, &mut *state);
    }

    assert_eq!(index.len(), 0, "a closed flow must stay out of the index");
}

/// Idle cleanup removes flows behind eviction's back, so its entries have to be
/// dropped too — otherwise the index grows one leaked key per reaped flow and
/// eviction starts popping keys that no longer exist.
#[tokio::test]
async fn idle_cleanup_leaves_no_index_entries_behind() {
    let base = Instant::now();
    let idle_timeout = Duration::from_secs(30);
    let now = base + Duration::from_secs(120);

    let index = FlowEvictionIndex::new();
    let flows = tokio::sync::RwLock::new(HashMap::new());
    {
        let mut guard = flows.write().await;
        for (key, id, last_seen) in [(1u32, 1u64, base), (2, 2, now), (3, 3, base)] {
            guard.insert(key, flow(id, last_seen));
            index.upsert(key, id, last_seen);
        }
    }

    for (key, handle) in drain_idle_flows(&flows, idle_timeout, now).await {
        let flow_id = handle.lock().await.id();
        index.remove(&key, flow_id);
    }

    assert_eq!(flows.read().await.len(), 1, "only the active flow survives cleanup");
    assert_eq!(index.len(), 1, "the index must shrink with the table");
    assert_eq!(index.pop_oldest(), Some((2, 2)));
}

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const REMOTE_PORT: u16 = 443;

/// A WS upstream that accepts every carrier dial and drains it. Flows have to
/// survive their dial for the table to actually fill: a refused upstream tears
/// each one down again and the eviction path would never be reached.
async fn spawn_idle_udp_upstream() -> Url {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(ws) = accept_async(stream).await {
                    let (_sink, mut read) = ws.split();
                    while let Some(Ok(_)) = read.next().await {}
                }
            });
        }
    });
    Url::parse(&format!("ws://{addr}/udp")).unwrap()
}

fn test_tun_writer() -> SharedTunWriter {
    let path = std::env::temp_dir()
        .join(format!("outline-tun-udp-eviction-{}.bin", rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    SharedTunWriter::new(file)
}

async fn build_engine(max_flows: usize) -> TunUdpEngine {
    let manager = build_test_manager_with_urls(None, Some(spawn_idle_udp_upstream().await)).await;
    TunUdpEngine::new(
        test_tun_writer(),
        crate::TunRouting::from_single_manager(manager),
        max_flows,
        Duration::from_secs(60),
        false,
        false,
        false,
        Vec::new().into(),
        false,
    )
}

fn flow_key(client_port: u16) -> UdpFlowKey {
    UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(CLIENT_IP),
        local_port: client_port,
        remote_ip: IpAddr::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    }
}

async fn send_from_client_port(engine: &TunUdpEngine, client_port: u16) {
    let bytes = crate::udp::build_ipv4_udp_packet(
        CLIENT_IP,
        REMOTE_IP,
        client_port,
        REMOTE_PORT,
        b"datagram",
    )
    .unwrap();
    let parsed = crate::udp::parse_udp_packet(&bytes).unwrap();
    engine.handle_packet(parsed).await.unwrap();
}

/// End-to-end over the engine: a full table evicts the least-recently-seen flow
/// and the index stays in step with the table across create / activity / evict.
#[tokio::test]
async fn engine_evicts_least_recently_seen_flow_and_keeps_the_index_in_step() {
    let engine = build_engine(2).await;

    send_from_client_port(&engine, 40000).await;
    send_from_client_port(&engine, 40001).await;
    assert_eq!(engine.inner.flows.read().await.len(), 2);
    assert_eq!(engine.inner.eviction_index.len(), 2, "every new flow enters the index");

    // The first flow takes traffic a full quantum later, so the second becomes
    // the least-recently-seen one. `last_seen` is moved explicitly rather than
    // by sending again: a sub-quantum bump deliberately leaves the index alone,
    // so racing the wall clock would make the expected victim a coin flip.
    let first = flow_key(40000);
    {
        let handle = engine.inner.flows.read().await.get(&first).cloned().unwrap();
        let mut state = handle.lock().await;
        state.last_seen = Instant::now() + Duration::from_secs(2);
        record_flow_activity(&engine.inner.eviction_index, &first, &mut *state);
    }

    send_from_client_port(&engine, 40002).await;

    let flows = engine.inner.flows.read().await;
    assert_eq!(flows.len(), 2, "the table stays at its limit");
    assert!(flows.contains_key(&first), "the recently active flow survives");
    assert!(
        !flows.contains_key(&flow_key(40001)),
        "the least-recently-seen flow is the eviction victim",
    );
    assert!(flows.contains_key(&flow_key(40002)), "the new flow took the freed slot");
    assert_eq!(
        engine.inner.eviction_index.len(),
        flows.len(),
        "the index must not outgrow the table it orders",
    );
}
