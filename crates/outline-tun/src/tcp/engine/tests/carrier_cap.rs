//! `[tun] max_carrier_flows` on the TCP path.
//!
//! The cap used to bind on the UDP table alone, so tunnelled TCP flows were
//! priced like direct ones and the two paths together could hold roughly twice
//! the configured number of carriers (256 UDP alongside 318 TCP was measured in
//! production, on a box whose cgroup limit the carriers were what exhausted).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::{
    TunCapture, build_test_manager, eviction_test_flow_state, test_flow_key, test_tun_tcp_config,
};
use crate::carrier_slots::CarrierSlots;

/// Engine wired with a carrier budget, mirroring what `spawn_tun_loop` does.
async fn engine_with_carrier_cap(
    cap: usize,
    max_flows: usize,
) -> (super::super::TunTcpEngine, outline_uplink::UplinkManager, Arc<CarrierSlots>) {
    let manager = build_test_manager("ws://127.0.0.1:1/".parse().unwrap()).await;
    let (writer, _capture) = TunCapture::new().await;
    let engine = super::super::TunTcpEngine::new(
        writer,
        crate::TunRouting::from_single_manager(manager.clone()),
        max_flows,
        Duration::from_secs(60),
        false,
        test_tun_tcp_config(),
        Arc::new(outline_transport::DnsCache::default()),
    );
    let slots = Arc::new(CarrierSlots::new(cap));
    engine.set_carrier_slots(Arc::clone(&slots));
    (engine, manager, slots)
}

/// The whole point of the cap: carriers run out before the flow table does.
#[tokio::test]
async fn carrier_cap_binds_before_the_flow_table_limit() {
    let (engine, manager, slots) = engine_with_carrier_cap(2, 8).await;
    let now = Instant::now();

    for (index, port) in [40110u16, 40111].iter().enumerate() {
        let key = test_flow_key(*port);
        engine
            .insert_flow(
                key.clone(),
                Arc::new(Mutex::new(eviction_test_flow_state(
                    &engine,
                    &manager,
                    key,
                    index as u64 + 1,
                    now + Duration::from_millis(index as u64),
                ))),
            )
            .await
            .unwrap();
    }
    assert_eq!(slots.in_use(), 2, "both tunnelled flows hold a carrier slot");
    assert_eq!(engine.inner.flows.len(), 2);

    // Third flow: the table has room (max_flows = 8), the carriers do not.
    let third = test_flow_key(40112);
    engine
        .insert_flow(
            third.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(
                &engine,
                &manager,
                third.clone(),
                3,
                now + Duration::from_millis(10),
            ))),
        )
        .await
        .unwrap();

    assert!(engine.inner.flows.contains_key(&third), "the newcomer was admitted");
    assert!(
        !engine.inner.flows.contains_key(&test_flow_key(40110)),
        "the oldest tunnelled flow was evicted to make room for the carrier"
    );
}

/// Direct flows are ~28× cheaper and deliberately outside the budget: charging
/// them would make the cap bind on traffic that owns no carrier at all.
#[tokio::test]
async fn direct_flows_do_not_take_carrier_slots() {
    let (engine, manager, slots) = engine_with_carrier_cap(1, 8).await;
    let now = Instant::now();

    let key = test_flow_key(40120);
    let mut state = eviction_test_flow_state(&engine, &manager, key.clone(), 1, now);
    state.routing.route = crate::TunRoute::Direct { fwmark: None };
    engine.insert_flow(key, Arc::new(Mutex::new(state))).await.unwrap();

    assert_eq!(slots.in_use(), 0, "a direct flow holds no carrier slot");

    // The single slot is still free for a tunnelled flow.
    let tunnelled = test_flow_key(40121);
    engine
        .insert_flow(
            tunnelled.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(
                &engine,
                &manager,
                tunnelled.clone(),
                2,
                now + Duration::from_millis(1),
            ))),
        )
        .await
        .unwrap();
    assert_eq!(slots.in_use(), 1);
}

/// Every teardown path has to give the slot back; `Drop` on the flow state is
/// what guarantees it, so tearing a flow down by any route must free capacity.
#[tokio::test]
async fn tearing_a_flow_down_returns_its_carrier_slot() {
    let (engine, manager, slots) = engine_with_carrier_cap(1, 8).await;
    let now = Instant::now();

    let key = test_flow_key(40130);
    engine
        .insert_flow(
            key.clone(),
            Arc::new(Mutex::new(eviction_test_flow_state(&engine, &manager, key.clone(), 1, now))),
        )
        .await
        .unwrap();
    assert_eq!(slots.in_use(), 1);

    engine.abort_flow_with_rst(&key, "test").await;
    assert_eq!(slots.in_use(), 0, "the slot came back when the flow was dropped");
}
