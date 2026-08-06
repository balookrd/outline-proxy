//! What `outline_ws_warm_standby_acquire_total` counts.
//!
//! The counter answers one question — "of the acquisitions that consulted the
//! warm pool, how many did it serve?" — so only code that actually asks the
//! pool may tick it. The `miss` outcome used to be recorded by
//! `connect_tcp_ws_fresh_internal`, which serves every fresh, redial and
//! migration dial; a migration redial cannot use a pooled carrier at all
//! (resume is a property of the handshake), so each one booked a miss against a
//! pool it never opened. On a fleet where fallback-wire dials and migrations
//! are common that inflates the denominator with acquisitions the pool was
//! never offered, and the hit-rate an operator reads is not a hit-rate.

use crate::config::{
    CipherKind, LoadBalancingConfig, TransportMode, UplinkConfig, UplinkTransport,
};
use crate::types::{UplinkCandidate, UplinkManager};

use super::tests::{closed_port_url, fallback_wire_at, lb, probe_cfg};

/// Names no other test in this process uses, so the label sets these tests read
/// back out of the shared registry belong to them alone — the counter lives in
/// a process-wide registry and the suite runs in parallel.
const UPLINK: &str = "acquire-metric-fixture";
const WIRE_UPLINK: &str = "acquire-metric-wire-fixture";

/// `outline_ws_warm_standby_acquire_total{transport="tcp",uplink,outcome="miss"}`,
/// or 0 when the series does not exist yet. Matched on label *substrings*
/// rather than on a rendered label order, which the encoder does not promise.
fn tcp_miss_count(uplink: &str) -> u64 {
    let rendered = outline_metrics::render_prometheus(&[]).expect("metrics render");
    rendered
        .lines()
        .filter(|line| line.starts_with("outline_ws_warm_standby_acquire_total{"))
        .filter(|line| line.contains(&format!("uplink=\"{uplink}\"")))
        .filter(|line| line.contains("outcome=\"miss\""))
        .filter(|line| line.contains("transport=\"tcp\""))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

/// An uplink named `name` whose every wire points at a closed port, with
/// `fallback_wires` fallbacks so a take can ask for a wire that exists but is
/// not the one the pool prewarms.
async fn manager_with_no_pool(
    name: &str,
    fallback_wires: usize,
) -> (UplinkManager, UplinkCandidate) {
    let closed_wire = closed_port_url().await;
    let uplink = UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(closed_wire.clone()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(closed_wire.clone()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: (0..fallback_wires).map(|_| fallback_wire_at(&closed_wire)).collect(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    };
    // `warm_standby_tcp: 0` — nothing prewarms, so every take is a genuine
    // empty-pool miss and no background refill dials the closed port.
    let manager = UplinkManager::new_for_test(
        "test",
        vec![uplink.clone()],
        probe_cfg(),
        LoadBalancingConfig { warm_standby_tcp: 0, ..lb() },
    )
    .unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };
    (manager, candidate)
}

/// A dial that never opens the pool must not move the counter; a take against
/// an empty pool must.
#[tokio::test]
async fn only_an_acquisition_that_consults_the_pool_records_a_miss() {
    let (manager, candidate) = manager_with_no_pool(UPLINK, 0).await;
    assert_eq!(
        tcp_miss_count(UPLINK),
        0,
        "fixture setup: this uplink name is new to the process-wide registry",
    );

    // A migration redial: it dials the wire directly and can never be served
    // from the pool. The dial itself fails (closed port) — irrelevant, because
    // the counter tick it used to make happened before the dial.
    let _ = manager
        .connect_tcp_ws_migrate_with_ack_prefix(&candidate, "test", None)
        .await;
    assert_eq!(
        tcp_miss_count(UPLINK),
        0,
        "a migration redial never asks the pool for anything, so it is not a pool miss",
    );

    // A take against an empty pool is exactly what `miss` means.
    assert!(
        manager.try_take_tcp_standby(&candidate, 0).await.is_none(),
        "fixture setup: the pool is configured empty",
    );
    assert_eq!(
        tcp_miss_count(UPLINK),
        1,
        "the take consulted the pool and it had nothing — that is the one miss",
    );
}

/// Asking the pool for a wire it is not prewarming is a miss too: the caller
/// asked and got nothing. Recording it is what keeps a node whose pool sits on
/// one wire while its dials go to another distinguishable from a node that
/// never asks the pool at all.
#[tokio::test]
async fn a_take_for_a_wire_the_pool_does_not_serve_is_a_miss() {
    let (manager, candidate) = manager_with_no_pool(WIRE_UPLINK, 2).await;
    assert_eq!(tcp_miss_count(WIRE_UPLINK), 0, "fixture setup: a name new to the registry");

    // The pool is pinned to wire 0 (`tun_wire_dial` is off in this fixture),
    // so a wire-2 take can never be served — it returns before it even looks
    // inside the deque.
    assert!(manager.try_take_tcp_standby(&candidate, 2).await.is_none());

    assert_eq!(
        tcp_miss_count(WIRE_UPLINK),
        1,
        "a take the pool cannot serve is still an acquisition it was asked about",
    );
}
