//! SS-UDP acquisition vs `warm_standby_udp` pool and `SessionId` preservation.
//!
//! When `resume_store` already holds a `SessionId` for the SS-UDP scope (e.g.
//! during a `soft switch`, carrier redial, or failover), `acquire_udp_on_wire`
//! must bypass the warm-standby pool and dial on-demand so `X-Outline-Resume`
//! can be sent during the upgrade handshake — a pooled carrier has already
//! completed its upgrade with an empty `X-Outline-Resume` and a fresh
//! `SessionId` on the target server.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderValue};
use url::Url;

use outline_transport::{SessionId, UdpResumeStore, global_resume_cache};
use outline_wire::resume::{RESUME_REQUEST_HEADER, SESSION_RESPONSE_HEADER};

use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, RoutingScope, TransportMode, UplinkConfig,
    UplinkTransport,
};
use crate::manager::standby::resume_cache_key;
use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

use super::tests::{lb, probe_cfg};

const UPLINK_BYPASS: &str = "udp-resume-bypass-fixture";
const UPLINK_FRESH_POOL: &str = "udp-fresh-pool-fixture";
const UPLINK_PROCESS_WIDE: &str = "udp-process-wide-fixture";

fn udp_acquire_count(uplink: &str, outcome: &str) -> u64 {
    let rendered = outline_metrics::render_prometheus(&[]).expect("metrics render");
    rendered
        .lines()
        .filter(|line| line.starts_with("outline_ws_warm_standby_acquire_total{"))
        .filter(|line| line.contains(&format!("uplink=\"{uplink}\"")))
        .filter(|line| line.contains(&format!("outcome=\"{outcome}\"")))
        .filter(|line| line.contains("transport=\"udp\""))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<u64>().ok())
        .sum()
}

struct CapturedUpgrade {
    headers: HeaderMap,
    issued: SessionId,
}

#[allow(clippy::result_large_err)]
async fn spawn_udp_resume_server(
    minted: Vec<SessionId>,
) -> (
    Url,
    mpsc::UnboundedReceiver<CapturedUpgrade>,
    oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (upgrades_tx, upgrades_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let next = AtomicUsize::new(0);
        let mut live = Vec::new();
        loop {
            let stream = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(_) => break,
                },
                _ = &mut shutdown_rx => break,
            };
            let upgrades_tx = upgrades_tx.clone();
            let issued = minted
                .get(next.fetch_add(1, Ordering::SeqCst))
                .copied()
                .unwrap_or_else(|| SessionId::from_bytes([0xFF; 16]));
            let callback = |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                let _ =
                    upgrades_tx.send(CapturedUpgrade { headers: req.headers().clone(), issued });
                resp.headers_mut().insert(
                    SESSION_RESPONSE_HEADER,
                    HeaderValue::from_str(&issued.to_hex()).unwrap(),
                );
                Ok(resp)
            };
            match accept_hdr_async(stream, callback).await {
                Ok(ws) => live.push(ws),
                Err(_) => break,
            }
        }
    });
    (Url::parse(&format!("ws://{addr}/udp")).unwrap(), upgrades_rx, shutdown_tx, task)
}

async fn next_upgrade(rx: &mut mpsc::UnboundedReceiver<CapturedUpgrade>) -> CapturedUpgrade {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("dial must reach mock server within timeout")
        .expect("mock server must capture upgrade")
}

fn make_ss_udp_uplink(name: &str, url: &Url) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url.clone()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(url.clone()),
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
        dscp: None,
        disable_udp_gso: false,
        ipv6_first: false,
        ipv4_only: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

struct GlobalResumeKeyGuard(String);

impl Drop for GlobalResumeKeyGuard {
    fn drop(&mut self) {
        global_resume_cache().forget(&self.0);
    }
}

#[tokio::test]
async fn ss_udp_acquire_with_stored_session_id_bypasses_warm_pool_and_keeps_pooled_stream() {
    let pooled_id = SessionId::from_bytes([0x11; 16]);
    let resumed_id = SessionId::from_bytes([0x22; 16]);
    let stored_id = SessionId::from_bytes([0xAA; 16]);
    let (url, mut upgrades_rx, shutdown_tx, task) =
        spawn_udp_resume_server(vec![pooled_id, resumed_id]).await;

    let uplink = make_ss_udp_uplink(UPLINK_BYPASS, &url);
    let manager = UplinkManager::new_for_test(
        "udp-bypass-group",
        vec![uplink.clone()],
        probe_cfg(),
        LoadBalancingConfig {
            mode: LoadBalancingMode::ActivePassive,
            routing_scope: RoutingScope::Global,
            shared_resume: true,
            warm_standby_udp: 1,
            ..lb()
        },
    )
    .unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    // Pre-warm the UDP pool: 1 pooled stream dialed with no X-Outline-Resume.
    manager.maintain_pool(0, TransportKind::Udp).await;
    let first = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(first.issued, pooled_id);
    assert!(first.headers.get(RESUME_REQUEST_HEADER).is_none());
    assert_eq!(manager.snapshot().await.uplinks[0].standby_udp_ready, 1);

    // Simulate an existing flow/association that already holds a SessionId.
    let store = UdpResumeStore::private();
    let key = resume_cache_key(manager.resume_scope(&candidate.uplink.name), "udp");
    store.ss().store(key.clone(), stored_id);

    let hits_before = udp_acquire_count(UPLINK_BYPASS, "hit");
    let misses_before = udp_acquire_count(UPLINK_BYPASS, "miss");

    let _transport = manager
        .acquire_udp_on_wire(&candidate, 0, "test", &store)
        .await
        .expect("on-demand resume dial must succeed");

    let second = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(
        second
            .headers
            .get(RESUME_REQUEST_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(stored_id.to_hex().as_str()),
        "acquire_udp_on_wire must bypass the pool and send the stored X-Outline-Resume",
    );
    assert_eq!(
        store.ss().get(&key),
        Some(resumed_id),
        "resume store must be updated with the newly issued SessionId from the resume dial",
    );
    assert_eq!(
        manager.snapshot().await.uplinks[0].standby_udp_ready,
        1,
        "pooled standby stream must stay untouched in the pool when bypassed for resume",
    );
    assert_eq!(
        udp_acquire_count(UPLINK_BYPASS, "hit"),
        hits_before,
        "bypassing the pool must not record a warm_standby hit",
    );
    assert_eq!(
        udp_acquire_count(UPLINK_BYPASS, "miss"),
        misses_before,
        "bypassing the pool must not record a false warm_standby miss",
    );

    let _ = shutdown_tx.send(());
    task.abort();
}

#[tokio::test]
async fn ss_udp_acquire_without_session_id_still_reuses_warm_pool_and_stores_issued_id() {
    let pooled_id = SessionId::from_bytes([0x33; 16]);
    let refill_id = SessionId::from_bytes([0x44; 16]);
    let (url, mut upgrades_rx, shutdown_tx, task) =
        spawn_udp_resume_server(vec![pooled_id, refill_id]).await;

    let uplink = make_ss_udp_uplink(UPLINK_FRESH_POOL, &url);
    let manager = UplinkManager::new_for_test(
        "udp-fresh-group",
        vec![uplink.clone()],
        probe_cfg(),
        LoadBalancingConfig {
            mode: LoadBalancingMode::ActivePassive,
            routing_scope: RoutingScope::Global,
            shared_resume: true,
            warm_standby_udp: 1,
            ..lb()
        },
    )
    .unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    manager.maintain_pool(0, TransportKind::Udp).await;
    let first = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(first.issued, pooled_id);
    assert_eq!(manager.snapshot().await.uplinks[0].standby_udp_ready, 1);

    let store = UdpResumeStore::private();
    let key = resume_cache_key(manager.resume_scope(&candidate.uplink.name), "udp");
    assert!(store.ss().get(&key).is_none());

    let hits_before = udp_acquire_count(UPLINK_FRESH_POOL, "hit");
    let _transport = manager
        .acquire_udp_on_wire(&candidate, 0, "test", &store)
        .await
        .expect("fresh flow acquire from warm pool must succeed");

    assert_eq!(
        udp_acquire_count(UPLINK_FRESH_POOL, "hit"),
        hits_before + 1,
        "fresh flow without SessionId must take from the warm-standby pool",
    );
    assert_eq!(
        store.ss().get(&key),
        Some(pooled_id),
        "fresh flow must retain the pooled stream's issued SessionId for future migrations",
    );

    let _ = shutdown_tx.send(());
    task.abort();
}

#[tokio::test]
async fn ss_udp_process_wide_store_uses_pool_when_empty_and_bypasses_when_cached() {
    let pooled_id_1 = SessionId::from_bytes([0x55; 16]);
    let pooled_id_2 = SessionId::from_bytes([0x66; 16]);
    let resumed_id = SessionId::from_bytes([0x77; 16]);
    let (url, mut upgrades_rx, shutdown_tx, task) =
        spawn_udp_resume_server(vec![pooled_id_1, pooled_id_2, resumed_id]).await;

    let uplink = make_ss_udp_uplink(UPLINK_PROCESS_WIDE, &url);
    let manager = UplinkManager::new_for_test(
        "udp-pw-group",
        vec![uplink.clone()],
        probe_cfg(),
        LoadBalancingConfig {
            mode: LoadBalancingMode::ActivePassive,
            routing_scope: RoutingScope::Global,
            shared_resume: false,
            warm_standby_udp: 1,
            ..lb()
        },
    )
    .unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };
    let key = resume_cache_key(manager.resume_scope(&candidate.uplink.name), "udp");
    let _guard = GlobalResumeKeyGuard(key.clone());
    global_resume_cache().forget(&key);

    // First prewarm.
    manager.maintain_pool(0, TransportKind::Udp).await;
    let up1 = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(up1.issued, pooled_id_1);

    // 1st acquire with empty cache: reuses pooled stream, caches `pooled_id_1`.
    let hits_before = udp_acquire_count(UPLINK_PROCESS_WIDE, "hit");
    let _first = manager
        .acquire_udp_standby_or_connect(&candidate, "test")
        .await
        .expect("1st ProcessWide acquire must succeed from pool");
    assert_eq!(udp_acquire_count(UPLINK_PROCESS_WIDE, "hit"), hits_before + 1);
    assert_eq!(global_resume_cache().get(&key), Some(pooled_id_1));

    // Wait for refill (triggered by try_take_alive) or run maintenance so pool is full again.
    let up2 = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(up2.issued, pooled_id_2);
    manager.maintain_pool(0, TransportKind::Udp).await;
    assert_eq!(manager.snapshot().await.uplinks[0].standby_udp_ready, 1);

    // 2nd acquire with `pooled_id_1` already cached: must bypass the pool and resume.
    let hits_mid = udp_acquire_count(UPLINK_PROCESS_WIDE, "hit");
    let misses_mid = udp_acquire_count(UPLINK_PROCESS_WIDE, "miss");
    let _second = manager
        .acquire_udp_standby_or_connect(&candidate, "test")
        .await
        .expect("2nd ProcessWide acquire must succeed via resume dial");

    let up3 = next_upgrade(&mut upgrades_rx).await;
    assert_eq!(
        up3.headers.get(RESUME_REQUEST_HEADER).and_then(|v| v.to_str().ok()),
        Some(pooled_id_1.to_hex().as_str()),
        "2nd ProcessWide acquire must present the cached SessionId",
    );
    assert_eq!(global_resume_cache().get(&key), Some(resumed_id));
    assert_eq!(manager.snapshot().await.uplinks[0].standby_udp_ready, 1);
    assert_eq!(udp_acquire_count(UPLINK_PROCESS_WIDE, "hit"), hits_mid);
    assert_eq!(udp_acquire_count(UPLINK_PROCESS_WIDE, "miss"), misses_mid);

    let _ = shutdown_tx.send(());
    task.abort();
}
