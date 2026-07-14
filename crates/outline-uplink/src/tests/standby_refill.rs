//! Warm-standby pool behaviour: refill discriminator (combined-SS) and refill
//! scheduling on acquisition.
//!
//! On a combined-SS uplink one URL carries both the TCP and UDP legs, told
//! apart by a hidden discriminator in the WS `/{token}` segment. The warm-
//! standby refill is generic over the pool's transport, so it MUST dial each
//! pool's leg with the matching discriminator: a UDP standby stream dialed with
//! the TCP token lands on the server's SS-TCP relay, and
//! `acquire_udp_standby_or_connect` later reuses it for a datagram session —
//! every packet then feeds the TCP decryptor and no echo returns (combined-SS
//! UDP looks dead while VLESS-UDP, which has no standby pool, keeps working).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::{accept_async, accept_hdr_async};
use url::Url;

use outline_wire::xhttp::{SsPathKind, decode_kind};

use crate::config::{TransportMode, UplinkConfig};
use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

use super::{lb, make_uplink, probe_disabled};

/// A one-shot mock WS server: accepts a single connection, captures the HTTP
/// upgrade request path, completes the handshake, then holds the socket open
/// (so the dialed stream stays alive and lands in the pool) until dropped.
// The `accept_hdr_async` callback's `Result<Response, ErrorResponse>` return is
// a tungstenite-imposed signature; the large `Err` variant is not ours to box.
#[allow(clippy::result_large_err)]
async fn spawn_upgrade_path_probe()
-> (Url, oneshot::Receiver<String>, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (path_tx, path_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut path_tx = Some(path_tx);
        let callback = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
            if let Some(tx) = path_tx.take() {
                let _ = tx.send(req.uri().path().to_string());
            }
            Ok(resp)
        };
        if let Ok(ws) = accept_hdr_async(stream, callback).await {
            // Keep the accepted stream (and thus the pooled client stream) alive
            // until the test signals shutdown.
            let _ = shutdown_rx.await;
            drop(ws);
        }
    });
    (Url::parse(&format!("ws://{addr}/base")).unwrap(), path_rx, shutdown_tx, task)
}

/// A combined-SS-over-WS uplink whose single `ss_ws_url` carries both legs.
fn combined_ss_ws_uplink(ss_ws_url: Url) -> UplinkConfig {
    UplinkConfig {
        // Combined mode: `is_combined_ss()` keys off `ss_ws_url`, and both
        // `tcp_dial_url()` / `udp_dial_url()` resolve to it. Null the split
        // fields so nothing but the combined URL is dialable.
        tcp_ws_url: None,
        udp_ws_url: None,
        ss_ws_url: Some(ss_ws_url),
        ss_mode: Some(TransportMode::WsH1),
        ..make_uplink("combined", "ws://unused.example/base")
    }
}

/// The UDP warm-standby refill on a combined-SS uplink must dial the **UDP**
/// leg. Before the fix the refill hard-coded `SsPathKind::Tcp` for every pool,
/// so this token decoded to `Tcp` and the pooled "UDP" stream was really a
/// TCP-leg connection.
#[tokio::test]
async fn combined_ss_udp_standby_refill_dials_udp_leg() {
    let (url, path_rx, shutdown_tx, task) = spawn_upgrade_path_probe().await;

    let mut config = lb();
    config.warm_standby_udp = 1;
    config.warm_standby_tcp = 0;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![combined_ss_ws_uplink(url)],
        probe_disabled(),
        config,
    )
    .unwrap();

    manager.maintain_pool(0, TransportKind::Udp).await;

    let path = tokio::time::timeout(Duration::from_secs(5), path_rx)
        .await
        .expect("refill must dial the combined-SS UDP standby within the timeout")
        .expect("probe must capture the upgrade path");
    let token = path
        .rsplit('/')
        .next()
        .expect("combined WS path carries a /{token} segment");
    assert_eq!(
        decode_kind(token),
        SsPathKind::Udp,
        "UDP standby refill must dial the combined-SS UDP leg, got path {path:?}",
    );

    let _ = shutdown_tx.send(());
    task.abort();
}

/// Sibling check that the TCP pool still dials the TCP leg — guards against a
/// fix that flips the discriminator the wrong way.
#[tokio::test]
async fn combined_ss_tcp_standby_refill_dials_tcp_leg() {
    let (url, path_rx, shutdown_tx, task) = spawn_upgrade_path_probe().await;

    let mut config = lb();
    config.warm_standby_tcp = 1;
    config.warm_standby_udp = 0;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![combined_ss_ws_uplink(url)],
        probe_disabled(),
        config,
    )
    .unwrap();

    manager.maintain_pool(0, TransportKind::Tcp).await;

    let path = tokio::time::timeout(Duration::from_secs(5), path_rx)
        .await
        .expect("refill must dial the combined-SS TCP standby within the timeout")
        .expect("probe must capture the upgrade path");
    let token = path
        .rsplit('/')
        .next()
        .expect("combined WS path carries a /{token} segment");
    assert_eq!(
        decode_kind(token),
        SsPathKind::Tcp,
        "TCP standby refill must dial the combined-SS TCP leg, got path {path:?}",
    );

    let _ = shutdown_tx.send(());
    task.abort();
}

/// A mock WS server that hangs up on the first `stale_first` connections right
/// after the handshake and keeps every later one open. Lets a test stage a pool
/// whose head entries are already dead by the time they are taken. The returned
/// counter tracks accepted connections, i.e. how many dials the client made.
async fn spawn_ws_server_with_stale_head(
    stale_first: usize,
) -> (Url, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_in_task = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        // Sockets accepted after the stale head are parked here so they stay
        // open (dropping them would close the pooled client streams too).
        let mut live = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let seen = accepted_in_task.fetch_add(1, Ordering::SeqCst);
            match accept_async(stream).await {
                // Handshake completed, then FIN: the client's pooled stream is
                // now stale and its acquisition-time peek will discard it.
                Ok(ws) if seen < stale_first => drop(ws),
                Ok(ws) => live.push(ws),
                Err(_) => break,
            }
        }
    });
    (Url::parse(&format!("ws://{addr}/tcp")).unwrap(), accepted, task)
}

/// Taking from a pool whose head entries went stale must schedule exactly ONE
/// refill, and that refill must restore the pool to `desired`.
///
/// The take path used to spawn a refill task per `pop_front()`, so walking past
/// K stale entries fired K+1 tasks — each resolving a standby context (a status
/// read) and bouncing off the refill mutex with nothing to do, because the first
/// task had already refilled the pool. The single refill has to cover every slot
/// the walk drained, not just the entry handed to the caller.
#[tokio::test]
async fn stale_pool_entries_schedule_a_single_refill() {
    const DESIRED: usize = 3;
    const STALE: usize = 2;

    let (url, accepted, task) = spawn_ws_server_with_stale_head(STALE).await;

    let mut config = lb();
    config.warm_standby_tcp = DESIRED;
    config.warm_standby_udp = 0;
    let uplink = make_uplink("standby", url.as_str());
    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), config)
            .unwrap();

    // Fill the pool: the first STALE entries land dead (server hung up), the
    // rest are live.
    manager.maintain_pool(0, TransportKind::Tcp).await;
    assert_eq!(manager.inner.standby_pools[0].tcp.len_hint(), DESIRED);
    // Let the server's FIN reach the pooled streams so the peek sees them closed.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };
    let taken = manager.try_take_tcp_standby(&candidate).await;
    assert!(
        taken.is_some(),
        "the take must walk past the {STALE} stale entries and hand out the live one",
    );

    assert_eq!(
        manager.inner.standby_pools[0]
            .refill_gate(TransportKind::Tcp)
            .spawned(),
        1,
        "one take must schedule one refill, however many stale entries it discarded",
    );

    // The single refill covers every drained slot, so the pool converges back to
    // `desired` (the taken stream is not returned to the pool).
    let refilled = tokio::time::timeout(Duration::from_secs(5), async {
        while manager.inner.standby_pools[0].tcp.len_hint() < DESIRED {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        refilled.is_ok(),
        "the refill must restore the pool to {DESIRED}, got {}",
        manager.inner.standby_pools[0].tcp.len_hint(),
    );
    assert_eq!(
        manager.inner.standby_pools[0]
            .refill_gate(TransportKind::Tcp)
            .spawned(),
        1,
        "refilling must not schedule further refills",
    );
    // Staging dialed DESIRED, the refill re-dialed the drained slots.
    assert_eq!(accepted.load(Ordering::SeqCst), 2 * DESIRED);

    task.abort();
}
