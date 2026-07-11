//! Regression coverage for the combined-SS warm-standby refill discriminator.
//!
//! On a combined-SS uplink one URL carries both the TCP and UDP legs, told
//! apart by a hidden discriminator in the WS `/{token}` segment. The warm-
//! standby refill is generic over the pool's transport, so it MUST dial each
//! pool's leg with the matching discriminator: a UDP standby stream dialed with
//! the TCP token lands on the server's SS-TCP relay, and
//! `acquire_udp_standby_or_connect` later reuses it for a datagram session —
//! every packet then feeds the TCP decryptor and no echo returns (combined-SS
//! UDP looks dead while VLESS-UDP, which has no standby pool, keeps working).

use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use url::Url;

use outline_wire::xhttp::{SsPathKind, decode_kind};

use crate::config::{TransportMode, UplinkConfig};
use crate::types::{TransportKind, UplinkManager};

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
