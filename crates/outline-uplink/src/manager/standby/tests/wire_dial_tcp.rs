//! A fallback-wire TCP dial must attribute itself to the wire it dialed —
//! its loss probe, its RTT sample and any carrier downgrade it observes.
//! Attributing them to the parent's primary slot is the bug class this
//! whole change exists to remove: it is how a fallback ended up capping
//! primary's carrier-descent slot, and how the loss verdict ended up in a
//! slot nobody reads.

use crate::types::TransportKind;

use super::sample_manager_with_fallbacks;

#[tokio::test]
async fn a_fallback_wire_dial_registers_its_probe_under_that_wire() {
    let manager = sample_manager_with_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    // The dial itself cannot succeed against a config pointing at a closed
    // loopback port; what this asserts is the attribution recorded on the
    // way, which happens before the dial can fail.
    let _ = manager.connect_tcp_ws_fresh_on_wire(&candidate, 2, "test").await;

    let registered = manager.registered_loss_probe_wires_for_test(0, TransportKind::Tcp);
    assert!(
        !registered.contains(&0),
        "a wire-2 dial must not file its probe under the primary wire"
    );
}

/// Stronger companion to the test above, gated to Linux because carrier loss
/// probes only exist there (`outline_transport::carrier_loss::CarrierLossProbe::from_tcp_stream`
/// is a no-op on every other platform — see that function's doc). Everywhere
/// else a dial's probe registration is a no-op regardless of correctness, so
/// the assertion above can only ever check the negative ("didn't land on
/// wire 0"). Here the dial actually succeeds against a live mock server, so
/// this is the test that fails outright if attribution regresses to filing
/// every dial under wire 0: the assertion below would then see `{0}`, not
/// `{2}`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_fallback_wire_dial_files_its_probe_under_wire_two_not_primary() {
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::accept_async;
    use url::Url;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if let Ok(ws) = accept_async(stream).await {
            // Hold the accepted socket open so the dialed stream stays alive
            // long enough for the test to inspect what got registered.
            let _ = shutdown_rx.await;
            drop(ws);
        }
    });
    let wire2_url = Url::parse(&format!("ws://{addr}/tcp")).unwrap();

    let manager = super::sample_manager_with_live_wire_two(wire2_url).await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    manager
        .connect_tcp_ws_fresh_on_wire(&candidate, 2, "test")
        .await
        .expect("the dial must succeed against the live mock server");

    let registered = manager.registered_loss_probe_wires_for_test(0, TransportKind::Tcp);
    assert_eq!(
        registered,
        std::collections::HashSet::from([2]),
        "a wire-2 dial must file its probe under wire 2 and nowhere else, got {registered:?}",
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock server task must finish within the timeout")
        .unwrap();
}
