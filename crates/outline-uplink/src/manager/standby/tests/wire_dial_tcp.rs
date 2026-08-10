//! A fallback-wire TCP dial must attribute itself to the wire it dialed —
//! its loss probe, its RTT sample and any carrier downgrade it observes.
//! Attributing them to the parent's primary slot is the bug class this
//! whole change exists to remove: it is how a fallback ended up capping
//! primary's carrier-descent slot, and how the loss verdict ended up in a
//! slot nobody reads.

use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::accept_async;
use url::Url;

/// A dial on wire 2 must file every piece of attribution it produces under
/// wire 2, never under the parent's primary slot.
///
/// This stands up a live mock WebSocket server so the dial actually
/// succeeds: `register_carrier_loss_probe` and
/// `report_connection_latency_for_wire` both run past
/// `connect_transport`'s `?`, so a fixture where every wire points at a
/// closed port (dial always fails) can only ever prove "nothing got
/// registered", which holds identically whether attribution is correct,
/// wrong, or entirely missing.
///
/// The RTT-EWMA assertions run on every platform — that bookkeeping has no
/// Linux dependency. The loss-probe assertion is narrower: carrier loss
/// probes only exist on Linux
/// (`outline_transport::carrier_loss::CarrierLossProbe::from_tcp_stream` is
/// a no-op everywhere else — see that function's doc), so it is the one
/// piece gated to `target_os = "linux"` rather than the whole test.
#[tokio::test]
async fn a_fallback_wire_dial_attributes_itself_to_wire_two_not_primary() {
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

    #[cfg(target_os = "linux")]
    {
        use crate::types::TransportKind;

        let registered = manager.registered_loss_probe_wires_for_test(0, TransportKind::Tcp);
        assert_eq!(
            registered,
            std::collections::HashSet::from([2]),
            "a wire-2 dial must file its probe under wire 2 and nowhere else, got {registered:?}",
        );
    }

    let status = manager.read_status_for_test(0);
    assert!(
        status
            .tcp
            .fallback_rtt_ewma
            .get(1)
            .copied()
            .unwrap_or_default()
            .value()
            .is_some(),
        "wire 2's own RTT slot (fallback_rtt_ewma[1]) must get the connection-latency sample"
    );
    assert!(
        status.tcp.rtt_ewma.value().is_none(),
        "the sample must not land on primary's rtt_ewma slot"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock server task must finish within the timeout")
        .unwrap();
}

/// [`crate::manager::UplinkManager::connect_tcp_ws_redial_on_wire`] is the
/// wire-aware sibling of `connect_tcp_ws_redial`, used by same-uplink
/// recovery paths that present a resume id on a specific wire before chunk 0
/// has been acknowledged (`outline-ws-rust`'s chunk-0 RST / stale-standby
/// retry). It must dial the wire it is given — not always primary — and its
/// attribution must follow that wire, exactly like the fresh-dial sibling
/// above.
#[tokio::test]
async fn a_wire_redial_dials_the_given_wire_not_primary() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if let Ok(ws) = accept_async(stream).await {
            let _ = shutdown_rx.await;
            drop(ws);
        }
    });
    let wire2_url = Url::parse(&format!("ws://{addr}/tcp")).unwrap();

    let manager = super::sample_manager_with_live_wire_two(wire2_url).await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    manager
        .connect_tcp_ws_redial_on_wire(
            &candidate,
            2,
            "test",
            Some(outline_transport::SessionId::from_bytes([9u8; 16])),
        )
        .await
        .expect("the redial must succeed against the live mock server");

    let status = manager.read_status_for_test(0);
    assert!(
        status
            .tcp
            .fallback_rtt_ewma
            .get(1)
            .copied()
            .unwrap_or_default()
            .value()
            .is_some(),
        "wire 2's own RTT slot (fallback_rtt_ewma[1]) must get the connection-latency sample"
    );
    assert!(
        status.tcp.rtt_ewma.value().is_none(),
        "the sample must not land on primary's rtt_ewma slot"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock server task must finish within the timeout")
        .unwrap();
}
