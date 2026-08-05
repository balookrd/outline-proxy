//! VLESS on a fallback wire used to be rejected outright: the QUIC mux was
//! built from the parent uplink's fields, so a fallback could only be SS.
//! On a fleet whose primary *and* first fallback are both VLESS, that left
//! the UDP plane with no usable fallback at all.

use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::accept_async;
use url::Url;

use outline_transport::UdpSessionTransport;

use super::{
    sample_manager_with_live_wire_two, sample_manager_with_vless_fallback, udp_candidate_for_test,
};

/// A VLESS fallback wire must be dialable on UDP, and must be built from
/// *its own* shape — not the parent's. `sample_manager_with_vless_fallback`
/// deliberately gives the primary a different family (SS, closed port): if
/// this were still reading `candidate.uplink.transport` /
/// `candidate.uplink.udp_dial_url()` instead of `spec`'s, wire 1 would be
/// routed through the SS dial path against the closed primary port and this
/// call would return `Err` (or the wrong transport variant), not
/// `Ok(UdpSessionTransport::Vless(_))`. Building the mux never dials eagerly
/// (VLESS-UDP opens sessions lazily per destination), so a correct wire-1
/// dial always succeeds without needing a reachable server.
#[tokio::test]
async fn a_vless_fallback_wire_is_dialable_on_udp() {
    let manager = sample_manager_with_vless_fallback().await;
    let candidate = udp_candidate_for_test(&manager, 0).await;

    let result = manager
        .acquire_udp_on_wire(&candidate, 1, "test", &outline_transport::UdpResumeStore::ProcessWide)
        .await;

    match result {
        Ok(UdpSessionTransport::Vless(_)) => {},
        Ok(UdpSessionTransport::Ss(_)) => {
            panic!(
                "wire 1 is configured as VLESS but the dial built an SS transport — \
                 this is the parent's primary family leaking through"
            );
        },
        Err(error) => panic!("a VLESS fallback wire must be dialable on udp, got: {error:#}"),
    }
}

/// A wire past the end of the chain must be rejected because the index does
/// not resolve — not because of some family restriction. Distinguishing
/// this from the family-restriction test matters: the bug this whole plan
/// removes was a rejection keyed on family (any VLESS fallback), not on
/// index.
#[tokio::test]
async fn a_wire_without_a_udp_path_is_rejected_by_index_not_by_family() {
    let manager = sample_manager_with_vless_fallback().await;
    let candidate = udp_candidate_for_test(&manager, 0).await;

    let result = manager
        .acquire_udp_on_wire(&candidate, 9, "test", &outline_transport::UdpResumeStore::ProcessWide)
        .await;

    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("wire 9 does not exist"),
    };
    assert!(format!("{error:#}").contains("wire 9"));
}

/// An SS fallback-wire UDP dial must attribute itself to the wire it dialed
/// — its loss probe and its RTT sample — never to the parent's primary
/// slot. Mirrors the TCP twin
/// (`wire_dial_tcp::a_fallback_wire_dial_attributes_itself_to_wire_two_not_primary`):
/// a live mock WebSocket server so the dial actually succeeds and the
/// post-dial bookkeeping (`register_carrier_loss_probe`,
/// `report_connection_latency_for_wire`) really runs, rather than bailing
/// out at `connect_transport`'s `?` — a fixture where every wire points at a
/// closed port can only prove "nothing got registered", which holds
/// identically whether attribution is correct, wrong, or entirely missing.
#[tokio::test]
async fn a_fallback_wire_udp_dial_attributes_itself_to_wire_two_not_primary() {
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
    let wire2_url = Url::parse(&format!("ws://{addr}/udp")).unwrap();

    let manager = sample_manager_with_live_wire_two(wire2_url).await;
    let candidate = udp_candidate_for_test(&manager, 0).await;

    manager
        .acquire_udp_on_wire(&candidate, 2, "test", &outline_transport::UdpResumeStore::ProcessWide)
        .await
        .expect("the dial must succeed against the live mock server");

    #[cfg(target_os = "linux")]
    {
        use crate::types::TransportKind;

        let registered = manager.registered_loss_probe_wires_for_test(0, TransportKind::Udp);
        assert_eq!(
            registered,
            std::collections::HashSet::from([2]),
            "a wire-2 dial must file its probe under wire 2 and nowhere else, got {registered:?}",
        );
    }

    let status = manager.read_status_for_test(0);
    assert!(
        status.udp.fallback_rtt_ewma.get(1).copied().flatten().is_some(),
        "wire 2's own RTT slot (fallback_rtt_ewma[1]) must get the connection-latency sample"
    );
    assert!(
        status.udp.rtt_ewma.is_none(),
        "the sample must not land on primary's rtt_ewma slot"
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock server task must finish within the timeout")
        .unwrap();
}
