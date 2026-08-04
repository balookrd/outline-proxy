// Only used by the Linux-gated sampling test below (the registry needs
// `TCP_INFO`, Linux-only); an unconditional import trips `unused_imports`
// under `-D warnings` on a non-Linux dev host, where that test compiles out.
#[cfg(target_os = "linux")]
use crate::types::TransportKind;

/// A window recorded against the wire that is currently active must be the one
/// `active_wire_loss` returns — the same active-wire rule the RTT already uses.
#[test]
fn loss_is_read_from_the_active_wire() {
    let mut status = crate::manager::status::PerTransportStatus::default();
    status.record_wire_loss_window(0, 1_000, 10, 200, 1.0);
    status.record_wire_loss_window(1, 1_000, 200, 200, 1.0);

    status.active_wire = 0;
    assert_eq!(status.active_wire_loss().ratio(), Some(0.01));

    status.active_wire = 1;
    assert_eq!(
        status.active_wire_loss().ratio(),
        Some(0.2),
        "after a wire flip, scoring must read the wire actually carrying traffic"
    );
}

/// Sampling one tick over a registered live carrier writes a verdict into the
/// status, so the metric has something to publish without any user traffic
/// bookkeeping in between.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_sampling_tick_writes_the_wire_verdict_into_status() {
    let mut config = crate::tests::lb();
    // One packet is enough to qualify here: the assertion is that a window
    // reaches the status at all, not how fast loopback moves segments.
    config.loss_sample_min_packets = 1;
    let manager = crate::types::UplinkManager::new_for_test(
        "test",
        vec![crate::tests::make_uplink("primary", "wss://primary.example.com/tcp")],
        crate::tests::probe_disabled(),
        config,
    )
    .unwrap();

    let (probe, mut client, mut server) =
        crate::loss::tests_support::live_probe_with_traffic().await;
    manager.register_carrier_loss_probe(0, 0, TransportKind::Tcp, Some(probe));

    // Counters are cumulative, so the very first read can only seed a
    // baseline — the traffic already pushed by `live_probe_with_traffic`
    // above is swallowed into it, not reported as a window. Push a further
    // burst before the second tick so it has a delta to diff against.
    manager.sample_carrier_loss_once().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client.write_all(&[0u8; 1024]).await.unwrap();
    let mut sink = vec![0u8; 1024];
    server.read_exact(&mut sink).await.unwrap();
    manager.sample_carrier_loss_once().await;

    let status = manager.inner.read_status(0);
    assert!(
        status.tcp.carrier_loss.observed_packets() > 0,
        "a live carrier under traffic must produce observed volume"
    );
}
