use super::LossEwma;
// `CarrierLossRegistry` and `MAX_PROBES_PER_WIRE` are exercised only by the
// Linux-gated tests below (the registry needs `TCP_INFO`, Linux-only). An
// unconditional import trips `unused_imports` under `-D warnings` on a
// non-Linux dev host, where those tests compile out entirely.
#[cfg(target_os = "linux")]
use super::{CarrierLossRegistry, MAX_IDLE_TICKS, MAX_PROBES_PER_WIRE};

/// A window that saw too little traffic proves nothing: one lost packet out of
/// ten is not "10% loss", it is no measurement. The EWMA must not move.
#[test]
fn a_window_below_the_minimum_volume_does_not_move_the_ewma() {
    let mut ewma = LossEwma::default();
    ewma.record_window(10, 1, 200, 0.2);
    assert_eq!(ewma.ratio(), None, "a sub-threshold window yields no verdict");
    assert_eq!(ewma.observed_packets(), 0, "and contributes no observed volume");
}

/// A window with enough volume produces the ratio itself on first sight —
/// there is no prior value to blend with, and starting from an implicit zero
/// would understate a path that was already lossy when sampling began.
#[test]
fn the_first_qualifying_window_seeds_the_ewma_with_its_own_ratio() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 20, 200, 0.2);
    assert_eq!(ewma.ratio(), Some(0.02));
    assert_eq!(ewma.observed_packets(), 1_000);
}

/// Subsequent windows blend, so a single clean or single terrible window
/// cannot swing selection on its own.
#[test]
fn later_windows_blend_into_the_ewma() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 20, 200, 0.5);
    ewma.record_window(1_000, 0, 200, 0.5);
    assert_eq!(ewma.ratio(), Some(0.01));
}

/// Inflation is capped: a burst of loss must degrade an uplink's rank, not
/// remove it from ranking altogether.
#[test]
fn inflation_is_clamped_at_the_cap() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 500, 200, 1.0);
    assert_eq!(ewma.inflation(20.0, 4.0), 4.0);
}

/// With the feature off the multiplier is exactly 1.0, so `base_latency` is
/// bit-for-bit what it is today.
#[test]
fn zero_k_yields_an_identity_multiplier() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 100, 200, 0.2);
    assert_eq!(ewma.inflation(0.0, 4.0), 1.0);
}

/// A wire that loses its last registered carrier must read as "not
/// measured" again, not as whatever ratio traffic left behind before the
/// carrier disappeared — otherwise a standby an operator would want to fail
/// over *to* keeps a stale lossy verdict forever.
#[test]
fn reset_clears_the_ratio_and_observed_volume() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 200, 200, 0.2);
    assert!(ewma.ratio().is_some(), "sanity: the window seeded a verdict");

    ewma.reset();

    assert_eq!(ewma.ratio(), None, "an emptied wire is unmeasured, not clean");
    assert_eq!(ewma.observed_packets(), 0);
}

/// A carrier that vanishes between ticks must not produce a delta at all —
/// neither negative (counters reset with the connection) nor inflated. Its
/// wire is also reported as emptied, so the caller can reset the wire's
/// verdict.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_vanished_carrier_contributes_no_window() {
    let mut registry = CarrierLossRegistry::default();
    let probe = crate::loss::tests_support::dead_probe().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);
    let collection = registry.collect_windows();
    assert!(collection.windows.is_empty(), "a dead carrier yields no window");
    assert_eq!(registry.len(), 0, "and is evicted from the registry");
    assert_eq!(
        collection.emptied_wires,
        vec![(crate::types::TransportKind::Tcp, 0)],
        "the wire that lost its last carrier must be reported"
    );
}

/// A carrier that stays alive but produces no traffic is not what the loss
/// signal exists to measure, and quinn only closes a retained QUIC
/// connection when every handle to it is dropped — so a registry entry with
/// `Δsent == 0` for several consecutive ticks must be evicted on its own,
/// independent of `alive`. Eviction is what releases the probe (the
/// `quinn::Connection` clone / duplicated fd) so the underlying carrier can
/// actually close.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_stale_but_alive_carrier_is_evicted_after_the_idle_bound() {
    let mut registry = CarrierLossRegistry::default();
    let (probe, _client, _server) = crate::loss::tests_support::live_pair().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);

    // No seeding tick: the baseline is taken at registration, so idleness is
    // counted from the moment the carrier is filed rather than one tick later.

    // Consecutive zero-delta ticks accumulate but must not evict before the
    // bound is reached — nothing on this idle-but-genuinely-alive loopback
    // pair ever sends a byte, so every one of these ticks sees `Δsent == 0`.
    for tick in 0..(MAX_IDLE_TICKS - 1) {
        let collection = registry.collect_windows();
        assert!(collection.windows.is_empty());
        assert_eq!(registry.len(), 1, "still within the idle bound at tick {tick}");
        assert!(collection.emptied_wires.is_empty());
    }

    // The tick that reaches the bound evicts the entry and reports its wire
    // as emptied in the same pass.
    let collection = registry.collect_windows();
    assert!(collection.windows.is_empty());
    assert_eq!(registry.len(), 0, "evicted once idleness persists past the bound");
    assert_eq!(collection.emptied_wires, vec![(crate::types::TransportKind::Tcp, 0)]);
}

/// Real traffic resets the idle counter, so a carrier that goes through an
/// ordinary lull and then resumes sending must never be evicted.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn traffic_resets_the_idle_counter() {
    use tokio::io::AsyncWriteExt;

    let mut registry = CarrierLossRegistry::default();
    let (probe, mut client, _server) = crate::loss::tests_support::live_pair().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);

    // The baseline comes from registration, so every tick here is a real
    // zero-delta tick.
    for _ in 0..(MAX_IDLE_TICKS - 1) {
        registry.collect_windows();
    }
    assert_eq!(registry.len(), 1, "sanity: one tick away from eviction");

    client.write_all(&[0u8; 64]).await.unwrap();
    // Give the kernel a moment to account the write in `tcpi_segs_out`.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let collection = registry.collect_windows();
    assert_eq!(registry.len(), 1, "traffic must reset the idle streak, not just delay eviction");
    assert!(collection.emptied_wires.is_empty());
}

/// One shared H2/H3 connection is handed to many sessions and every one of
/// them registers. Counting it once per session would let a wire clear the
/// minimum-volume threshold on a fraction of the traffic the threshold names.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_same_carrier_registered_twice_is_counted_once() {
    let mut registry = CarrierLossRegistry::default();
    let (probe, _client, _server) = crate::loss::tests_support::live_pair().await;
    let twin = probe.try_clone().expect("a second handle on the same carrier");

    registry.register(crate::types::TransportKind::Tcp, 0, probe);
    registry.register(crate::types::TransportKind::Tcp, 0, twin);

    assert_eq!(registry.len(), 1, "one carrier occupies one registry slot");
}

/// A dead entry must not squat on its identity. A registration that matches a
/// dead entry replaces it, so the slot is free the moment a new carrier
/// inherits a dead one's address.
///
/// The identity collision this guards against cannot be staged from this
/// crate — identity is derived inside `outline-transport` from the socket's
/// 4-tuple and cannot be forged from here without a test-only escape hatch in
/// that crate, which is not worth adding. Registering a dead carrier's own
/// clone reaches the same branch: it is the identity-matches-a-dead-entry
/// path, which is the branch under test.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_registration_matching_a_dead_entry_replaces_it() {
    let mut registry = CarrierLossRegistry::default();
    let dead = crate::loss::tests_support::dead_probe().await;
    let twin = dead.try_clone().expect("a second handle on the dead carrier");

    registry.register(crate::types::TransportKind::Tcp, 0, dead);
    registry.register(crate::types::TransportKind::Tcp, 0, twin);

    assert_eq!(registry.len(), 1, "the corpse is replaced, never duplicated");
}

/// The registry is bounded: a busy uplink dials constantly, and every dial
/// registers a distinct carrier. Oldest entries are dropped, newest kept.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_registry_is_bounded_per_wire() {
    let mut registry = CarrierLossRegistry::default();
    let mut sockets = Vec::new();
    for _ in 0..(MAX_PROBES_PER_WIRE + 4) {
        let (probe, client, server) = crate::loss::tests_support::live_pair().await;
        sockets.push((client, server));
        registry.register(crate::types::TransportKind::Tcp, 0, probe);
    }
    assert_eq!(registry.len(), MAX_PROBES_PER_WIRE);
}

/// A carrier must contribute its first window on the very next tick, not the
/// one after. Field evidence for why: the busiest gateway registered 37 new
/// carriers in two minutes and almost none survived to a second tick, so with
/// the baseline taken on the first tick the registry observed roughly 5% of
/// the traffic actually flowing. Taking the baseline at registration is what
/// makes a short-lived carrier count at all.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_carrier_contributes_a_window_on_the_first_tick_after_registration() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut registry = CarrierLossRegistry::default();
    let (probe, mut client, mut server) = crate::loss::tests_support::live_pair().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);

    // Traffic strictly after registration: whatever the carrier sent before it
    // was filed belongs to no window and must not be attributed to one.
    for _ in 0..16 {
        client.write_all(&[0u8; 1024]).await.unwrap();
    }
    let mut sink = vec![0u8; 16 * 1024];
    server.read_exact(&mut sink).await.unwrap();

    let collection = registry.collect_windows();
    let window = collection
        .windows
        .iter()
        .find(|w| w.transport == crate::types::TransportKind::Tcp && w.wire == 0);
    assert!(
        window.is_some_and(|w| w.sent > 0),
        "the first tick after registration must already carry a delta, not just a baseline"
    );
}
