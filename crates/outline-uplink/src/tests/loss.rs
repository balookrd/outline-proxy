use super::LossEwma;
// `CarrierLossRegistry` and `MAX_PROBES_PER_WIRE` are exercised only by the
// Linux-gated tests below (the registry needs `TCP_INFO`, Linux-only). An
// unconditional import trips `unused_imports` under `-D warnings` on a
// non-Linux dev host, where those tests compile out entirely.
#[cfg(target_os = "linux")]
use super::{CarrierLossRegistry, MAX_PROBES_PER_WIRE};

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

/// A carrier that vanishes between ticks must not produce a delta at all —
/// neither negative (counters reset with the connection) nor inflated.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_vanished_carrier_contributes_no_window() {
    let mut registry = CarrierLossRegistry::default();
    let probe = crate::loss::tests_support::dead_probe().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);
    let windows = registry.collect_windows();
    assert!(windows.is_empty(), "a dead carrier yields no window");
    assert_eq!(registry.len(), 0, "and is evicted from the registry");
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
