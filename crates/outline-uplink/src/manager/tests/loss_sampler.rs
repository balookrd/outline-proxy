use std::time::Duration;

use tokio::time::Instant;

use crate::loss::{LossCollection, LossWindow};
use crate::manager::status::{PerTransportStatus, UplinkStatus};
use crate::types::TransportKind;

use super::apply_loss_collection;

/// A window recorded against the wire that is currently active must be the one
/// `active_wire_loss` returns — the same active-wire rule the RTT already uses.
#[test]
fn loss_is_read_from_the_active_wire() {
    let mut status = PerTransportStatus::default();
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

/// `record_wire_loss_window` (and the `LossEwma::record_window` it wraps)
/// must report whether the window actually qualified — callers use that to
/// decide whether this tick produced fresh evidence.
#[test]
fn record_wire_loss_window_reports_whether_it_qualified() {
    let mut status = PerTransportStatus::default();
    assert!(
        !status.record_wire_loss_window(0, 10, 1, 200, 1.0),
        "a window below min_packets must report false and leave no verdict"
    );
    assert_eq!(status.active_wire_loss().ratio(), None);

    assert!(
        status.record_wire_loss_window(0, 1_000, 100, 200, 1.0),
        "a qualifying window must report true"
    );
    assert_eq!(status.active_wire_loss().ratio(), Some(0.1));
}

// ── Loss-elevated episode maintenance ───────────────────────────────────────
//
// `loss_elevated_since` is the continuous-episode anchor the loss-driven
// strict-mode failover reads (`UplinkManager::loss_failover_switch_target`).
// `PerTransportStatus::update_loss_elevated_since` is the per-tick threshold
// check; `apply_loss_collection` (the pure, synchronous helper
// `sample_carrier_loss_once` calls) is what actually decides, from a
// sampling pass's `LossCollection`, whether this tick produced *fresh*
// evidence for the active wire — the freshness gate that keeps a frozen,
// no-longer-current ratio from being read as ongoing evidence forever.

const MAX_STALENESS: Duration = Duration::from_secs(30);

/// A ratio strictly above the threshold starts the episode; the boundary
/// value itself (`ratio == threshold`) must not. Both ticks are stamped
/// fresh — this test is only about the ratio-vs-threshold comparison.
#[test]
fn update_loss_elevated_since_sets_above_and_not_at_the_threshold() {
    let mut status = PerTransportStatus::default();
    let now = Instant::now();

    status.record_wire_loss_window(0, 1_000, 500, 1, 1.0); // exactly 50%
    status.loss_last_qualifying_at = Some(now);
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since, None,
        "ratio == threshold is not 'above' it — must not elevate"
    );

    status.record_wire_loss_window(0, 1_000, 600, 1, 1.0); // alpha=1.0 overwrites to 60%
    status.loss_last_qualifying_at = Some(now);
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since,
        Some(now),
        "ratio strictly above the threshold must start the episode"
    );
}

/// `threshold <= 0.0` is the documented off switch: the episode must never
/// be set, no matter how lossy the wire measures.
#[test]
fn update_loss_elevated_since_zero_threshold_never_elevates() {
    let mut status = PerTransportStatus::default();
    let now = Instant::now();
    status.record_wire_loss_window(0, 1_000, 999, 1, 1.0); // ~100% loss
    status.loss_last_qualifying_at = Some(now);
    status.update_loss_elevated_since(0.0, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since, None,
        "loss_failover_ratio = 0.0 must disable the check entirely"
    );
}

/// A verdict last confirmed well past `max_staleness` must not be trusted as
/// current evidence, even though the (frozen) ratio itself is still above
/// the threshold — the core regression this task's review flagged: a
/// sub-`min_packets` window leaves the ratio untouched, so without this gate
/// a one-off bad measurement would keep reading as "still elevated" forever.
#[test]
fn update_loss_elevated_since_treats_a_stale_verdict_as_unmeasured() {
    let mut status = PerTransportStatus::default();
    let now = Instant::now();
    let long_ago = now - Duration::from_secs(120);

    status.record_wire_loss_window(0, 1_000, 900, 1, 1.0); // 90%, frozen
    status.loss_last_qualifying_at = Some(long_ago);
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since, None,
        "a ratio last confirmed well past max_staleness must not elevate the episode"
    );
}

/// A verdict confirmed within `max_staleness` — even if not from this exact
/// tick — must still count as current: sparse-but-regular measurements
/// (e.g. light keepalive traffic) must not be treated as permanently stale
/// just because they do not land on every single sampling tick.
#[test]
fn update_loss_elevated_since_trusts_a_verdict_within_the_staleness_window() {
    let mut status = PerTransportStatus::default();
    let now = Instant::now();
    let recently = now - Duration::from_secs(20);

    status.record_wire_loss_window(0, 1_000, 900, 1, 1.0);
    status.loss_last_qualifying_at = Some(recently);
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since,
        Some(now),
        "a verdict confirmed within max_staleness must still count as current evidence"
    );
}

fn window(wire: u8, sent: u64, lost: u64) -> LossCollection {
    LossCollection {
        windows: vec![LossWindow {
            transport: TransportKind::Tcp,
            wire,
            sent,
            lost,
        }],
        emptied_wires: Vec::new(),
    }
}

/// `apply_loss_collection` must only stamp freshness for a window that (a)
/// targets the transport's currently *active* wire and (b) actually
/// qualified (met `min_packets`). Neither a non-active wire's traffic nor a
/// sub-threshold window on the active wire may count as fresh evidence.
#[test]
fn apply_loss_collection_only_stamps_freshness_for_a_qualifying_active_wire_window() {
    let mut status = UplinkStatus::default(); // active_wire defaults to 0
    let now = Instant::now();

    // Wire 1 is lossy, but it is not the active wire (0).
    apply_loss_collection(&mut status, &window(1, 1_000, 900), 1, 1.0, 0.5, MAX_STALENESS, now);
    assert_eq!(
        status.tcp.loss_last_qualifying_at, None,
        "a non-active wire's window must not stamp freshness for the active wire's episode"
    );
    assert_eq!(status.tcp.loss_elevated_since, None);

    // Wire 0 (active) but below min_packets.
    apply_loss_collection(&mut status, &window(0, 10, 9), 200, 1.0, 0.5, MAX_STALENESS, now);
    assert_eq!(
        status.tcp.loss_last_qualifying_at, None,
        "a sub-threshold window on the active wire must not qualify as fresh"
    );
}

/// Regression for the review finding: before the fix, the episode's
/// "elevated" verdict was re-derived every tick straight from
/// `active_wire_loss().ratio()`, which a sub-`min_packets` window leaves
/// completely untouched. A wire that measured high loss once and then only
/// produced light, sub-threshold traffic (keepalives under the volume
/// floor) kept reading "still elevated" indefinitely, purely because wall
/// clock time kept passing — the episode "aged" on a measurement that had
/// long since stopped being observed. With the freshness gate, the frozen
/// ratio stops counting as evidence once its last qualifying measurement is
/// older than `max_staleness`.
#[test]
fn a_frozen_ratio_stops_counting_as_evidence_once_it_goes_stale() {
    let mut status = UplinkStatus::default();
    let t0 = Instant::now();

    // t0: a qualifying 90% loss window elevates the episode.
    apply_loss_collection(&mut status, &window(0, 1_000, 900), 200, 1.0, 0.5, MAX_STALENESS, t0);
    assert_eq!(status.tcp.loss_elevated_since, Some(t0));

    // t0+20s: only light, sub-threshold traffic — well within max_staleness
    // (30s), so the episode must still be trusted.
    let t1 = t0 + Duration::from_secs(20);
    apply_loss_collection(&mut status, &window(0, 5, 4), 200, 1.0, 0.5, MAX_STALENESS, t1);
    assert_eq!(
        status.tcp.loss_elevated_since,
        Some(t0),
        "a verdict still within max_staleness must keep the episode alive"
    );

    // t0+40s: still only light traffic — now past max_staleness since the
    // last *qualifying* measurement (t0).
    let t2 = t0 + Duration::from_secs(40);
    apply_loss_collection(&mut status, &window(0, 5, 4), 200, 1.0, 0.5, MAX_STALENESS, t2);

    assert_eq!(
        status.tcp.carrier_loss.ratio(),
        Some(0.9),
        "sanity: the ratio itself never moved off the original measurement"
    );
    assert_eq!(
        status.tcp.loss_elevated_since, None,
        "once the last qualifying measurement is older than max_staleness, a frozen ratio \
         must stop counting as current evidence"
    );
}

/// An uplink continuously over the threshold keeps its original episode
/// anchor across repeated elevated ticks, but one clean tick clears it —
/// and loss above the threshold afterward starts a genuinely new episode,
/// not a resumption of the old one. This is the discipline that keeps an
/// uplink flapping around the threshold from ever accumulating its way past
/// `loss_failover_duration`.
#[test]
fn interrupted_loss_episode_restarts_the_clock() {
    let mut status = UplinkStatus::default();
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(5);
    let t2 = t0 + Duration::from_secs(10);
    let t3 = t0 + Duration::from_secs(15);

    // Tick 1: 90% loss — starts the episode.
    apply_loss_collection(&mut status, &window(0, 1_000, 900), 1, 1.0, 0.5, MAX_STALENESS, t0);
    assert!(
        status.tcp.loss_elevated_since.is_some(),
        "a tick above the threshold must start the episode"
    );
    assert_eq!(status.tcp.loss_elevated_since, Some(t0));

    // Tick 2: still 90% loss — the anchor must not move.
    apply_loss_collection(&mut status, &window(0, 1_000, 900), 1, 1.0, 0.5, MAX_STALENESS, t1);
    assert_eq!(
        status.tcp.loss_elevated_since,
        Some(t0),
        "a continuing episode must keep its original start, not slide forward"
    );

    // Tick 3: ratio drops to 0% — one clean tick clears the episode.
    apply_loss_collection(&mut status, &window(0, 1_000, 0), 1, 1.0, 0.5, MAX_STALENESS, t2);
    assert_eq!(
        status.tcp.loss_elevated_since, None,
        "a single clean tick must clear the episode rather than merely pausing it"
    );

    // Tick 4: 90% loss again — a fresh episode, never allowed to inherit
    // tick 1's start.
    apply_loss_collection(&mut status, &window(0, 1_000, 900), 1, 1.0, 0.5, MAX_STALENESS, t3);
    assert_eq!(
        status.tcp.loss_elevated_since,
        Some(t3),
        "loss above the threshold after an interruption must start a NEW episode anchored at \
         the current tick, not resume the stale one from tick 1"
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

/// End to end: once a wire's only carrier disappears (dies, or goes idle
/// long enough to be evicted as stale), the next sampling tick must reset
/// that wire's verdict on the status, not just drop the dead registry entry.
/// A lossy uplink that stops carrying traffic must read as "not measured"
/// again — otherwise it keeps a stale penalty as a failover target forever.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn losing_the_last_carrier_resets_the_wire_verdict_on_status() {
    let mut config = crate::tests::lb();
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

    // Seed the baseline, then push a real window so the wire has a verdict
    // to lose.
    manager.sample_carrier_loss_once().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client.write_all(&[0u8; 1024]).await.unwrap();
    let mut sink = vec![0u8; 1024];
    server.read_exact(&mut sink).await.unwrap();
    manager.sample_carrier_loss_once().await;

    assert!(
        manager.inner.read_status(0).tcp.carrier_loss.ratio().is_some(),
        "sanity: the wire has a measured verdict"
    );

    // Kill the carrier and keep sampling until the dead entry is evicted.
    drop(client);
    drop(server);
    for _ in 0..50 {
        manager.sample_carrier_loss_once().await;
        if manager.inner.read_status(0).tcp.carrier_loss.ratio().is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    assert_eq!(
        manager.inner.read_status(0).tcp.carrier_loss.ratio(),
        None,
        "losing the last carrier must clear the verdict, not leave the last ratio standing"
    );
}
