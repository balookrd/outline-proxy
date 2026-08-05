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
    status.loss_last_qualifying_at = Some((0, now));
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since, None,
        "ratio == threshold is not 'above' it — must not elevate"
    );

    status.record_wire_loss_window(0, 1_000, 600, 1, 1.0); // alpha=1.0 overwrites to 60%
    status.loss_last_qualifying_at = Some((0, now));
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
    status.loss_last_qualifying_at = Some((0, now));
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
    status.loss_last_qualifying_at = Some((0, long_ago));
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
    status.loss_last_qualifying_at = Some((0, recently));
    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since,
        Some(now),
        "a verdict confirmed within max_staleness must still count as current evidence"
    );
}

/// Regression: the freshness stamp must be tied to the specific wire it
/// came from, not just "some wire was fresh recently" — otherwise a fresh
/// measurement on the wire the dial loop just moved *off* of could validate
/// a completely different (and possibly still-lossy) wire's stale ratio for
/// up to `max_staleness` after the flip.
#[test]
fn update_loss_elevated_since_does_not_trust_a_stamp_from_a_different_wire() {
    let mut status = PerTransportStatus::default();
    let now = Instant::now();

    // Wire 0 was freshly (and cleanly) measured just now...
    status.record_wire_loss_window(0, 1_000, 100, 1, 1.0); // wire 0: 10%, clean
    status.loss_last_qualifying_at = Some((0, now));

    // ...but the dial loop has since flipped the active wire to 1, whose
    // ratio is 90% from a measurement no tick has ever confirmed (no stamp
    // was ever recorded for wire 1).
    status.record_wire_loss_window(1, 1_000, 900, 1, 1.0); // wire 1: 90%
    status.active_wire = 1;

    status.update_loss_elevated_since(0.5, now, MAX_STALENESS);
    assert_eq!(
        status.loss_elevated_since, None,
        "a freshness stamp recorded for wire 0 must not vouch for wire 1's ratio after a flip, \
         even though the stamp's timestamp is well within max_staleness"
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

/// Same property as `interrupted_loss_episode_restarts_the_clock`, but
/// driven through the real sampler entry point (`sample_carrier_loss_once`)
/// instead of `apply_loss_collection` directly. The unit test above covers
/// the pure episode-maintenance logic in isolation; this one covers the
/// seam around it that the pure test cannot reach: that
/// `sample_carrier_loss_once` still reassesses the episode on a tick whose
/// `LossCollection` is completely empty (the round-1 fix the first review
/// specifically credited — reintroducing an early `continue` before the
/// reassessment would leave this test red while the pure unit tests above
/// stay green), and that `max_staleness` really is wired end to end as
/// `3 × loss_sample_interval` (mistyping that multiplier, or the units,
/// would also only show up here).
#[tokio::test(start_paused = true)]
async fn sample_carrier_loss_once_ages_out_a_stale_episode_across_empty_ticks() {
    let mut config = crate::tests::lb();
    // Pin the interval here rather than inheriting it: the arithmetic below
    // (and every duration in the comments) is written against a 10 s grid, so
    // a change to the shipped default must not silently retune this test.
    config.loss_sample_interval = Duration::from_secs(10);
    config.loss_failover_ratio = 0.5;
    let manager = crate::types::UplinkManager::new_for_test(
        "test",
        vec![crate::tests::make_uplink("primary", "wss://primary.example.com/tcp")],
        crate::tests::probe_disabled(),
        config,
    )
    .unwrap();

    // Stage an already-elevated episode with a fresh qualifying stamp, but
    // register no live carrier at all: every `sample_carrier_loss_once`
    // call below therefore observes a completely empty `LossCollection`.
    let now = Instant::now();
    manager.inner.with_status_mut(0, |status| {
        status.tcp.record_wire_loss_window(0, 1_000, 900, 1, 1.0); // 90%, frozen from here on
        status.tcp.loss_last_qualifying_at = Some((0, now));
        status.tcp.loss_elevated_since = Some(now);
    });

    // Two ticks inside max_staleness (30s = 3 x 10s loss_sample_interval):
    // the episode must survive — proving the empty-collection tick still
    // reassesses it rather than skipping the reassessment outright.
    tokio::time::advance(Duration::from_secs(10)).await;
    manager.sample_carrier_loss_once().await;
    assert_eq!(
        manager.inner.read_status(0).tcp.loss_elevated_since,
        Some(now),
        "an episode reassessed on an empty-collection tick within max_staleness must survive"
    );

    tokio::time::advance(Duration::from_secs(10)).await;
    manager.sample_carrier_loss_once().await;
    assert_eq!(manager.inner.read_status(0).tcp.loss_elevated_since, Some(now));

    // Third tick crosses 30s total since the last qualifying measurement —
    // the episode must clear, even though nothing ever re-measured the wire
    // (there is no live carrier registered at all).
    tokio::time::advance(Duration::from_secs(15)).await;
    manager.sample_carrier_loss_once().await;
    assert_eq!(
        manager.inner.read_status(0).tcp.loss_elevated_since,
        None,
        "an episode whose last qualifying measurement is older than 3 x loss_sample_interval \
         must clear — pins max_staleness end to end through sample_carrier_loss_once, not just \
         as an isolated Duration value"
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

/// A carrier handed out from the warm pool never passes through the dial path,
/// so the take is the only place its loss probe can be filed. Field evidence
/// for why this matters: on the busiest gateway `transport_connects_total`
/// showed 3382 `reused` TCP acquisitions against 11 `started` ones, and the
/// TCP plane carried no verdict at all despite 1.4 GiB of traffic — measurement
/// coverage was following the dial rate rather than the traffic.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn taking_a_carrier_from_the_warm_pool_registers_its_loss_probe() {
    use outline_transport::TransportStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    let manager = crate::types::UplinkManager::new_for_test(
        "test",
        vec![crate::tests::make_uplink("primary", "wss://primary.example.com/tcp")],
        crate::tests::probe_disabled(),
        crate::tests::lb(),
    )
    .unwrap();

    // A real carrier over loopback: the take path peeks at the socket, so a
    // fabricated stream would be discarded as stale before registration.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (_server, _) = listener.accept().await.unwrap();
    let ws =
        WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None).await;
    manager.inner.standby_pools[0]
        .tcp
        .lock()
        .await
        .push_back(TransportStream::new_http1(ws));

    assert_eq!(
        manager.inner.carrier_loss[0].lock().len(),
        0,
        "nothing is registered before the take"
    );

    let candidate = crate::types::UplinkCandidate {
        index: 0,
        uplink: manager.inner.uplinks[0].clone(),
    };
    let taken = manager.try_take_tcp_standby(&candidate, 0).await;

    assert!(taken.is_some(), "the pooled carrier must be handed out");
    assert_eq!(
        manager.inner.carrier_loss[0].lock().len(),
        1,
        "a carrier taken from the pool must have its probe registered, or it is never measured"
    );
}

/// A `/control/apply` rebuilds every manager, and the probe registry lives on
/// the manager — so without carrying it across, every carrier that survives
/// the apply is never observed again. Registration only ever happens when a
/// carrier is dialed or handed out of the pool, and a long-lived one (a video
/// stream's UDP session) may not be dialed again for hours. Field evidence:
/// after an apply the busiest node kept publishing a TCP verdict, whose
/// carriers churn constantly, while its UDP plane went silent for good even
/// though it was carrying 17.9 MiB/min.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn probe_registries_survive_a_manager_rebuild() {
    let make = || {
        crate::types::UplinkManager::new_for_test(
            "test",
            vec![
                crate::tests::make_uplink("primary", "wss://primary.example.com/tcp"),
                crate::tests::make_uplink("backup", "wss://backup.example.com/tcp"),
            ],
            crate::tests::probe_disabled(),
            crate::tests::lb(),
        )
        .unwrap()
    };

    let old = make();
    let (probe, _client, _server) = crate::loss::tests_support::live_pair().await;
    old.register_carrier_loss_probe(1, 0, TransportKind::Udp, Some(probe));
    assert_eq!(old.inner.carrier_loss[1].lock().len(), 1);

    let carried = old.take_carrier_loss_registries();
    assert_eq!(
        old.inner.carrier_loss[1].lock().len(),
        0,
        "the displaced manager gives its registries up rather than keeping a second copy"
    );

    let new = make();
    new.adopt_carrier_loss_registries(carried);
    assert_eq!(
        new.inner.carrier_loss[1].lock().len(),
        1,
        "a carrier that outlived the rebuild must still be observed by the new manager"
    );
    assert_eq!(
        new.inner.carrier_loss[0].lock().len(),
        0,
        "and it must land on the uplink it belonged to, matched by name rather than by index"
    );
}
