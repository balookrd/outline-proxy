use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::{EdgeThrottleCtx, EdgeThrottleDetector, StallTracker};
use crate::server::cluster::mesh::{
    ControlDatagram, MeshEndpoint, MeshIdentity, parse_control_datagram,
};
use crate::server::transport::throughput_monitor::ThrottleDetectParams;

/// Window 1s, fire after 3 sustained stall-windows, 30s cooldown.
fn tracker() -> StallTracker {
    StallTracker::new(&ThrottleDetectParams {
        window: Duration::from_secs(1),
        sustain_windows: 3,
        signal_cooldown: Duration::from_secs(30),
        ..Default::default()
    })
}

#[tokio::test]
async fn fast_sends_never_fire() {
    let mut t = tracker();
    let now = Instant::now();
    for _ in 0..10 {
        assert!(!t.observe(Duration::from_millis(100), now), "a fast send is not a stall");
    }
}

#[tokio::test]
async fn one_long_send_spans_the_streak() {
    let mut t = tracker();
    // A single send blocked for 3.5 windows already meets sustain_windows(3).
    assert!(t.observe(Duration::from_millis(3500), Instant::now()));
}

#[tokio::test]
async fn gradual_stall_fires_after_sustain_windows() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), now)); // streak 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // streak 2
    assert!(t.observe(Duration::from_millis(1200), now)); // streak 3 -> fire
}

#[tokio::test]
async fn a_fast_send_resets_the_streak() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // 2
    assert!(!t.observe(Duration::from_millis(100), now)); // fast -> reset to 0
    assert!(!t.observe(Duration::from_millis(1200), now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), now)); // 2
    assert!(t.observe(Duration::from_millis(1200), now)); // 3 -> fire
}

#[tokio::test]
async fn cooldown_gates_a_second_hint() {
    let mut t = tracker();
    let t0 = Instant::now();
    assert!(t.observe(Duration::from_millis(3500), t0), "first qualifying stall fires");
    // A second qualifying streak within the 30s cooldown is suppressed.
    assert!(!t.observe(Duration::from_millis(3500), t0 + Duration::from_secs(10)));
    // Past the cooldown it fires again.
    assert!(t.observe(Duration::from_millis(3500), t0 + Duration::from_secs(35)));
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Detection tunables that fire on a single stalled window with a long cooldown.
fn fire_on_first_stall() -> ThrottleDetectParams {
    ThrottleDetectParams {
        enabled: true,
        window: Duration::from_millis(10),
        sustain_windows: 1,
        signal_cooldown: Duration::from_secs(30),
        ..Default::default()
    }
}

/// End-to-end datagram signalling over a real mesh QUIC connection: the edge
/// detector, on a sustained client-write stall, sends a THROTTLE_HINT that the
/// home reads and decodes to the same session id. Exercises the whole novel wire
/// path of T3 — that mesh datagrams are enabled (T1 config), the codec round-
/// trips over a real hop, and the detector actually emits on `observe_send` —
/// which the pure `StallTracker` / `ThrottleRegistry` unit tests cannot.
#[tokio::test]
async fn edge_detector_signals_throttle_hint_over_the_mesh() {
    let psk = b"t5-throttle-hint-psk";
    let home = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();

    // Both sides must drive the handshake: the home only progresses once it
    // accepts (a quinn gotcha the mesh endpoint tests hit too).
    let (home_conn, edge_conn) =
        tokio::join!(async { home.accept().await.unwrap().unwrap() }, async {
            edge.connect(home_addr).await.unwrap()
        },);

    let session_id = [9u8; 16];
    // Build the detector directly over the dialled connection (no PADDING global
    // needed) and drive one send blocked for ~10 windows — past sustain_windows.
    let ctx = EdgeThrottleCtx {
        conn: edge_conn,
        session_id,
        params: fire_on_first_stall(),
    };
    let mut detector = EdgeThrottleDetector::new(ctx);
    detector.observe_send(Duration::from_millis(100));

    let datagram = tokio::time::timeout(Duration::from_secs(5), home_conn.read_datagram())
        .await
        .expect("a throttle-hint datagram must arrive")
        .expect("mesh connection must stay open");
    assert_eq!(
        parse_control_datagram(&datagram).unwrap(),
        ControlDatagram::ThrottleHint { session_id },
        "the home must decode the hint to the same session id",
    );
    // Keep the endpoints alive until the datagram has been read.
    drop((home, edge, detector));
}

/// A fast client-facing send is not a stall, so the edge sends nothing: the home
/// waits and times out.
#[tokio::test]
async fn edge_detector_stays_quiet_for_a_fast_send() {
    let psk = b"t5-quiet-psk";
    let home = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let home_addr = home.local_addr().unwrap();
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();

    let (home_conn, edge_conn) =
        tokio::join!(async { home.accept().await.unwrap().unwrap() }, async {
            edge.connect(home_addr).await.unwrap()
        },);

    let ctx = EdgeThrottleCtx {
        conn: edge_conn,
        session_id: [1u8; 16],
        params: fire_on_first_stall(),
    };
    let mut detector = EdgeThrottleDetector::new(ctx);
    // 1ms << 10ms window: zero stalled windows, no hint.
    detector.observe_send(Duration::from_millis(1));

    let got = tokio::time::timeout(Duration::from_millis(300), home_conn.read_datagram()).await;
    assert!(got.is_err(), "a fast send must not emit a datagram");
    drop((home, edge, detector));
}
