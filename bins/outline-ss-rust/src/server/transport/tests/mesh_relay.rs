use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use quinn::{Connection, ReadError, ReadToEndError, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use outline_wire::CipherKind;
use outline_wire::cluster::ShardId;

use super::{
    EdgeThrottleCtx, EdgeThrottleDetector, StallTracker, handle_mesh_connection, open_edge_relay,
};
use crate::crypto::UserKey;
use crate::metrics::{AppProtocol, Metrics, Protocol};
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CarrierKind, CloseReason, ControlDatagram, MeshEndpoint, MeshFraming, MeshIdentity,
    MeshPeerPool, OPEN_ACK_ACCEPTED, OpenHeader, OpenHeaderV5, ThrottleRegistry, UserFrame,
    parse_control_datagram,
};
use crate::server::dns_cache::DnsCache;
use crate::server::nat::NatTable;
use crate::server::peer_user_cache::PeerUserCache;
use crate::server::replay::ReplayStore;
use crate::server::resumption::downlink_ring::DownlinkRing;
use crate::server::resumption::{
    OrphanRegistry, Parked, ParkedSsUdpStream, ParkedTcp, ResumeOutcome, ResumptionConfig,
    SessionId, TcpProtocolContext,
};
use crate::server::state::{RouteRegistry, RoutesSnapshot, Services, TransportRoute, UdpServices};
use crate::server::tests::sample_config;
use crate::server::transport::XhttpRegistryLimits;
use crate::server::transport::resume_headers::EdgeResumeAdvert;
use crate::server::transport::throughput_monitor::ThrottleDetectParams;

fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))))
}

/// Window 1s, fire after 3 sustained stall-windows, 30s cooldown. The
/// delivered-rate floor is disabled (0) so these cases isolate the streak +
/// cooldown logic; the floor has its own tests below. With the floor off the
/// delivered `bytes` are irrelevant, so they pass `0`.
fn tracker() -> StallTracker {
    StallTracker::new(&ThrottleDetectParams {
        window: Duration::from_secs(1),
        sustain_windows: 3,
        edge_min_bytes_per_sec: 0,
        signal_cooldown: Duration::from_secs(30),
        ..Default::default()
    })
}

#[tokio::test]
async fn fast_sends_never_fire() {
    let mut t = tracker();
    let now = Instant::now();
    for _ in 0..10 {
        assert!(!t.observe(Duration::from_millis(100), 0, now), "a fast send is not a stall");
    }
}

#[tokio::test]
async fn one_long_send_spans_the_streak() {
    let mut t = tracker();
    // A single send blocked for 3.5 windows already meets sustain_windows(3).
    assert!(t.observe(Duration::from_millis(3500), 0, Instant::now()));
}

#[tokio::test]
async fn gradual_stall_fires_after_sustain_windows() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // streak 1
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // streak 2
    assert!(t.observe(Duration::from_millis(1200), 0, now)); // streak 3 -> fire
}

#[tokio::test]
async fn a_fast_send_resets_the_streak() {
    let mut t = tracker();
    let now = Instant::now();
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // 2
    assert!(!t.observe(Duration::from_millis(100), 0, now)); // fast -> reset to 0
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // 1
    assert!(!t.observe(Duration::from_millis(1200), 0, now)); // 2
    assert!(t.observe(Duration::from_millis(1200), 0, now)); // 3 -> fire
}

#[tokio::test]
async fn cooldown_gates_a_second_hint() {
    let mut t = tracker();
    let t0 = Instant::now();
    assert!(t.observe(Duration::from_millis(3500), 0, t0), "first qualifying stall fires");
    // A second qualifying streak within the 30s cooldown is suppressed.
    assert!(!t.observe(Duration::from_millis(3500), 0, t0 + Duration::from_secs(10)));
    // Past the cooldown it fires again.
    assert!(t.observe(Duration::from_millis(3500), 0, t0 + Duration::from_secs(35)));
}

/// Window 1s, fire after 3 stall-windows, but with a 100 KB/s delivered-rate
/// floor to exercise the low-bandwidth cut.
fn floored_tracker() -> StallTracker {
    StallTracker::new(&ThrottleDetectParams {
        window: Duration::from_secs(1),
        sustain_windows: 3,
        edge_min_bytes_per_sec: 100_000,
        signal_cooldown: Duration::from_secs(30),
        ..Default::default()
    })
}

#[tokio::test]
async fn slow_client_below_floor_stays_quiet() {
    let mut t = floored_tracker();
    let now = Instant::now();
    // Three 1.2s stalled sends of 10 KB each: ~8.3 KB/s, far below the 100 KB/s
    // floor. The streak is met but delivery is a slow/idle client, not a
    // throttle — no hint fires.
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now));
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now));
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now));
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now));
}

#[tokio::test]
async fn throttled_client_above_floor_fires() {
    let mut t = floored_tracker();
    let now = Instant::now();
    // Three 1.2s stalled sends of 256 KiB each: ~218 KB/s, above the 100 KB/s
    // floor — a real last-mile throttle still pushing volume, so it fires.
    assert!(!t.observe(Duration::from_millis(1200), 262_144, now));
    assert!(!t.observe(Duration::from_millis(1200), 262_144, now));
    assert!(t.observe(Duration::from_millis(1200), 262_144, now));
}

#[tokio::test]
async fn a_slow_streak_that_speeds_up_past_the_floor_fires() {
    let mut t = floored_tracker();
    let now = Instant::now();
    // Two slow 10 KB windows keep the streak but stay under the floor...
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now)); // streak 1, below floor
    assert!(!t.observe(Duration::from_millis(1200), 10_000, now)); // streak 2, below floor
    // ...then a large delivery pulls the streak's average rate over the floor
    // ((10k+10k+1_000k)/3.6s ≈ 283 KB/s > 100 KB/s) while sustain is met.
    assert!(t.observe(Duration::from_millis(1200), 1_000_000, now)); // streak 3 -> fire
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
    let mut detector = EdgeThrottleDetector::new(ctx, test_metrics());
    // 100ms send spans ~10 windows (window 10ms), and 256 KiB over 100ms is
    // ~2.6 MB/s — well past the default 64 KB/s floor — so the hint fires.
    detector.observe_send(Duration::from_millis(100), 262_144);

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
    let mut detector = EdgeThrottleDetector::new(ctx, test_metrics());
    // 1ms << 10ms window: zero stalled windows, no hint (regardless of volume).
    detector.observe_send(Duration::from_millis(1), 262_144);

    let got = tokio::time::timeout(Duration::from_millis(300), home_conn.read_datagram()).await;
    assert!(got.is_err(), "a fast send must not emit a datagram");
    drop((home, edge, detector));
}

// ── Home-side accept loop ──────────────────────────────────────────────────────

/// A home-side mesh runtime over a fresh loopback endpoint, with empty route
/// tables and a `relay_cap`-slot relayed-session cap: enough for
/// `handle_mesh_connection` to admit relay streams and dispatch them. An
/// admitted relay parks on its first carrier read — these tests never write
/// payload bytes after the OPEN — so it holds its permit until the test drops
/// the connection.
/// One TCP route with a single configured user — the minimum a relayed carrier
/// needs to be admitted, since a path resolving to an empty user list is refused
/// at setup (every packet on it would fail authentication).
fn tcp_route() -> Arc<TransportRoute> {
    let user =
        UserKey::new("relay-user", "relay-password", None, CipherKind::Chacha20IetfPoly1305, None)
            .unwrap();
    Arc::new(TransportRoute {
        users: Arc::from(vec![user].into_boxed_slice()),
        candidate_users: Arc::from(vec![Arc::<str>::from("relay-user")].into_boxed_slice()),
        peer_user_cache: Arc::new(PeerUserCache::with_capacity(8)),
    })
}

/// Builds a home runtime whose TCP route table serves exactly `tcp_paths`. A
/// relayed carrier is admitted only when its OPEN path resolves to a non-empty
/// user list, so a test wanting an admitted relay must list the path its header
/// carries — and passing `&[]` models the config mismatch this home cannot serve.
fn home_runtime_serving(
    psk: &[u8],
    relay_cap: usize,
    tcp_paths: &[&str],
) -> (Arc<ClusterCtx>, Arc<Services>, RoutesSnapshot) {
    home_runtime_inner(psk, relay_cap, tcp_paths, None)
}

/// [`home_runtime_serving`] with a caller-supplied orphan registry, so a test
/// can park sessions the home will be asked to resume. The v4 tests pass `None`
/// and get the disabled no-op registry they have always had.
fn home_runtime_with_registry(
    psk: &[u8],
    relay_cap: usize,
    tcp_paths: &[&str],
    registry: Arc<OrphanRegistry>,
) -> (Arc<ClusterCtx>, Arc<Services>, RoutesSnapshot) {
    home_runtime_inner(psk, relay_cap, tcp_paths, Some(registry))
}

fn home_runtime_inner(
    psk: &[u8],
    relay_cap: usize,
    tcp_paths: &[&str],
    registry: Option<Arc<OrphanRegistry>>,
) -> (Arc<ClusterCtx>, Arc<Services>, RoutesSnapshot) {
    let metrics = test_metrics();
    let endpoint = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let cluster = Arc::new(ClusterCtx {
        pool: Arc::new(MeshPeerPool::new(endpoint.clone(), HashMap::new(), 8)),
        endpoint,
        relay_budget: Duration::from_secs(5),
        throttle_registry: ThrottleRegistry::new(),
        relay_permits: Arc::new(Semaphore::new(relay_cap)),
        metrics: Arc::clone(&metrics),
    });
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        registry,
        16,
        XhttpRegistryLimits::unbounded(),
    ));
    let tcp = tcp_paths
        .iter()
        .map(|path| ((*path).to_string(), tcp_route()))
        .collect::<BTreeMap<_, _>>();
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(tcp),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss: Arc::new(BTreeMap::new()),
        xhttp_ss_udp: Arc::new(BTreeMap::new()),
    }));
    (cluster, services, routes)
}

/// The common case: a home that serves the `/tcp` path [`ss_tcp_open`] carries.
fn home_runtime(psk: &[u8], relay_cap: usize) -> (Arc<ClusterCtx>, Arc<Services>, RoutesSnapshot) {
    home_runtime_serving(psk, relay_cap, &["/tcp"])
}

/// Connects an edge to `home` and hands back both ends of the mesh connection.
/// Both sides must be driven together: the home only progresses once it accepts.
async fn connect_edge(home: &MeshEndpoint, edge: &MeshEndpoint) -> (Connection, Connection) {
    let home_addr = home.local_addr().unwrap();
    tokio::join!(async { home.accept().await.unwrap().unwrap() }, async {
        edge.connect(home_addr).await.unwrap()
    })
}

/// Opens a relay stream and writes `open` as its length-prefixed OPEN header —
/// what `open_relay_stream` does on the edge, inlined here so a test can also
/// send a header this build cannot parse.
async fn open_relay(conn: &Connection, open: &[u8]) -> (SendStream, RecvStream) {
    let (mut send, recv) = conn.open_bi().await.unwrap();
    send.write_all(&(open.len() as u32).to_be_bytes()).await.unwrap();
    send.write_all(open).await.unwrap();
    (send, recv)
}

/// A well-formed OPEN header for an SS-over-WS relayed session.
fn ss_tcp_open(session: u8) -> Vec<u8> {
    OpenHeader {
        carrier: CarrierKind::SsTcp,
        session_id: [session; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        path: "/tcp".to_string(),
        peer_addr: None,
    }
    .encode()
}

/// Polls `outline_ss_mesh_relay_active` until it reads `want`, panicking after
/// 5 s. The gauge is the observable "this relay was admitted and is being
/// served" — it rises inside `serve_relayed` and falls when that returns.
async fn wait_for_active_relays(metrics: &Arc<Metrics>, want: u32) {
    let needle = format!("outline_ss_mesh_relay_active {want}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let rendered = metrics.render_prometheus();
        if rendered.lines().any(|line| line == needle) {
            return;
        }
        assert!(Instant::now() < deadline, "active relays never reached {want}:\n{rendered}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A relay stream whose OPEN this build cannot parse (a peer mid rolling
/// upgrade) is a *per-stream* failure, not a connection one: the QUIC
/// connection stays live, and the relays already riding it — plus the
/// control-datagram receiver the accept loop owns — depend on the loop staying
/// up. So the loop must drop that one stream and keep accepting.
#[tokio::test]
async fn an_unparsable_open_header_does_not_stop_the_accept_loop() {
    let psk = b"mesh-accept-bad-open-psk";
    let (cluster, services, routes) = home_runtime(psk, 8);
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let metrics = Arc::clone(&cluster.metrics);
    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services, routes));

    // Version 0xFF: a header this build rejects, exactly as a peer on a newer
    // wire version would send. Waiting for the home to close the stream pins the
    // ordering — the loop has seen this failure before the next stream opens.
    let (_bad_send, mut bad_recv) = open_relay(&edge_conn, &[0xFF; 8]).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), bad_recv.read_to_end(64))
        .await
        .expect("the home must close a relay stream whose OPEN it cannot parse");

    // A well-formed relay opened afterwards must still be served.
    let (_send, _recv) = open_relay(&edge_conn, &ss_tcp_open(1)).await;
    wait_for_active_relays(&metrics, 1).await;
    assert!(!home.is_finished(), "the accept loop must outlive a per-stream failure");
    drop((edge, edge_conn));
}

/// The one exit condition: when the peer closes the QUIC connection, the accept
/// loop must return (releasing the control-datagram receiver with it) rather
/// than spin on a dead connection.
#[tokio::test]
async fn a_closed_connection_ends_the_accept_loop() {
    let psk = b"mesh-accept-close-psk";
    let (cluster, services, routes) = home_runtime(psk, 8);
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services, routes));
    edge_conn.close(0u32.into(), b"edge done");

    tokio::time::timeout(Duration::from_secs(5), home)
        .await
        .expect("a closed connection must end the accept loop")
        .unwrap();
    drop(edge);
}

/// Bounded resources: a home serves at most `relay_permits` relayed sessions at
/// once. A stream arriving past the cap is refused outright — both halves reset
/// with [`CloseReason::Capacity`], so the edge fails fast and serves its client
/// locally — instead of spawning one more unbounded relay.
#[tokio::test]
async fn relay_streams_past_the_cap_are_refused() {
    let psk = b"mesh-accept-cap-psk";
    let (cluster, services, routes) = home_runtime(psk, 1);
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let metrics = Arc::clone(&cluster.metrics);
    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services, routes));

    // The single permit goes to the first relay, which parks on its carrier read
    // and holds it for the rest of the test.
    let (_first_send, _first_recv) = open_relay(&edge_conn, &ss_tcp_open(1)).await;
    wait_for_active_relays(&metrics, 1).await;

    let (_send, mut recv) = open_relay(&edge_conn, &ss_tcp_open(2)).await;
    let error = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
        .await
        .expect("a refused relay must be answered, not left hanging")
        .expect_err("the home must reset a relay stream it has no capacity for");
    let capacity = VarInt::from_u32(CloseReason::Capacity.code());
    assert!(
        matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == capacity),
        "expected a Capacity reset, got {error:?}",
    );
    // Refused, not served: the active-relay gauge never counted a second one.
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.lines().any(|line| line == "outline_ss_mesh_relay_active 1"),
        "a refused relay must not be spawned:\n{rendered}",
    );
    assert!(!home.is_finished(), "refusing a relay must not stop the accept loop");
    drop((edge, edge_conn));
}

/// Config-mismatch guard: a relayed carrier whose path resolves to no users on
/// this home must be refused at setup, not served. Serving it would hand the
/// relay a route with no keys, so every stream/datagram on it fails
/// authentication and is silently dropped — the black hole an asymmetric cluster
/// config produced in production (an edge relaying its own path to a home that
/// never served it). The refusal is explicit: a `NoRoute` reset the edge can act
/// on, plus a counted reason.
#[tokio::test]
async fn a_relayed_carrier_with_no_home_route_is_refused() {
    let psk = b"mesh-accept-no-route-psk";
    // This home serves no TCP path at all, so `/tcp` in the OPEN header cannot
    // resolve — exactly the asymmetric-path case.
    let (cluster, services, routes) = home_runtime_serving(psk, 8, &[]);
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let metrics = Arc::clone(&cluster.metrics);
    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services, routes));

    let (_send, mut recv) = open_relay(&edge_conn, &ss_tcp_open(1)).await;
    let error = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
        .await
        .expect("a relay with no servable route must be refused, not left hanging")
        .expect_err("the home must reset a relay stream it has no route for");
    let no_route = VarInt::from_u32(CloseReason::NoRoute.code());
    assert!(
        matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == no_route),
        "expected a NoRoute reset, got {error:?}",
    );

    let rendered = metrics.render_prometheus();
    // The gauge is only published once something touched it, so "never served"
    // reads as absent-or-zero.
    assert!(
        !rendered.lines().any(|line| {
            line.starts_with("outline_ss_mesh_relay_active ")
                && line != "outline_ss_mesh_relay_active 0"
        }),
        "a relay with no route must never be served:\n{rendered}",
    );
    assert!(
        rendered.lines().any(|line| {
            line.starts_with("outline_ss_mesh_relay_rejected_total{reason=\"no_route\"}")
                && line.ends_with(" 1")
        }),
        "the refusal must be counted under reason=\"no_route\":\n{rendered}",
    );
    assert!(!home.is_finished(), "refusing a relay must not stop the accept loop");
    drop((edge, edge_conn));
}

/// The positive half of the setup handshake: a path this home does serve is
/// admitted, and the home says so with the one-byte OPEN ack before any carrier
/// byte. The ack is what lets an edge tell "the home took this relay" from "the
/// home refused it" *before* it upgrades the client carrier.
#[tokio::test]
async fn an_admitted_relay_acks_before_serving() {
    let psk = b"mesh-accept-ack-psk";
    let (cluster, services, routes) = home_runtime(psk, 8);
    let edge = MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge).await;

    let metrics = Arc::clone(&cluster.metrics);
    let home = tokio::spawn(handle_mesh_connection(home_conn, cluster, services, routes));

    let (_send, mut recv) = open_relay(&edge_conn, &ss_tcp_open(1)).await;
    let mut ack = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack))
        .await
        .expect("the home must ack an admitted relay")
        .expect("reading the mesh OPEN ack");
    assert_eq!(ack[0], OPEN_ACK_ACCEPTED, "the ack byte must mark the relay accepted");

    wait_for_active_relays(&metrics, 1).await;
    assert!(!home.is_finished());
    drop((edge, edge_conn));
}

/// End-to-end degradation: when the home refuses for a config mismatch, the
/// edge's `open_edge_relay` returns `None` *before* the client carrier is
/// upgraded, so the caller serves a fresh local session instead of splicing the
/// client into a relay that would drop everything. This is the whole point of
/// gating the `101` on the ack.
#[tokio::test]
async fn an_edge_relay_refused_for_no_route_falls_back_to_a_local_session() {
    let psk = b"mesh-edge-fallback-psk";
    let (home_cluster, services, routes) = home_runtime_serving(psk, 8, &[]);
    let home_addr = home_cluster.endpoint.local_addr().unwrap();
    let home_endpoint = home_cluster.endpoint.clone();

    // Home side: accept the edge's dial and serve its streams.
    let home_metrics = Arc::clone(&home_cluster.metrics);
    let home = tokio::spawn(async move {
        let conn = home_endpoint.accept().await.unwrap().unwrap();
        handle_mesh_connection(conn, home_cluster, services, routes).await;
    });

    let shard = ShardId::new(0).unwrap();
    let edge_endpoint =
        MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
    let edge_cluster = ClusterCtx {
        pool: Arc::new(MeshPeerPool::new(
            edge_endpoint.clone(),
            HashMap::from([(shard, home_addr)]),
            8,
        )),
        endpoint: edge_endpoint,
        relay_budget: Duration::from_secs(5),
        throttle_registry: ThrottleRegistry::new(),
        relay_permits: Arc::new(Semaphore::new(8)),
        metrics: test_metrics(),
    };

    let advert = EdgeResumeAdvert {
        session_id: SessionId::from_bytes([1u8; 16]),
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: false,
        down_acked: 0,
    };
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 40000));
    let opened = tokio::time::timeout(
        Duration::from_secs(5),
        open_edge_relay(&edge_cluster, shard, &advert, CarrierKind::SsTcp, "/tcp", peer),
    )
    .await
    .expect("a refused relay must resolve, not hang the upgrade");
    assert!(
        opened.is_none(),
        "a home refusing for no route must leave the edge to serve a fresh local session",
    );

    let rendered = edge_cluster.metrics.render_prometheus();
    assert!(
        rendered.lines().any(|line| {
            line.starts_with("outline_ss_mesh_relay_opened_total{outcome=\"refused\"}")
                && line.ends_with(" 1")
        }),
        "an explicit home refusal must be counted apart from an unreachable home:\n{rendered}",
    );
    // The home counted the same event on its side.
    let home_rendered = home_metrics.render_prometheus();
    assert!(
        home_rendered.lines().any(|line| {
            line.starts_with("outline_ss_mesh_relay_rejected_total{reason=\"no_route\"}")
                && line.ends_with(" 1")
        }),
        "the home must count the refusal it issued:\n{home_rendered}",
    );
    home.abort();
}

// ── Home-side v5 (edge-terminated crypto) ─────────────────────────────────────

/// A resumption config with the feature and the v2 downlink ring both on — the
/// shape a home needs to hold parks and replay their unacked suffix.
fn enabled_resumption() -> ResumptionConfig {
    ResumptionConfig {
        enabled: true,
        downlink_buffer_bytes: 64 * 1024,
        ..ResumptionConfig::defaults_disabled()
    }
}

fn test_registry() -> Arc<OrphanRegistry> {
    Arc::new(OrphanRegistry::new(enabled_resumption(), test_metrics()))
}

/// The far end of a parked session's upstream socket, standing in for the
/// target server. Held by the test so the socket stays open — dropping it would
/// EOF the parked upstream the home is about to splice onto.
struct TestUpstream {
    peer: tokio::net::TcpStream,
}

impl TestUpstream {
    /// Reads exactly `n` bytes the home wrote to the parked upstream.
    async fn read(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), self.peer.read_exact(&mut buf))
            .await
            .expect("the upstream must receive the relayed bytes")
            .expect("reading the relayed uplink");
        buf
    }

    /// Writes `data` as if the target server answered.
    async fn write(&mut self, data: &[u8]) {
        self.peer
            .write_all(data)
            .await
            .expect("writing the upstream downlink");
    }

    /// Kills the upstream with an RST, as a target that dies mid-response does.
    /// `SO_LINGER = 0` turns the close into a reset, so the home's next upstream
    /// read fails instead of reading a clean EOF. Set through `socket2` on the
    /// borrowed fd — tokio's own setter is deprecated, and a zero linger cannot
    /// block on close anyway (there is nothing to flush).
    fn abort(self) {
        let socket = socket2::SockRef::from(&self.peer);
        socket
            .set_linger(Some(Duration::ZERO))
            .expect("setting SO_LINGER on the test upstream");
        drop(self);
    }
}

/// Parks a TCP session under `id` owned by `owner`, returning the far end of
/// its upstream socket. Mirrors what the relay parks on a carrier drop.
async fn park_test_session(registry: &OrphanRegistry, id: SessionId, owner: &str) -> TestUpstream {
    park_parked_tcp(registry, id, owner, None).await
}

/// Like [`park_test_session`] but with a v2 downlink ring already holding
/// `already_sent` — the plaintext the session had emitted before the carrier
/// died, which the next resume replays the unacked suffix of.
async fn park_test_session_with_ring(
    registry: &OrphanRegistry,
    id: SessionId,
    owner: &str,
    already_sent: &[u8],
) -> TestUpstream {
    let ring = Arc::new(parking_lot::Mutex::new(DownlinkRing::new(64 * 1024)));
    ring.lock().push(already_sent);
    park_parked_tcp(registry, id, owner, Some(ring)).await
}

async fn park_parked_tcp(
    registry: &OrphanRegistry,
    id: SessionId,
    owner: &str,
    downlink_ring: Option<Arc<parking_lot::Mutex<DownlinkRing>>>,
) -> TestUpstream {
    let listener = tokio::net::TcpListener::bind(loopback()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (upstream, peer) = tokio::join!(
        async { listener.accept().await.unwrap().0 },
        tokio::net::TcpStream::connect(addr),
    );
    let (upstream_reader, upstream_writer) = upstream.into_split();
    let metrics = test_metrics();
    let user = UserKey::new(owner, "relay-password", None, CipherKind::Chacha20IetfPoly1305, None)
        .unwrap();
    let user_id = user.id_arc();
    registry.park(
        id,
        Parked::Tcp(ParkedTcp {
            upstream_writer,
            upstream_reader,
            target_display: Arc::from("example.com:443"),
            owner: Arc::clone(&user_id),
            protocol_context: TcpProtocolContext::Ss(user),
            user_counters: metrics.user_counters(&user_id),
            upstream_guard: metrics.open_tcp_upstream_connection(
                user_id,
                Protocol::Http3,
                AppProtocol::Shadowsocks,
            ),
            upstream_bytes_acked: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            downlink_ring,
        }),
    );
    TestUpstream { peer: peer.unwrap() }
}

/// A v5 OPEN header for a TCP-framed relayed session under `id`.
fn v5_header(id: SessionId) -> OpenHeaderV5 {
    OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: *id.as_bytes(),
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    }
}

/// What an edge observes from a v5 relay attempt: whether the home acked, and
/// the reason it eventually closed the stream with (if any).
struct V5Outcome {
    acked: bool,
    close_reason: Option<CloseReason>,
}

impl V5Outcome {
    fn acked(&self) -> bool {
        self.acked
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }
}

/// A live v5 relay: the edge's half of an admitted, spliced session.
struct V5Session {
    send: SendStream,
    recv: RecvStream,
}

impl V5Session {
    /// Writes plaintext toward the home, as an edge does once it has decrypted
    /// a client frame.
    async fn edge_write(&mut self, data: &[u8]) {
        self.send
            .write_all(data)
            .await
            .expect("writing plaintext to the home");
    }

    /// Reads exactly `n` plaintext bytes the home relayed back.
    async fn edge_read(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), self.recv.read_exact(&mut buf))
            .await
            .expect("the home must relay the downlink")
            .expect("reading the relayed downlink");
        buf
    }

    /// Ends the edge's half as a carrier switch does, then waits for the home to
    /// close its own. The client-gone path is the one failure-free end, so the
    /// home must answer it with a FIN rather than a reset.
    async fn edge_finish(mut self) {
        self.send.finish().expect("finishing the edge half");
        tokio::time::timeout(Duration::from_secs(5), self.recv.read_to_end(4096))
            .await
            .expect("the home must close its half once the edge finishes")
            .expect("a client-gone end must be a clean FIN, not a reset");
    }

    /// Waits for the home to end the stream and reports how: `None` for a clean
    /// FIN, `Some(reason)` for a reset.
    async fn end_reason(mut self) -> Option<CloseReason> {
        let ended = tokio::time::timeout(Duration::from_secs(5), self.recv.read_to_end(4096))
            .await
            .expect("the home must end the relay, not leave it hanging");
        match ended {
            Ok(_) => None,
            Err(ReadToEndError::Read(error)) => Some(reset_reason_read(&error)),
            Err(other) => panic!("unexpected read-to-end failure: {other:?}"),
        }
    }
}

/// A home node running the real mesh accept loop, plus an edge connection to
/// drive it with. Exercises the live version dispatch: every header goes over a
/// real mesh QUIC stream into `handle_mesh_connection`.
struct MeshHomeHarness {
    /// Held so the home endpoint and its relay-permit pool outlive the harness.
    _cluster: Arc<ClusterCtx>,
    registry: Arc<OrphanRegistry>,
    metrics: Arc<Metrics>,
    /// Held so the edge socket stays bound for the harness's lifetime.
    _edge_endpoint: MeshEndpoint,
    edge_conn: Connection,
    home: tokio::task::JoinHandle<()>,
}

impl MeshHomeHarness {
    async fn new() -> Self {
        let psk = b"mesh-home-v5-psk";
        let registry = test_registry();
        let (cluster, services, routes) =
            home_runtime_with_registry(psk, 8, &["/tcp"], Arc::clone(&registry));
        let edge_endpoint =
            MeshEndpoint::bind(loopback(), &MeshIdentity::derive(psk).unwrap()).unwrap();
        let (home_conn, edge_conn) = connect_edge(&cluster.endpoint, &edge_endpoint).await;
        let metrics = Arc::clone(&cluster.metrics);
        let home =
            tokio::spawn(handle_mesh_connection(home_conn, Arc::clone(&cluster), services, routes));
        Self {
            _cluster: cluster,
            registry,
            metrics,
            _edge_endpoint: edge_endpoint,
            edge_conn,
            home,
        }
    }

    fn registry(&self) -> &Arc<OrphanRegistry> {
        &self.registry
    }

    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Opens a v5 relay and reports the outcome, sending the USER frame only if
    /// the home acked (as a real edge does).
    async fn serve_v5(&self, header: OpenHeaderV5) -> V5Outcome {
        self.serve_v5_with_user(header, "beerloga").await
    }

    async fn serve_v5_with_user(&self, header: OpenHeaderV5, user: &str) -> V5Outcome {
        let (mut send, mut recv) = open_relay(&self.edge_conn, &header.encode()).await;
        let mut ack = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack))
            .await
            .expect("the home must answer a v5 OPEN, not leave it hanging");
        if let Err(error) = read {
            return V5Outcome {
                acked: false,
                close_reason: Some(reset_reason(&error)),
            };
        }
        assert_eq!(ack[0], OPEN_ACK_ACCEPTED, "an ack byte must mark the relay accepted");
        send.write_all(&UserFrame { user: user.to_string() }.encode())
            .await
            .expect("writing the USER frame");
        let ended = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
            .await
            .expect("the home must resolve phase 2, not leave it hanging");
        let close_reason = match ended {
            Ok(_) => None,
            Err(ReadToEndError::Read(error)) => Some(reset_reason_read(&error)),
            Err(other) => panic!("unexpected read-to-end failure: {other:?}"),
        };
        V5Outcome { acked: true, close_reason }
    }

    /// Opens a v5 relay that must be admitted, returning the spliced session.
    async fn serve_v5_ok(&self, header: OpenHeaderV5, user: &str) -> V5Session {
        let (mut send, mut recv) = open_relay(&self.edge_conn, &header.encode()).await;
        let mut ack = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack))
            .await
            .expect("the home must ack an admitted v5 relay")
            .expect("reading the v5 OPEN ack");
        assert_eq!(ack[0], OPEN_ACK_ACCEPTED);
        send.write_all(&UserFrame { user: user.to_string() }.encode())
            .await
            .expect("writing the USER frame");
        V5Session { send, recv }
    }

    /// Drives a v4 OPEN and reports whether it reached the untouched v4 path.
    /// Only that path admits a header carrying a route path with no park behind
    /// it — the v5 path would refuse it with `NoSession`.
    async fn serve_v4_reaches_legacy_path(&self) -> bool {
        let (_send, mut recv) = open_relay(&self.edge_conn, &ss_tcp_open(1)).await;
        let mut ack = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut ack)).await;
        if !matches!(read, Ok(Ok(()))) || ack[0] != OPEN_ACK_ACCEPTED {
            return false;
        }
        wait_for_active_relays(&self.metrics, 1).await;
        true
    }
}

impl Drop for MeshHomeHarness {
    fn drop(&mut self) {
        self.home.abort();
    }
}

/// The `CloseReason` behind a `quinn` read failure, or `Abort` for any other
/// failure shape (a reset is a reset).
fn reset_reason(error: &quinn::ReadExactError) -> CloseReason {
    match error {
        quinn::ReadExactError::ReadError(error) => reset_reason_read(error),
        quinn::ReadExactError::FinishedEarly(_) => CloseReason::Fin,
    }
}

fn reset_reason_read(error: &ReadError) -> CloseReason {
    match error {
        ReadError::Reset(code) => CloseReason::from_code(
            u32::try_from(code.into_inner()).expect("close reasons fit in a u32"),
        ),
        _ => CloseReason::Abort,
    }
}

#[tokio::test]
async fn has_park_reports_a_committed_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([3u8; 16]);
    assert!(!registry.has_park(id), "no park yet");

    let _upstream = park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id), "a committed park must be visible");
}

#[tokio::test]
async fn has_park_reports_an_in_flight_reservation() {
    // The phase-1 ack must not answer "no session" while a park is still
    // landing — that is the park-miss race `take_for_resume` already guards.
    let registry = test_registry();
    let id = SessionId::from_bytes([4u8; 16]);
    let _reservation = registry.reserve_park(id);

    assert!(registry.has_park(id), "a reserved park must count as present");
}

#[tokio::test]
async fn has_park_does_not_consume_the_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([5u8; 16]);
    let _upstream = park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id));
    assert!(registry.has_park(id), "the probe must be read-only");

    let outcome = registry.take_for_resume(id, "beerloga").await;
    assert!(matches!(outcome, ResumeOutcome::Hit(_)), "the park must still be takeable");
}

#[tokio::test]
async fn v5_home_refuses_when_no_park_exists() {
    let harness = MeshHomeHarness::new().await;

    let outcome = harness.serve_v5(v5_header(SessionId::from_bytes([6u8; 16]))).await;

    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
    assert!(
        !outcome.acked(),
        "the refusal replaces the ack, before the edge upgrades its client"
    );
}

#[tokio::test]
async fn v5_home_refuses_when_the_user_does_not_own_the_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([7u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let outcome = harness.serve_v5_with_user(v5_header(id), "cloud").await;

    assert!(outcome.acked(), "phase 1 cannot know the user yet, so it acks");
    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
}

#[tokio::test]
async fn v5_home_splices_plaintext_to_the_parked_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([8u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    // Uplink: what the edge writes as plaintext reaches the parked upstream verbatim.
    session.edge_write(b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(upstream.read(18).await, b"GET / HTTP/1.1\r\n\r\n");

    // Downlink: the home encrypts nothing — the edge seals it under its own key.
    upstream.write(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert_eq!(session.edge_read(19).await, b"HTTP/1.1 200 OK\r\n\r\n");
}

#[tokio::test]
async fn v5_home_replays_the_ring_suffix_before_new_downlink() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([9u8; 16]);
    // 12 plaintext bytes already sent, client acked the first 5.
    let _upstream =
        park_test_session_with_ring(harness.registry(), id, "beerloga", b"HELLO-WORLD!").await;

    let mut header = v5_header(id);
    header.symmetric_replay = true;
    header.client_down_acked = 5;

    let mut session = harness.serve_v5_ok(header, "beerloga").await;

    assert_eq!(
        session.edge_read(7).await,
        b"-WORLD!",
        "the home replays exactly the unacked suffix, as plaintext"
    );
}

#[tokio::test]
async fn a_v4_relay_still_takes_the_untouched_v4_path() {
    // The 24 end-to-end cluster tests depend on this until Task 7 retires v4.
    let harness = MeshHomeHarness::new().await;

    assert!(
        harness.serve_v4_reaches_legacy_path().await,
        "a v4 OPEN must still dispatch into the original serve_relayed"
    );
}

/// Value of the rendered Prometheus counter whose line starts with `prefix`, or
/// `0` when the series was never touched (an untouched counter is not rendered).
fn counter_value(rendered: &str, prefix: &str) -> u64 {
    rendered
        .lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn rejected(rendered: &str, reason: &str) -> u64 {
    counter_value(
        rendered,
        &format!("outline_ss_mesh_relay_rejected_total{{reason=\"{reason}\"}}"),
    )
}

fn outcome(rendered: &str, outcome: &str) -> u64 {
    counter_value(
        rendered,
        &format!("outline_ss_mesh_relay_outcome_total{{outcome=\"{outcome}\"}}"),
    )
}

/// Parks a session of a kind the TCP splice cannot serve, so a TCP-framed v5
/// OPEN for the same id hits the parked-kind mismatch arm.
fn park_ss_udp_stream(registry: &OrphanRegistry, id: SessionId, owner: &str) {
    registry.park(
        id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: Vec::new(),
            owner: Arc::from(owner),
        }),
    );
}

/// The home does not own a plaintext SS-UDP path yet, so a v5 OPEN carrying UDP
/// framing must be refused before anything is consumed — and, critically, before
/// the park is taken, so the session survives for a carrier this home can serve.
#[tokio::test]
async fn v5_home_refuses_udp_framing() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([20u8; 16]);
    let _upstream = park_test_session(harness.registry(), id, "beerloga").await;

    let mut header = v5_header(id);
    header.framing = MeshFraming::Udp;
    let outcome_seen = harness.serve_v5(header).await;

    assert!(!outcome_seen.acked(), "the refusal replaces the ack");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    assert!(
        harness.registry().has_park(id),
        "a refused UDP relay must leave the park untouched for a servable carrier",
    );
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "udp_unsupported"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 1, "{rendered}");
}

/// A TCP-framed v5 OPEN whose id resolves to a park of another kind is a forged
/// or mismatched peer. It must be refused — and counted, so a home that keeps
/// hitting this is visible rather than silently dropping relays.
#[tokio::test]
async fn v5_home_refuses_a_park_of_the_wrong_kind() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([21u8; 16]);
    park_ss_udp_stream(harness.registry(), id, "beerloga");

    let outcome_seen = harness.serve_v5(v5_header(id)).await;

    assert!(outcome_seen.acked(), "phase 1 only asks whether a park exists");
    assert_eq!(outcome_seen.close_reason(), Some(CloseReason::Abort));
    let rendered = harness.metrics().render_prometheus();
    assert_eq!(rejected(&rendered, "framing_mismatch"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 1, "{rendered}");
}

/// Accounting completeness: every terminal path through the v5 handler records
/// exactly one outcome, so `outline_ss_mesh_relay_outcome_total` reconciles
/// against the relays this home actually served. A never-working relay went
/// unnoticed in production precisely because it did not.
#[tokio::test]
async fn v5_relay_outcomes_are_counted_on_every_path() {
    let harness = MeshHomeHarness::new().await;

    // Miss: nothing parked under the id.
    let missed = harness.serve_v5(v5_header(SessionId::from_bytes([22u8; 16]))).await;
    assert_eq!(missed.close_reason(), Some(CloseReason::NoSession));

    // Miss: a park exists but belongs to someone else.
    let stolen = SessionId::from_bytes([23u8; 16]);
    let _stolen_upstream = park_test_session(harness.registry(), stolen, "beerloga").await;
    let rejected_owner = harness.serve_v5_with_user(v5_header(stolen), "cloud").await;
    assert_eq!(rejected_owner.close_reason(), Some(CloseReason::NoSession));

    // Hit: the park this user owns is spliced onto the relay.
    let served = SessionId::from_bytes([24u8; 16]);
    let _served_upstream = park_test_session(harness.registry(), served, "beerloga").await;
    let _session = harness.serve_v5_ok(v5_header(served), "beerloga").await;
    wait_for_active_relays(harness.metrics(), 1).await;

    let rendered = harness.metrics().render_prometheus();
    assert_eq!(outcome(&rendered, "hit"), 1, "{rendered}");
    assert_eq!(outcome(&rendered, "miss"), 2, "{rendered}");
    assert_eq!(rejected(&rendered, "no_session"), 1, "{rendered}");
    assert_eq!(rejected(&rendered, "unknown_user"), 1, "{rendered}");
}

/// A v5 session must survive more than one carrier switch. The home owns the
/// upstream socket, so when the mesh carrier ends it has to put the session back
/// into the registry under the same id — otherwise the second switch closes the
/// upstream and the client silently loses its connection.
#[tokio::test]
async fn a_v5_session_can_be_resumed_twice() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([25u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;

    // First carrier.
    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    first.edge_write(b"first").await;
    assert_eq!(upstream.read(5).await, b"first");
    upstream.write(b"one").await;
    assert_eq!(first.edge_read(3).await, b"one");
    first.edge_finish().await;

    // The home must have re-parked the still-healthy upstream.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !harness.registry().has_park(id) {
        assert!(Instant::now() < deadline, "the home never re-parked the relayed session");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Second carrier: the same upstream socket, still live.
    let mut second = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    second.edge_write(b"second").await;
    assert_eq!(
        upstream.read(6).await,
        b"second",
        "the second carrier must reach the very same upstream socket"
    );
    upstream.write(b"two").await;
    assert_eq!(second.edge_read(3).await, b"two");

    let rendered = harness.metrics().render_prometheus();
    assert_eq!(outcome(&rendered, "hit"), 2, "both carriers are hits:\n{rendered}");
}

/// A failure mid-splice must not reach the edge as a graceful FIN. Dropping the
/// mesh send half would `finish` it, and the edge would seal a truncated
/// response to its client as complete — so every failure arm resets instead.
#[tokio::test]
async fn a_failed_splice_does_not_present_as_a_clean_close() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([26u8; 16]);
    let upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    // The target dies with an RST, so the home's upstream read fails.
    upstream.abort();

    assert_eq!(
        session.end_reason().await,
        Some(CloseReason::Abort),
        "a broken upstream must reach the edge as a reset, never as a clean FIN",
    );
}

/// The other half of the contract: a genuine upstream EOF still ends the mesh
/// stream gracefully, so the edge can seal a complete response.
#[tokio::test]
async fn a_clean_upstream_eof_still_finishes_the_relay_stream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([27u8; 16]);
    let mut upstream = park_test_session(harness.registry(), id, "beerloga").await;
    let session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    upstream.write(b"done").await;
    drop(upstream); // ordinary close: FIN, not RST

    assert_eq!(
        session.end_reason().await,
        None,
        "a clean upstream EOF must finish the relay stream, not reset it",
    );
}
