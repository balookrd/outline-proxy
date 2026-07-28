use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use quinn::{Connection, ReadError, ReadToEndError, RecvStream, SendStream, VarInt};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use outline_wire::CipherKind;
use outline_wire::cluster::ShardId;

use super::{
    EdgeThrottleCtx, EdgeThrottleDetector, StallTracker, handle_mesh_connection, open_edge_relay,
};
use crate::crypto::UserKey;
use crate::metrics::Metrics;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CarrierKind, CloseReason, ControlDatagram, MeshEndpoint, MeshIdentity, MeshPeerPool,
    OPEN_ACK_ACCEPTED, OpenHeader, ThrottleRegistry, parse_control_datagram,
};
use crate::server::dns_cache::DnsCache;
use crate::server::nat::NatTable;
use crate::server::peer_user_cache::PeerUserCache;
use crate::server::replay::ReplayStore;
use crate::server::resumption::SessionId;
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
        None,
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
