//! `tun_wire_dial` on the UDP plane: a wire with no UDP path configured must
//! be *skipped*, never dialed and failed.
//!
//! The uplink under test has three wires: the primary (wire 0) is a genuine
//! carrier fault (nothing listens on the dead port, so the dial really is
//! attempted and really does fail), the first fallback (wire 1) has no UDP
//! path configured at all, and the second fallback (wire 2) is live. If wire 1
//! is correctly skipped, `active_wire` — the only externally observable trace
//! of `record_wire_outcome` — advances exactly once within the dial (0 → 1,
//! off wire 0's real failure) and then holds. An implementation that instead
//! attempts wire 1 and records its inevitable failure would advance a
//! *second* time in the same dial (1 → 2), because `min_failures = 1` in this
//! fixture flips the active wire on a single recorded failure. That second
//! advance is the regression this suite exists to catch — reaching wire 2's
//! live upstream at all is necessary but not sufficient, since a buggy
//! "attempt every wire, even one with no UDP path configured" implementation
//! reaches it too.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use outline_uplink::{
    CipherKind, FallbackTransport, LoadBalancingConfig, ProbeConfig, TransportKind, TransportMode,
    UplinkConfig, UplinkManager, UplinkRegistry, UplinkTransport, WsProbeConfig,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use url::Url;

use crate::udp::{TunUdpEngine, UdpFlowKey};
use crate::wire::IpVersion;
use crate::{SharedTunWriter, TunRouting};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const REMOTE_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// A live WS upstream that just accepts and counts — no resume/decrypt
// machinery needed, this suite only cares which wire got a completed dial.
// ---------------------------------------------------------------------------

struct LiveUdpUpstream {
    url: Url,
    accepted: Arc<AtomicUsize>,
    accepted_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<()>>,
}

impl LiveUdpUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel();
        let counter = Arc::clone(&accepted);
        let notify = accepted_tx;
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                let notify = notify.clone();
                tokio::spawn(async move {
                    let Ok(ws) = accept_async(stream).await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = notify.send(());
                    // Drain until the client goes away; the datagram contents
                    // are irrelevant to this suite.
                    use futures_util::StreamExt;
                    let (_sink, mut read) = ws.split();
                    while read.next().await.transpose().ok().flatten().is_some() {}
                });
            }
        });
        Self {
            url: Url::parse(&format!("ws://{addr}/udp")).unwrap(),
            accepted,
            accepted_rx: tokio::sync::Mutex::new(accepted_rx),
        }
    }

    fn url(&self) -> Url {
        self.url.clone()
    }

    async fn expect_accept(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            self.accepted_rx.lock().await.recv().await
        })
        .await
        .expect("timed out waiting for the live wire to be dialed")
        .expect("upstream accept loop ended");
    }

    fn accept_count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Fixture: one uplink, three wires.
// ---------------------------------------------------------------------------

/// A URL nothing listens on: connection refused, deterministically and fast —
/// the same fixture `crate::tcp::engine::tests::wire_fallback` uses for a
/// dead primary.
fn dead_url() -> Url {
    "ws://127.0.0.1:1/udp".parse().unwrap()
}

fn ss_fallback(udp_ws_url: Option<Url>) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

/// Wire 0 = dead (real dial, real failure). Wire 1 = no UDP path configured
/// at all. Wire 2 = live.
fn three_wire_uplink(wire2_live_url: Url) -> UplinkConfig {
    UplinkConfig {
        name: "primary".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(dead_url()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![ss_fallback(None), ss_fallback(Some(wire2_live_url))],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

fn test_probe_config() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 2,
        max_dials: 1,
        // A single recorded failure flips `active_wire` — this fixture
        // relies on that to tell "skipped" from "attempted and failed" apart
        // within one dial (see the module doc).
        min_failures: 1,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn test_load_balancing_config() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: outline_uplink::LoadBalancingMode::ActiveActive,
        routing_scope: outline_uplink::RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
        loss_latency_penalty_k: 0.0,
        loss_latency_inflation_max: 4.0,
        loss_sample_interval: Duration::from_secs(30),
        loss_sample_min_packets: 50,
        loss_ewma_alpha: 0.2,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        mode_downgrade_duration: Duration::from_secs(60),
        carrier_degraded_failover: None,
        loss_failover_ratio: 0.0,
        loss_failover_duration: None,
        runtime_failure_window: Duration::from_secs(60),
        chunk0_failure_window: Duration::from_secs(300),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        health_weighted_selection: false,
        tun_wire_dial: false,
        health_weight_floor: 0.05,
        vless_udp_mux_limits: outline_uplink::VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
        reselect_at: Vec::new(),
        reselect_interval: None,
    }
}

async fn build_manager(wire2_live_url: Url, tun_wire_dial: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![three_wire_uplink(wire2_live_url)],
        test_probe_config(),
        LoadBalancingConfig {
            tun_wire_dial,
            ..test_load_balancing_config()
        },
    )
    .unwrap()
}

fn test_tun_writer() -> SharedTunWriter {
    let path = std::env::temp_dir()
        .join(format!("outline-tun-udp-wire-fallback-{}.bin", rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    SharedTunWriter::new(file)
}

async fn build_engine(manager: UplinkManager) -> TunUdpEngine {
    TunUdpEngine::new(
        test_tun_writer(),
        TunRouting::new(UplinkRegistry::from_single_manager(manager), None, None, false),
        128,
        // No carrier cap: these tests exercise other limits.
        0,
        Duration::from_secs(60),
        false,
        true,
        false,
        Vec::new().into(),
        false,
    )
}

fn flow_key(client_port: u16) -> UdpFlowKey {
    UdpFlowKey {
        version: IpVersion::V4,
        local_ip: std::net::IpAddr::V4(CLIENT_IP),
        local_port: client_port,
        remote_ip: std::net::IpAddr::V4(REMOTE_IP),
        remote_port: REMOTE_PORT,
    }
}

async fn send_client_datagram(engine: &TunUdpEngine, client_port: u16, payload: &[u8]) {
    let bytes =
        crate::udp::build_ipv4_udp_packet(CLIENT_IP, REMOTE_IP, client_port, REMOTE_PORT, payload)
            .unwrap();
    let parsed = crate::udp::parse_udp_packet(&bytes).unwrap();
    engine.handle_packet(parsed).await.unwrap();
}

/// The flow's `(id, uplink_index)`, or `None` if it is not in the table.
async fn flow_state(engine: &TunUdpEngine, key: &UdpFlowKey) -> Option<(u64, usize)> {
    let handle = engine.inner.flows.read().await.get(key).map(Arc::clone)?;
    let guard = handle.lock().await;
    Some((guard.id, guard.uplink_index))
}

/// Wait until the flow has bound to an uplink (left the `usize::MAX`
/// "connecting" placeholder), or panic if it never does.
async fn wait_until_bound(engine: &TunUdpEngine, key: &UdpFlowKey) {
    for _ in 0..600 {
        if let Some((_, index)) = flow_state(engine, key).await
            && index != usize::MAX
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the flow never bound to an uplink");
}

/// Wait until the flow is gone from the table (a dial that could not reach
/// any wire tears the flow down), or panic if it is still there.
async fn wait_until_torn_down(engine: &TunUdpEngine, key: &UdpFlowKey) {
    for _ in 0..600 {
        if flow_state(engine, key).await.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the flow was never torn down");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tun_udp_skips_a_wire_with_no_udp_path_instead_of_dialing_and_failing_it() {
    let live = LiveUdpUpstream::start().await;
    let manager = build_manager(live.url(), true).await;
    let engine = build_engine(manager.clone()).await;

    let key = flow_key(50100);
    send_client_datagram(&engine, 50100, b"hello").await;
    wait_until_bound(&engine, &key).await;

    // The flow must have reached wire 2's live upstream — proof the dead
    // primary and the UDP-less fallback did not sink the whole uplink.
    live.expect_accept().await;
    assert_eq!(live.accept_count(), 1);

    // The load-bearing assertion: `active_wire` must have advanced exactly
    // once (0 -> 1, off wire 0's real failure) and no further. A second
    // advance (1 -> 2) can only happen if wire 1's absent UDP path was
    // recorded as a *failure* rather than skipped — see the module doc.
    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        1,
        "wire 1 (no UDP path configured) must not have recorded an outcome; \
         active_wire must have advanced only once, off wire 0's real failure",
    );
}

/// Gate-off counterpart: `dial_over_wires` only ever tries wire 0 when
/// `tun_wire_dial` is off, so the dead primary must fail the whole dial —
/// exactly as it did before this feature existed. Without this test, the
/// claim that a gate-off node never touches a fallback wire on the UDP plane
/// rested only on the gate-on test above still passing.
#[tokio::test]
async fn tun_udp_gate_off_never_tries_a_fallback_wire() {
    let live = LiveUdpUpstream::start().await;
    let manager = build_manager(live.url(), false).await;
    let engine = build_engine(manager.clone()).await;

    let key = flow_key(50200);
    send_client_datagram(&engine, 50200, b"hello").await;
    wait_until_torn_down(&engine, &key).await;

    assert_eq!(
        live.accept_count(),
        0,
        "gate-off must never dial a fallback wire, even on a dead primary"
    );
    // `record_wire_outcome` is a no-op with the gate off (see
    // `dial_over_wires`), so `active_wire` must never have moved.
    assert_eq!(manager.active_wire(0, TransportKind::Udp), 0);
}

// ---------------------------------------------------------------------------
// Review finding 2: a gate-off node must still dial wire 0 through
// `acquire_udp_on_wire` when wire 0 itself has no UDP path — never
// short-circuit to `NotApplicable`, which belongs only to wires the gate is
// walking past. Fixture: a TCP-only primary with a UDP-carrying fallback,
// the documented shape `supports_udp_any()` (selection.rs) admits to the UDP
// candidate set.
// ---------------------------------------------------------------------------

/// Wire 0 (primary) has no UDP path at all; wire 1 (fallback) does. With the
/// gate off this uplink must still show up as a UDP candidate
/// (`supports_udp_any()`), and its dial must stop at wire 0.
fn tcp_only_primary_with_udp_fallback(wire1_udp_url: Url) -> UplinkConfig {
    UplinkConfig {
        name: "primary".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![ss_fallback(Some(wire1_udp_url))],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

async fn build_tcp_only_primary_manager(wire1_udp_url: Url, tun_wire_dial: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![tcp_only_primary_with_udp_fallback(wire1_udp_url)],
        test_probe_config(),
        LoadBalancingConfig {
            tun_wire_dial,
            ..test_load_balancing_config()
        },
    )
    .unwrap()
}

/// Teeth for finding 2. Before the fix, a gate-off dial of this uplink hit
/// `!spec.supports_udp()` on wire 0 unconditionally and returned
/// `NotApplicable` — `dial_over_wires` then exhausted `order = [0]` with no
/// recorded error and surfaced its own `"no wires configured"` text instead
/// of wire 0's real, specific failure. That text becomes a production metric
/// label (`report_udp_runtime_failure` -> `normalize_other_runtime_failure_detail`),
/// so the regression is a silent label swap, not a crash — this test pins the
/// exact text that must survive it.
#[tokio::test]
async fn tun_udp_gate_off_dials_wire_0_even_when_it_has_no_udp_path() {
    let live = LiveUdpUpstream::start().await;
    let manager = build_tcp_only_primary_manager(live.url(), false).await;
    let engine = build_engine(manager.clone()).await;

    let key = flow_key(50400);
    send_client_datagram(&engine, 50400, b"hello").await;
    wait_until_torn_down(&engine, &key).await;

    assert_eq!(
        live.accept_count(),
        0,
        "gate-off must never dial the fallback wire, even though it is the \
         only wire with a UDP path",
    );

    // The load-bearing assertion: wire 0's own `acquire_udp_on_wire` failure
    // must have reached `report_runtime_failure` and landed in the uplink's
    // `last_error`. A `NotApplicable` short-circuit would instead leave
    // `dial_over_wires`'s generic "no wires configured" text here — a
    // different label, on a counter that never ticked.
    let snapshot = manager.snapshot().await;
    let error = snapshot.uplinks[0]
        .last_error
        .as_deref()
        .expect("wire 0's dial attempt must have recorded a runtime failure");
    assert!(
        error.contains("no udp dial URL configured for uplink primary wire 0"),
        "wire 0 must have reached `acquire_udp_on_wire` and failed with its own \
         error text, not dial_over_wires's generic fallback: got {error:?}",
    );
}

// ---------------------------------------------------------------------------
// Review finding 3 (and its finding-1 gate-off counterpart): the soft-switch
// redial (`TunUdpEngine::migrate_udp_flow`) must follow the *target*
// uplink's own active wire when the gate is on, and must stay pinned to wire
// 0 regardless of that state when the gate is off.
//
// Fixture: a two-uplink `active_passive` + global + `shared_resume` cluster,
// the shape an automatic failover migrates a live flow under. "a" is a
// plain single-wire uplink the flow starts on. "b" — the failover target —
// has a dead wire 0 and a live wire 1, so its `active_wire` can be primed to
// 1 independently of "a" and independently of the failover itself.
//
// Priming uses `record_wire_outcome` directly — the same public method
// `dial_over_wires` calls internally to record an outcome — rather than
// driving a real dial cascade against "b": it is the state machine's own
// API, not a private test hook, and it sidesteps
// `set_active_uplink_by_name`'s `reset_all_uplink_statuses()`, which would
// erase exactly the state being primed (see `candidates.rs:1240` and the
// task report's account of why that call is unusable here). The failover
// itself is driven the same way `force_failover_to_second_uplink` drives it
// for TCP (`crate::tcp::engine::tests::migrate`): `report_runtime_failure`
// plus a candidate query, never `set_active_uplink_by_name`, so "b"'s primed
// active wire survives to the moment the redial reads it.
// ---------------------------------------------------------------------------

async fn two_uplink_cluster_manager(
    a_live_url: Url,
    b_wire1_live_url: Url,
    tun_wire_dial: bool,
) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![
            single_wire_uplink("a", a_live_url),
            two_wire_uplink("b", dead_url(), b_wire1_live_url),
        ],
        test_probe_config(),
        LoadBalancingConfig {
            mode: outline_uplink::LoadBalancingMode::ActivePassive,
            routing_scope: outline_uplink::RoutingScope::Global,
            shared_resume: true,
            tun_wire_dial,
            ..test_load_balancing_config()
        },
    )
    .unwrap()
}

fn single_wire_uplink(name: &str, udp_ws_url: Url) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(udp_ws_url),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

/// Wire 0 = dead. Wire 1 = live. Used for "b", the failover target, so its
/// `active_wire` can be primed to 1 and its dead wire 0 stays a real,
/// distinguishable trap for a gate-off redial that ignores the prime.
fn two_wire_uplink(name: &str, wire0_dead: Url, wire1_live: Url) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(wire0_dead),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![ss_fallback(Some(wire1_live))],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

/// Drive an automatic runtime-failure failover off uplink `a` (index 0), the
/// same way probe/runtime failure does in production — never through
/// `set_active_uplink_by_name`, which would reset the state this suite
/// primes. Asserts the move happened, mirroring
/// `force_failover_to_second_uplink` in the TCP migrate suite.
async fn force_udp_failover_to_uplink_b(manager: &UplinkManager) {
    manager
        .report_runtime_failure(0, TransportKind::Udp, &anyhow::anyhow!("carrier died"))
        .await;
    let _ = manager.udp_candidates(None).await;
    assert_eq!(
        manager.active_uplinks_snapshot().udp_for(true),
        Some(1),
        "the failover must have repointed the group to uplink b",
    );
}

/// Wait until the flow reports `uplink_index == target`, or panic. Local
/// variant of `crate::udp::tests::soft_switch::wait_for_migration` — that
/// helper also checks the flow id survived, which these tests don't track.
async fn wait_for_uplink_index(engine: &TunUdpEngine, key: &UdpFlowKey, target: usize) {
    for _ in 0..600 {
        if let Some((_, index)) = flow_state(engine, key).await
            && index == target
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the flow never reached uplink index {target}");
}

/// Gate on: the redial must follow "b"'s own active wire (primed to 1), not
/// always wire 0. Before Task 7's soft-switch site existed this was a
/// wire-0-only redial by construction; this is the direct test that gap
/// asked for but never got (see the task report's "no dedicated test for the
/// soft-switch redial site" deviation).
#[tokio::test]
async fn tun_udp_soft_switch_redial_follows_the_targets_active_wire() {
    let live_a = LiveUdpUpstream::start().await;
    let live_b1 = LiveUdpUpstream::start().await;
    let manager = two_uplink_cluster_manager(live_a.url(), live_b1.url(), true).await;

    // Establish "a" as the group's starting active uplink. This runs before
    // the prime below, not after: `set_active_uplink_by_name` resets every
    // uplink's `active_wire` to 0 (`reset_all_uplink_statuses`), which would
    // erase the very state this fixture is about to prime on "b".
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();

    manager.record_wire_outcome(1, TransportKind::Udp, 0, false, 2);
    assert_eq!(
        manager.active_wire(1, TransportKind::Udp),
        1,
        "fixture setup: b's active wire must be primed before the flow starts",
    );

    let engine = build_engine(manager.clone()).await;
    let key = flow_key(50500);
    send_client_datagram(&engine, 50500, b"hello").await;
    wait_until_bound(&engine, &key).await;
    live_a.expect_accept().await;
    assert_eq!(live_a.accept_count(), 1, "the flow must start on uplink a");

    force_udp_failover_to_uplink_b(&manager).await;
    wait_for_uplink_index(&engine, &key, 1).await;

    // The load-bearing assertion: the redial reached b's live wire 1, not
    // its dead wire 0.
    live_b1.expect_accept().await;
    assert_eq!(
        live_b1.accept_count(),
        1,
        "the soft-switch redial must have followed b's active wire (1)",
    );
}

/// Gate off: the redial must stay pinned to wire 0 even though "b"'s active
/// wire has genuinely moved to 1 — an ungated read (the bug finding 1
/// describes) would dial wire 1's live upstream instead and the flow would
/// migrate; the fix must instead hit wire 0's dead upstream and tear the
/// flow down, exactly like a fleet binary that predates wire support.
#[tokio::test]
async fn tun_udp_soft_switch_redial_gate_off_uses_wire_0_regardless_of_active_wire() {
    let live_a = LiveUdpUpstream::start().await;
    let live_b1 = LiveUdpUpstream::start().await;
    let manager = two_uplink_cluster_manager(live_a.url(), live_b1.url(), false).await;

    // Establish "a" as the group's starting active uplink. This runs before
    // the prime below, not after: `set_active_uplink_by_name` resets every
    // uplink's `active_wire` to 0 (`reset_all_uplink_statuses`), which would
    // erase the very state this fixture is about to prime on "b".
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();

    manager.record_wire_outcome(1, TransportKind::Udp, 0, false, 2);
    assert_eq!(
        manager.active_wire(1, TransportKind::Udp),
        1,
        "fixture setup: b's active wire must be primed before the flow starts",
    );

    let engine = build_engine(manager.clone()).await;
    let key = flow_key(50600);
    send_client_datagram(&engine, 50600, b"hello").await;
    wait_until_bound(&engine, &key).await;
    live_a.expect_accept().await;

    force_udp_failover_to_uplink_b(&manager).await;

    // The load-bearing assertion: the redial must have hit b's dead wire 0
    // and torn the flow down — b's live wire 1 (the primed active wire) must
    // never have been dialed.
    wait_until_torn_down(&engine, &key).await;
    assert_eq!(
        live_b1.accept_count(),
        0,
        "gate-off must never touch a non-zero wire, even one the active-wire \
         state machine has genuinely moved to",
    );
}
