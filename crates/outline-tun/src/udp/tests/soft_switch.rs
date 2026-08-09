//! A live TUN UDP flow surviving a strict-active-uplink repoint.
//!
//! # What is being preserved
//!
//! Not bytes. A parked UDP session keeps no back-buffer — the kernel receive
//! buffer fills and overflow drops, because UDP is loss-tolerant by design
//! (`bins/outline-ss-rust/src/server/resumption/parked.rs`). What a resume hit
//! preserves is the **session**: the server re-points the parked NAT entries at
//! the new carrier, so the exit keeps the same source port and the peer's NAT
//! binding survives. These tests therefore assert on *which Session ID reaches
//! the server and whether it hits*, not on a byte stream.
//!
//! # The mock's park model
//!
//! The mock does not treat "an id was once issued" as resumable. It parks an id
//! only once the connection that was issued it has **closed**, exactly as the
//! server does (`docs/SESSION-RESUMPTION.md` § Park sequence). Without that, a
//! redial arriving before the old carrier had gone would still be scored a hit
//! and the tests would pass against a client that never retired anything —
//! which is precisely the bug the retire-before-redial ordering exists to stop.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use parking_lot::Mutex as SyncMutex;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
};
use url::Url;

use outline_uplink::UplinkRegistry;

use crate::tcp::engine::tests::build_test_cluster_udp_manager;
use crate::udp::{TunUdpEngine, UdpFlowKey};
use crate::wire::IpVersion;
use crate::{SharedTunWriter, TunRouting};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const REMOTE_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// Mock upstream with a park model
// ---------------------------------------------------------------------------

/// What one WebSocket dial presented and what the server made of it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedDial {
    /// `X-Outline-Resume` value the client sent, if any.
    presented: Option<String>,
    /// Whether that id named a session this server currently holds parked.
    hit: bool,
    /// `X-Outline-Session` value this dial was issued.
    issued: String,
}

#[derive(Default)]
struct UpstreamState {
    next_id: u64,
    /// Ids that were issued and whose connection has since closed — the only
    /// ones a resume can hit. An id whose connection is still live is NOT here,
    /// which is what makes a redial-before-retire score a miss.
    parked: HashSet<String>,
    /// Live connections by the id they were issued, so closing one can park it.
    live: HashMap<String, ()>,
    dials: Vec<ObservedDial>,
}

struct ResumableUdpUpstream {
    url: Url,
    state: Arc<SyncMutex<UpstreamState>>,
    dialled_tx: mpsc::UnboundedSender<()>,
    dialled_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<()>>,
}

impl ResumableUdpUpstream {
    async fn start() -> Arc<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialled_tx, dialled_rx) = mpsc::unbounded_channel();
        let upstream = Arc::new(Self {
            url: Url::parse(&format!("ws://{addr}/udp")).unwrap(),
            state: Arc::new(SyncMutex::new(UpstreamState::default())),
            dialled_tx,
            dialled_rx: tokio::sync::Mutex::new(dialled_rx),
        });
        let state = Arc::clone(&upstream.state);
        let notify = upstream.dialled_tx.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&state);
                let notify = notify.clone();
                tokio::spawn(async move {
                    let issued_slot: Arc<SyncMutex<Option<String>>> =
                        Arc::new(SyncMutex::new(None));
                    let issued_for_handshake = Arc::clone(&issued_slot);
                    let state_for_handshake = Arc::clone(&state);
                    #[allow(clippy::result_large_err)]
                    let callback =
                        move |request: &HandshakeRequest,
                              mut response: HandshakeResponse|
                              -> Result<HandshakeResponse, ErrorResponse> {
                            let presented = request
                                .headers()
                                .get("x-outline-resume")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            let mut guard = state_for_handshake.lock();
                            guard.next_id += 1;
                            let issued = format!("{:032x}", guard.next_id);
                            // The park model: a hit requires the presented id to
                            // have been *parked*, which only happens once its own
                            // connection closed.
                            let hit = presented
                                .as_ref()
                                .is_some_and(|id| guard.parked.remove(id.as_str()));
                            guard.live.insert(issued.clone(), ());
                            guard.dials.push(ObservedDial {
                                presented,
                                hit,
                                issued: issued.clone(),
                            });
                            drop(guard);
                            *issued_for_handshake.lock() = Some(issued.clone());
                            response
                                .headers_mut()
                                .insert("x-outline-session", issued.parse().unwrap());
                            Ok(response)
                        };
                    let Ok(ws) = accept_hdr_async(stream, callback).await else {
                        return;
                    };
                    let _ = notify.send(());
                    let (_sink, mut read) = ws.split();
                    // Drain until the client goes away; the datagram contents
                    // are irrelevant here — this suite is about which id the
                    // dial presents and whether the park is there to hit.
                    while read.next().await.transpose().ok().flatten().is_some() {}
                    // The connection is gone: park whatever it was issued, so a
                    // later redial presenting that id can hit.
                    if let Some(issued) = issued_slot.lock().take() {
                        let mut guard = state.lock();
                        guard.live.remove(&issued);
                        guard.parked.insert(issued);
                    }
                });
            }
        });
        upstream
    }

    fn url(&self) -> Url {
        self.url.clone()
    }

    fn dials(&self) -> Vec<ObservedDial> {
        self.state.lock().dials.clone()
    }

    /// Wait until `count` dials have completed their handshake.
    async fn wait_for_dials(&self, count: usize) {
        let mut rx = self.dialled_rx.lock().await;
        while self.state.lock().dials.len() < count {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for dial #{count}"))
                .expect("upstream accept loop ended");
        }
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn test_tun_writer() -> SharedTunWriter {
    let path = std::env::temp_dir()
        .join(format!("outline-tun-udp-softswitch-{}.bin", rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    SharedTunWriter::new(file)
}

async fn build_engine(manager: outline_uplink::UplinkManager) -> TunUdpEngine {
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
        local_ip: IpAddr::V4(CLIENT_IP),
        local_port: client_port,
        remote_ip: IpAddr::V4(REMOTE_IP),
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

/// Wait until the flow reports `uplink_index == target` without ever leaving
/// the table. Returns `false` if it was torn down instead — the two outcomes
/// this suite has to tell apart.
async fn wait_for_migration(engine: &TunUdpEngine, key: &UdpFlowKey, target: usize) -> bool {
    for _ in 0..600 {
        match flow_state(engine, key).await {
            Some((_, index)) if index == target => return true,
            Some(_) => {},
            None => return false,
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

async fn wait_until_bound(engine: &TunUdpEngine, key: &UdpFlowKey) -> (u64, usize) {
    for _ in 0..600 {
        if let Some((id, index)) = flow_state(engine, key).await
            && index != usize::MAX
        {
            return (id, index);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the flow never bound to an uplink");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// An operator soft switch must carry a live TUN UDP flow over to the new
/// active uplink. Before this, the flow was torn down under `global_switch` —
/// the UDP twin of the TCP RST, and just as blind to the switch's intent.
///
/// The assertion that matters is not merely "the flow moved": it is that the
/// redial presented **this flow's own** id and that the server scored it a
/// **hit**, which under the mock's park model can only happen if the client
/// closed the old carrier before dialling.
#[tokio::test]
async fn an_operator_soft_switch_migrates_a_live_udp_flow() {
    let upstream = ResumableUdpUpstream::start().await;
    let manager =
        build_test_cluster_udp_manager(&[("a", upstream.url()), ("b", upstream.url())]).await;
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();
    let engine = build_engine(manager.clone()).await;

    let key = flow_key(42001);
    send_client_datagram(&engine, 42001, b"hello").await;
    upstream.wait_for_dials(1).await;
    let (flow_id, index) = wait_until_bound(&engine, &key).await;
    assert_eq!(index, 0, "the flow was born on \"a\"");

    let (_index, applied_soft) = manager.set_active_uplink_by_name("b", None, true).await.unwrap();
    assert!(applied_soft, "a shared_resume group must honour the soft bit");

    assert!(
        wait_for_migration(&engine, &key, 1).await,
        "a soft switch must carry the UDP flow to the new active uplink, not tear it down",
    );
    assert_eq!(
        flow_state(&engine, &key).await.map(|(id, _)| id),
        Some(flow_id),
        "the flow record survived: this is a migration, not a teardown and a fresh flow",
    );

    upstream.wait_for_dials(2).await;
    let dials = upstream.dials();
    assert_eq!(dials[0].presented, None, "the first dial resumes nothing");
    assert_eq!(
        dials[1].presented.as_deref(),
        Some(dials[0].issued.as_str()),
        "the redial must present the id the server issued to THIS flow",
    );
    assert!(
        dials[1].hit,
        "the old carrier must be retired before the redial, or the server has \
         nothing parked and the session's source port is lost",
    );
}

/// Negative control for the park model itself.
///
/// If the mock scored a hit on any id it had ever issued, the test above would
/// pass against a client that dialled first and closed afterwards — the very
/// ordering bug it exists to catch. Here the same id is presented while its
/// connection is still live, and the server must score it a miss.
#[tokio::test]
async fn a_resume_presented_against_a_live_session_is_a_miss() {
    let upstream = ResumableUdpUpstream::start().await;
    let manager =
        build_test_cluster_udp_manager(&[("a", upstream.url()), ("b", upstream.url())]).await;
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();
    let engine = build_engine(manager.clone()).await;

    // One live flow, holding its carrier open.
    send_client_datagram(&engine, 42002, b"hello").await;
    upstream.wait_for_dials(1).await;
    wait_until_bound(&engine, &flow_key(42002)).await;
    let issued = upstream.dials()[0].issued.clone();

    // Present that id by hand while its connection is still up.
    let mut request =
        tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            upstream.url().as_str(),
        )
        .unwrap();
    request
        .headers_mut()
        .insert("x-outline-resume", issued.parse().unwrap());
    let (_ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();
    upstream.wait_for_dials(2).await;

    let dials = upstream.dials();
    assert_eq!(dials[1].presented.as_deref(), Some(issued.as_str()));
    assert!(
        !dials[1].hit,
        "an id whose session is still live is not parked, so it must miss — \
         this is what makes the hit in the soft-switch test meaningful",
    );
}

/// A hard switch still tears the flow down. Strict `active_passive` means one
/// active uplink at a time, and an operator draining a node did not ask for the
/// sessions to be relayed back to it through the mesh.
#[tokio::test]
async fn a_hard_switch_still_tears_the_udp_flow_down() {
    let upstream = ResumableUdpUpstream::start().await;
    let manager =
        build_test_cluster_udp_manager(&[("a", upstream.url()), ("b", upstream.url())]).await;
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();
    let engine = build_engine(manager.clone()).await;

    let key = flow_key(42003);
    send_client_datagram(&engine, 42003, b"hello").await;
    upstream.wait_for_dials(1).await;
    wait_until_bound(&engine, &key).await;

    manager.set_active_uplink_by_name("b", None, false).await.unwrap();
    // The verdict is consulted when the flow next has something to do.
    send_client_datagram(&engine, 42003, b"more").await;

    for _ in 0..600 {
        if flow_state(&engine, &key).await.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("a hard switch must remove the flow from the table");
}

/// A **fresh** flow must never present another flow's Session ID.
///
/// TUN dials one carrier per flow, but the SS-UDP resume id used to live in a
/// process-wide cache keyed `<scope>#udp` — one slot for every flow in the
/// group. So a new flow presented whatever the last closed flow had parked, and
/// a hit there is not a missed resume but a hit on **someone else's session**:
/// the server re-points that flow's NAT entries at this carrier, and
/// `build_client_response_packet` then re-sources its peer's datagrams from
/// *this* flow's remote — one flow's traffic delivered to the client wearing
/// another flow's address.
#[tokio::test]
async fn a_fresh_udp_flow_never_presents_another_flows_session_id() {
    let upstream = ResumableUdpUpstream::start().await;
    let manager =
        build_test_cluster_udp_manager(&[("a", upstream.url()), ("b", upstream.url())]).await;
    manager.set_active_uplink_by_name("a", None, false).await.unwrap();
    let engine = build_engine(manager.clone()).await;

    // Flow one, then torn down — so its id is parked and available to steal.
    let first = flow_key(42004);
    send_client_datagram(&engine, 42004, b"one").await;
    upstream.wait_for_dials(1).await;
    let (first_id, _) = wait_until_bound(&engine, &first).await;
    engine.close_flow_if_current(&first, first_id, "read_error").await;

    // A different 5-tuple: a genuinely new session.
    let second = flow_key(42005);
    send_client_datagram(&engine, 42005, b"two").await;
    upstream.wait_for_dials(2).await;
    wait_until_bound(&engine, &second).await;

    let dials = upstream.dials();
    assert_eq!(
        dials[1].presented, None,
        "a fresh flow has no id of its own and must present none — presenting \
         the previous flow's parked id splices it onto that flow's session",
    );
    assert!(!dials[1].hit);
}
