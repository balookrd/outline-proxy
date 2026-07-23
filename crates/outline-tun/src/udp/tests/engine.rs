//! Route-stability tests for the UDP engine under `[tun] route_by_sni`.
//!
//! SNI-routing steers a new flow by the domain sniffed from its first
//! datagram, but only a QUIC *Initial* carries a ClientHello. A flow torn down
//! while the client's QUIC connection is still live (idle eviction, carrier
//! read error, `max_flows` eviction) is recreated by a Short Header datagram
//! with nothing to sniff — the route must not silently revert to the literal
//! IP decision, which would move a live connection to a different exit (or
//! drop it) mid-session.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use outline_routing::{RouteRule, RouteTarget, RoutingTable, RoutingTableConfig};
use outline_uplink::UplinkRegistry;
use shadowsocks_crypto::{CipherKind, decrypt_udp_packet};
use socks5_proto::TargetAddr;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::quic_sniff::test_vectors::{build_initial, client_hello};
use crate::tcp::engine::tests::build_test_manager_with_urls;
use crate::udp::{TunUdpEngine, UdpFlowKey};
use crate::wire::IpVersion;
use crate::{SharedTunWriter, TunRouting};

const QUIC_V1: u32 = 0x0000_0001;
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const REMOTE_PORT: u16 = 443;
/// The domain the routing table sends through the tunnel group. Every other
/// destination — including the literal `REMOTE_IP` — hits the table's `Drop`
/// default, so "routed by SNI" and "routed by IP" are trivially separable:
/// the upstream sees the datagram only in the former case.
const TUNNELLED_SNI: &str = "video.example.com";
const GROUP: &str = "test";

/// A WS upstream that decrypts every inbound SS-UDP frame and reports the
/// encoded destination + payload. Unlike the single-shot upstream in
/// `tests/sniff.rs` this one accepts repeatedly: a torn-down flow drops its
/// carrier, so the recreated flow dials a fresh WebSocket.
struct TestUdpUpstream {
    url: Url,
    decoded_rx: Mutex<mpsc::UnboundedReceiver<(TargetAddr, Vec<u8>)>>,
}

impl TestUdpUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(ws) = accept_async(stream).await else {
                        return;
                    };
                    let (_sink, mut read) = ws.split();
                    let cipher = CipherKind::Chacha20IetfPoly1305;
                    let master_key = cipher.derive_master_key("Secret0").unwrap();
                    while let Some(Ok(message)) = read.next().await {
                        if let Message::Binary(bytes) = message
                            && let Ok(plain) = decrypt_udp_packet(cipher, &master_key, &bytes[..])
                            && let Ok((target, consumed)) = TargetAddr::from_wire_bytes(&plain)
                        {
                            let payload = plain[consumed..].to_vec();
                            let _ = tx.send((target, payload));
                        }
                    }
                });
            }
        });
        Self {
            url: Url::parse(&format!("ws://{addr}/udp")).unwrap(),
            decoded_rx: Mutex::new(rx),
        }
    }

    async fn expect_decoded(&self) -> (TargetAddr, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            self.decoded_rx.lock().await.recv().await
        })
        .await
        .expect("timed out waiting for upstream UDP datagram")
        .expect("upstream channel closed")
    }

    /// Assert nothing reaches the upstream within `window` — the observable
    /// signature of a datagram that was routed away from the tunnel (here: the
    /// table's `Drop` default).
    async fn expect_silence(&self, window: Duration) {
        let received =
            tokio::time::timeout(window, async { self.decoded_rx.lock().await.recv().await }).await;
        if let Ok(Some((target, _))) = received {
            panic!("expected no upstream datagram, got one framed for {target}");
        }
    }
}

fn test_tun_writer() -> SharedTunWriter {
    let path =
        std::env::temp_dir().join(format!("outline-tun-udp-route-{}.bin", rand::random::<u64>()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    SharedTunWriter::new(file)
}

/// One domain rule (`TUNNELLED_SNI` → the tunnel group) over a `Drop` default:
/// the destination IP matches no CIDR rule, so an IP-resolved flow is dropped
/// while an SNI-resolved one is tunnelled.
async fn domain_rule_table() -> Arc<RoutingTable> {
    Arc::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: vec![RouteRule {
                inline_prefixes: Vec::new(),
                files: Vec::new(),
                inline_domains: vec![TUNNELLED_SNI.to_string()],
                domain_files: Vec::new(),
                file_poll: Duration::from_secs(60),
                target: RouteTarget::Group(GROUP.into()),
                fallback: None,
                invert: false,
            }],
            default_target: RouteTarget::Drop,
            default_fallback: None,
        })
        .await
        .unwrap(),
    )
}

async fn build_engine(upstream_url: Url, route_by_sni: bool) -> (TunUdpEngine, Arc<RoutingTable>) {
    let manager = build_test_manager_with_urls(None, Some(upstream_url)).await;
    let table = domain_rule_table().await;
    let routing = TunRouting::new(
        UplinkRegistry::from_single_manager(manager),
        Some(Arc::clone(&table)),
        None,
        false,
    );
    let engine = TunUdpEngine::new(
        test_tun_writer(),
        routing,
        128,
        Duration::from_secs(60),
        false,
        true,
        route_by_sni,
        Vec::new().into(),
        false,
    );
    (engine, table)
}

async fn send_client_datagram(engine: &TunUdpEngine, client_port: u16, payload: &[u8]) {
    let bytes =
        crate::udp::build_ipv4_udp_packet(CLIENT_IP, REMOTE_IP, client_port, REMOTE_PORT, payload)
            .unwrap();
    let parsed = crate::udp::parse_udp_packet(&bytes).unwrap();
    engine.handle_packet(parsed).await.unwrap();
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

/// Tear the flow down through the engine's own teardown path — the one a
/// carrier read error, an idle eviction and a `max_flows` eviction all end in.
/// The client's QUIC connection is untouched and keeps sending on the same
/// 5-tuple.
async fn tear_down_flow(engine: &TunUdpEngine, client_port: u16) {
    let key = flow_key(client_port);
    let flow_id = engine
        .inner
        .flows
        .read()
        .await
        .get(&key)
        .expect("flow must exist before teardown")
        .lock()
        .await
        .id;
    engine.close_flow_if_current(&key, flow_id, "read_error").await;
    assert!(
        !engine.inner.flows.read().await.contains_key(&key),
        "flow must be gone after teardown",
    );
}

fn quic_initial(sni: &str) -> Vec<u8> {
    let dcid = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    build_initial(QUIC_V1, &dcid, &client_hello(sni))
}

/// A QUIC 1-RTT (Short Header) packet — what a client sends once its handshake
/// is done. The header-form bit is clear, so there is no ClientHello to sniff.
fn quic_short_header() -> Vec<u8> {
    let mut packet = vec![0x40]; // short header, fixed bit set
    packet.extend_from_slice(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]); // DCID
    packet.extend_from_slice(&[0x00, 0x01]); // packet number
    packet.extend_from_slice(b"encrypted 1-rtt payload");
    packet
}

#[tokio::test]
async fn recreated_flow_keeps_sni_route_while_quic_connection_is_live() {
    let upstream = TestUdpUpstream::start().await;
    let (engine, _table) = build_engine(upstream.url.clone(), true).await;

    // The QUIC Initial pins the flow to the domain rule → tunnel group.
    send_client_datagram(&engine, 40100, &quic_initial(TUNNELLED_SNI)).await;
    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::Domain(TUNNELLED_SNI.to_string(), REMOTE_PORT));

    // The flow dies underneath a still-live QUIC connection.
    tear_down_flow(&engine, 40100).await;

    // The client's next datagram is a Short Header: nothing to sniff. Routing
    // it by IP would hit the `Drop` default and silently kill the connection.
    send_client_datagram(&engine, 40100, &quic_short_header()).await;
    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(
        target,
        TargetAddr::Domain(TUNNELLED_SNI.to_string(), REMOTE_PORT),
        "a flow recreated mid-connection must keep the SNI route, not fall back to IP",
    );
}

#[tokio::test]
async fn routing_rule_reload_drops_the_remembered_sni_route() {
    let upstream = TestUdpUpstream::start().await;
    let (engine, table) = build_engine(upstream.url.clone(), true).await;

    send_client_datagram(&engine, 40200, &quic_initial(TUNNELLED_SNI)).await;
    let (target, _) = upstream.expect_decoded().await;
    assert_eq!(target, TargetAddr::Domain(TUNNELLED_SNI.to_string(), REMOTE_PORT));

    tear_down_flow(&engine, 40200).await;
    // A rule reload bumps the table version — what the watcher does after a
    // `domain_file` change. The memory predates the current rules, so it must
    // not steer the recreated flow; resolution falls back to the live table
    // (here: the `Drop` default for the literal IP).
    table.version.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

    send_client_datagram(&engine, 40200, &quic_short_header()).await;
    upstream.expect_silence(Duration::from_millis(750)).await;
}

#[tokio::test]
async fn sni_routing_disabled_keeps_ip_resolution_and_allocates_no_memory() {
    let upstream = TestUdpUpstream::start().await;
    let (engine, _table) = build_engine(upstream.url.clone(), false).await;

    assert!(
        engine.inner.sni_route_cache.is_none(),
        "route_by_sni off must not allocate the sniffed-SNI memory",
    );

    // With SNI-routing off the route comes from the literal IP even for a
    // sniffable Initial — the `Drop` default stands, unchanged by this fix.
    send_client_datagram(&engine, 40300, &quic_initial(TUNNELLED_SNI)).await;
    upstream.expect_silence(Duration::from_millis(750)).await;
}
