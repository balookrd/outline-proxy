//! Direct-routed (`via = "direct"`) UDP flows.
//!
//! Two invariants live here. The uplink send must run on the flow's own task,
//! never inline on the shared TUN read-loop: a direct flow talks to a plain
//! socket, and a full `SO_SNDBUF` / a congested qdisc on a slow egress parks
//! `send_to` for as long as the kernel needs — which, done inline, parks every
//! other flow's packets with it. And the downlink reader must reuse its
//! receive buffer across datagrams without letting one datagram's bytes bleed
//! into the next.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig, SharedRoutingTable};
use outline_uplink::UplinkRegistry;
use tokio::net::UdpSocket;

use crate::tcp::engine::tests::build_test_manager_with_urls;
use crate::udp::types::UDP_OUTBOUND_QUEUE_CAP;
use crate::udp::{TunUdpEngine, UdpFlowKey};
use crate::wire::{IPV6_HEADER_LEN, IpVersion};
use crate::{SharedTunWriter, TunRouting};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_PORT: u16 = 41000;

/// Reads back the IP packets the engine wrote into the TUN device, one at a
/// time. The writer is handed a plain file, so the capture is just the file.
struct TunCapture {
    path: PathBuf,
    offset: usize,
}

impl TunCapture {
    fn new() -> (SharedTunWriter, Self) {
        let path = std::env::temp_dir()
            .join(format!("outline-tun-udp-direct-{}.bin", rand::random::<u64>()));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (SharedTunWriter::new(file), Self { path, offset: 0 })
    }

    async fn next_packet(&mut self) -> Vec<u8> {
        for _ in 0..250 {
            let data = tokio::fs::read(&self.path).await.unwrap_or_default();
            if let Some(remaining) = data.get(self.offset..)
                && let Some(len) = packet_length(remaining)
                && remaining.len() >= len
            {
                self.offset += len;
                return remaining[..len].to_vec();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for a captured TUN packet");
    }
}

impl Drop for TunCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn packet_length(data: &[u8]) -> Option<usize> {
    match data.first().map(|byte| byte >> 4)? {
        4 if data.len() >= 4 => Some(usize::from(u16::from_be_bytes([data[2], data[3]]))),
        6 if data.len() >= 6 => {
            Some(IPV6_HEADER_LEN + usize::from(u16::from_be_bytes([data[4], data[5]])))
        },
        _ => None,
    }
}

/// An engine whose routing table sends everything out `via = "direct"`.
async fn direct_engine(writer: SharedTunWriter) -> TunUdpEngine {
    direct_engine_with_ipsec(
        writer,
        false,
        Duration::from_secs(60),
        crate::routing::IPSEC_NAT_T_PORT,
        Duration::from_secs(20),
        Duration::from_secs(3600),
    )
    .await
}

async fn direct_engine_with_ipsec(
    writer: SharedTunWriter,
    ipsec_bypass: bool,
    idle_timeout: Duration,
    ipsec_nat_t_port: u16,
    ipsec_nat_keepalive_interval: Duration,
    ipsec_idle_timeout: Duration,
) -> TunUdpEngine {
    let manager = build_test_manager_with_urls(None, None).await;
    let table = SharedRoutingTable::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: Vec::new(),
            default_target: RouteTarget::Direct,
            default_fallback: None,
        })
        .await
        .unwrap(),
    );
    let routing = TunRouting::new(
        UplinkRegistry::from_single_manager(manager),
        Some(table),
        None,
        None,
        ipsec_bypass,
    );
    TunUdpEngine::new_with_ipsec_params_for_tests(
        writer,
        routing,
        128,
        // No carrier cap: these tests exercise other limits.
        0,
        idle_timeout,
        false,
        false,
        false,
        crate::empty_sniff_override(),
        crate::empty_sniff_override(),
        false,
        ipsec_nat_t_port,
        ipsec_nat_keepalive_interval,
        ipsec_idle_timeout,
    )
}

async fn send_client_datagram(engine: &TunUdpEngine, destination: SocketAddr, payload: &[u8]) {
    let IpAddr::V4(destination_ip) = destination.ip() else {
        panic!("test destinations are IPv4");
    };
    let bytes = crate::udp::build_ipv4_udp_packet(
        CLIENT_IP,
        destination_ip,
        CLIENT_PORT,
        destination.port(),
        payload,
    )
    .unwrap();
    let parsed = crate::udp::parse_udp_packet(&bytes).unwrap();
    engine.handle_packet(parsed).await.unwrap();
}

fn flow_key(destination: SocketAddr) -> UdpFlowKey {
    UdpFlowKey {
        version: IpVersion::V4,
        local_ip: IpAddr::V4(CLIENT_IP),
        local_port: CLIENT_PORT,
        remote_ip: destination.ip(),
        remote_port: destination.port(),
    }
}

/// The read-loop hands each datagram to the flow's bounded outbound queue and
/// returns; the flow's own sender task awaits the socket. Ordering within the
/// flow is preserved, and the queue is bounded so a stuck egress costs a
/// bounded amount of memory (and drops, which is connectionless-correct)
/// instead of stalling the read-loop.
#[tokio::test]
async fn direct_flow_sends_through_a_bounded_per_flow_queue() {
    let (writer, _capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();
    let engine = direct_engine(writer).await;

    let payloads: [&[u8]; 3] = [b"first", b"second-datagram", b"third-datagram-is-longest"];
    for payload in payloads {
        send_client_datagram(&engine, destination_addr, payload).await;
    }

    for expected in payloads {
        let mut buf = vec![0u8; 2048];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), destination.recv_from(&mut buf))
                .await
                .expect("timed out waiting for a direct datagram")
                .unwrap();
        assert_eq!(&buf[..len], expected, "direct datagrams must arrive in order, unmodified");
    }

    let flow = engine
        .inner
        .direct_flows
        .read()
        .await
        .get(&flow_key(destination_addr))
        .cloned()
        .expect("the direct flow must be registered");
    assert_eq!(
        flow.lock().await.outbound_tx.max_capacity(),
        UDP_OUTBOUND_QUEUE_CAP,
        "the direct outbound queue must be bounded, like the tunnelled one",
    );
}

/// An egress error belongs to the flow's sender task, not to the read-loop:
/// surfacing it inline made one unroutable destination look like a read-loop
/// failure (and, before the queue, cost the loop a `send_to` await per packet).
#[tokio::test]
async fn direct_send_failure_stays_off_the_read_loop() {
    let (writer, _capture) = TunCapture::new();
    let engine = direct_engine(writer).await;
    // Port 0 is not a sendable destination — the kernel rejects the send.
    let unroutable = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    let before = forward_error_count("direct_send_error");
    send_client_datagram(&engine, unroutable, b"goes nowhere").await;

    assert!(
        engine
            .inner
            .direct_flows
            .read()
            .await
            .contains_key(&flow_key(unroutable)),
        "the flow is created off the send result, exactly like the tunnelled path",
    );
    // The failure is not swallowed either — the sender task counts it.
    for _ in 0..100 {
        if forward_error_count("direct_send_error") > before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the sender task must count a failed direct send");
}

/// Current value of `outline_ws_tun_udp_forward_errors_total{reason="…"}` from
/// the rendered exposition. The registry is process-global, so tests compare a
/// delta rather than an absolute value.
fn forward_error_count(reason: &str) -> u64 {
    let rendered = outline_metrics::render_prometheus(&[]).expect("render metrics");
    let needle = format!("outline_ws_tun_udp_forward_errors_total{{reason=\"{reason}\"}} ");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&needle)?.trim().parse().ok())
        .unwrap_or(0)
}

/// The downlink reader keeps one receive buffer for its lifetime instead of
/// allocating 64 KiB per datagram. Reuse is only correct if the buffer is
/// cleared between datagrams: a shorter datagram following a longer one must
/// not inherit the tail of its predecessor.
#[tokio::test]
async fn direct_downlink_reuses_its_buffer_without_bleeding_between_datagrams() {
    let (writer, mut capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();
    let engine = direct_engine(writer).await;

    send_client_datagram(&engine, destination_addr, b"open the flow").await;
    let mut buf = vec![0u8; 2048];
    let (_, client_addr) =
        tokio::time::timeout(Duration::from_secs(5), destination.recv_from(&mut buf))
            .await
            .expect("timed out waiting for the opening datagram")
            .unwrap();

    // A long reply, then a much shorter one: a buffer that is reused without
    // being cleared would deliver the short reply with the long one's tail.
    let long: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
    let short = b"short".to_vec();
    for reply in [long.clone(), short.clone()] {
        destination.send_to(&reply, client_addr).await.unwrap();
    }

    for expected in [long, short] {
        let packet = capture.next_packet().await;
        let parsed = crate::udp::parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.destination_port, CLIENT_PORT);
        assert_eq!(
            parsed.payload, expected,
            "each downlink datagram must carry exactly its own bytes",
        );
    }
}

/// Process-global keepalive gauge (`outline_ws_tun_ipsec_nat_keepalive_flows_active`)
/// is shared across parallel test threads, so tests that spawn keepalive-emulating
/// flows serialize on this lock and wait for `AbortOnDrop` teardown before releasing it.
static IPSEC_KEEPALIVE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn ipsec_bypass_nat_t_port_emits_rfc3948_keepalive_on_idle() {
    let _serial = IPSEC_KEEPALIVE_TEST_LOCK.lock().await;
    let (writer, _capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();
    let engine = direct_engine_with_ipsec(
        writer,
        true,
        Duration::from_secs(60),
        destination_addr.port(),
        Duration::from_millis(50),
        Duration::from_secs(3600),
    )
    .await;

    send_client_datagram(&engine, destination_addr, b"ikev2-init").await;

    let mut buf = vec![0u8; 256];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .expect("timed out waiting for initial datagram")
        .unwrap();
    assert_eq!(&buf[..len], b"ikev2-init");

    let (ka_len, _) = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .expect("timed out waiting for RFC 3948 NAT-keepalive")
        .unwrap();
    assert_eq!(&buf[..ka_len], &[0xff], "RFC 3948 §2.3 NAT-keepalive must be 1 byte 0xff");
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn ipsec_bypass_disabled_or_other_port_does_not_emit_keepalive() {
    let (writer, _capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();

    // Case 1: ipsec_bypass = false even when port matches nat_t_port.
    let engine_disabled = direct_engine_with_ipsec(
        writer.clone(),
        false,
        Duration::from_secs(60),
        destination_addr.port(),
        Duration::from_millis(40),
        Duration::from_secs(3600),
    )
    .await;
    send_client_datagram(&engine_disabled, destination_addr, b"plain-udp").await;
    let mut buf = vec![0u8; 256];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"plain-udp");
    assert!(
        tokio::time::timeout(Duration::from_millis(120), destination.recv_from(&mut buf))
            .await
            .is_err(),
        "keepalive must not be emitted when ipsec_bypass is false",
    );

    // Case 2: ipsec_bypass = true, but destination port != nat_t_port.
    let other_dest = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let other_addr = other_dest.local_addr().unwrap();
    let engine_other_port = direct_engine_with_ipsec(
        writer,
        true,
        Duration::from_secs(60),
        destination_addr.port(),
        Duration::from_millis(40),
        Duration::from_secs(3600),
    )
    .await;
    send_client_datagram(&engine_other_port, other_addr, b"non-nat-t").await;
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), other_dest.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"non-nat-t");
    assert!(
        tokio::time::timeout(Duration::from_millis(120), other_dest.recv_from(&mut buf))
            .await
            .is_err(),
        "keepalive must not be emitted on ports other than NAT-T",
    );
}

#[tokio::test]
async fn ipsec_nat_keepalive_does_not_extend_last_seen_past_ipsec_idle_timeout() {
    let _serial = IPSEC_KEEPALIVE_TEST_LOCK.lock().await;
    let (writer, _capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();
    let engine = direct_engine_with_ipsec(
        writer,
        true,
        Duration::from_millis(80),
        destination_addr.port(),
        Duration::from_millis(30),
        Duration::from_millis(220),
    )
    .await;

    send_client_datagram(&engine, destination_addr, b"start").await;
    let mut buf = vec![0u8; 256];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"start");

    // Past general idle_timeout (80ms), the ipsec flow must still survive cleanup.
    tokio::time::sleep(Duration::from_millis(110)).await;
    engine.cleanup_idle_flows().await;
    assert!(
        engine
            .inner
            .direct_flows
            .read()
            .await
            .contains_key(&flow_key(destination_addr)),
        "ipsec_bypass flow must outlive general idle_timeout",
    );

    // Past ipsec_idle_timeout (220ms), synthetic keepalives must NOT have extended last_seen.
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine.cleanup_idle_flows().await;
    assert!(
        !engine
            .inner
            .direct_flows
            .read()
            .await
            .contains_key(&flow_key(destination_addr)),
        "ipsec_bypass flow must be reaped after ipsec_idle_timeout despite synthetic keepalives",
    );

    // Drain any keepalive already in flight, then confirm the sender stopped.
    while tokio::time::timeout(Duration::from_millis(60), destination.recv_from(&mut buf))
        .await
        .is_ok()
    {}
    assert!(
        tokio::time::timeout(Duration::from_millis(100), destination.recv_from(&mut buf))
            .await
            .is_err(),
        "sender task must stop sending keepalives once the flow is reaped",
    );
    drop(engine);
    tokio::time::sleep(Duration::from_millis(20)).await;
}

fn keepalive_client_metric_value(name: &str, client_ip: IpAddr) -> i64 {
    let rendered = outline_metrics::render_prometheus(&[]).expect("render metrics");
    let needle = format!("{name}{{client_ip=\"{client_ip}\"}} ");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&needle)?.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn ipsec_nat_keepalive_metrics_track_active_flows_and_packets() {
    let _serial = IPSEC_KEEPALIVE_TEST_LOCK.lock().await;
    let (writer, _capture) = TunCapture::new();
    let destination = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let destination_addr = destination.local_addr().unwrap();
    let engine = direct_engine_with_ipsec(
        writer,
        true,
        Duration::from_millis(60),
        destination_addr.port(),
        Duration::from_millis(30),
        Duration::from_millis(120),
    )
    .await;

    let client_ip = IpAddr::V4(CLIENT_IP);
    let active_before =
        keepalive_client_metric_value("outline_ws_tun_ipsec_nat_keepalive_flows_active", client_ip);
    let packets_before = keepalive_client_metric_value(
        "outline_ws_tun_ipsec_nat_keepalive_packets_total",
        client_ip,
    );

    send_client_datagram(&engine, destination_addr, b"open").await;
    let mut buf = vec![0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        keepalive_client_metric_value("outline_ws_tun_ipsec_nat_keepalive_flows_active", client_ip,),
        active_before + 1,
    );

    let (ka_len, _) = tokio::time::timeout(Duration::from_secs(2), destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..ka_len], &[0xff]);
    assert!(
        keepalive_client_metric_value(
            "outline_ws_tun_ipsec_nat_keepalive_packets_total",
            client_ip,
        ) > packets_before,
    );

    tokio::time::sleep(Duration::from_millis(140)).await;
    engine.cleanup_idle_flows().await;
    for _ in 0..100 {
        if keepalive_client_metric_value(
            "outline_ws_tun_ipsec_nat_keepalive_flows_active",
            client_ip,
        ) == active_before
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        keepalive_client_metric_value("outline_ws_tun_ipsec_nat_keepalive_flows_active", client_ip,),
        active_before,
    );
}
