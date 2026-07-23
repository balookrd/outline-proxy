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
use std::sync::Arc;
use std::time::Duration;

use outline_routing::{RouteTarget, RoutingTable, RoutingTableConfig};
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
    let manager = build_test_manager_with_urls(None, None).await;
    let table = Arc::new(
        RoutingTable::compile(&RoutingTableConfig {
            rules: Vec::new(),
            default_target: RouteTarget::Direct,
            default_fallback: None,
        })
        .await
        .unwrap(),
    );
    let routing =
        TunRouting::new(UplinkRegistry::from_single_manager(manager), Some(table), None, false);
    TunUdpEngine::new(
        writer,
        routing,
        128,
        Duration::from_secs(60),
        false,
        false,
        false,
        Vec::new().into(),
        false,
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
