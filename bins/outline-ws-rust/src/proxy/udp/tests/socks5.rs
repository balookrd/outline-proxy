use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use outline_uplink::UplinkRegistry;

use super::*;
use crate::proxy::udp::tests::{make_manager, no_router_config};

/// How long a datagram may take to travel client → relay → target on loopback.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Settle time between datagrams, so the relay has processed the previous one
/// before the next arrives (the assertions are about ordering, not timing).
const SETTLE: Duration = Duration::from_millis(100);

/// A live UDP ASSOCIATE session whose only uplink group is down and opted into
/// `bypass_when_down`, so every datagram takes the direct path and lands on a
/// local socket we can observe.
struct Association {
    task: JoinHandle<anyhow::Result<()>>,
    relay: SocketAddr,
    client: UdpSocket,
    /// The control connection: the association tears itself down on EOF, so
    /// this has to outlive the test body.
    _control: TcpStream,
}

async fn start_association() -> Association {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let (connected, accepted) = tokio::join!(TcpStream::connect(listen_addr), listener.accept());
    let mut control = connected.unwrap();
    let (server, client_addr) = accepted.unwrap();

    let registry = UplinkRegistry::from_single_manager(make_manager("main", true));
    let config = Arc::new(no_router_config());
    let task = tokio::spawn(serve_udp_associate(
        server,
        config,
        registry,
        socket_addr_to_target(client_addr),
    ));

    // SOCKS5 reply: VER | REP | RSV | ATYP=IPv4 | BND.ADDR (4) | BND.PORT (2).
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], SOCKS_REP_SUCCESS, "association refused");
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
        u16::from_be_bytes([reply[8], reply[9]]),
    );

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    Association { task, relay, client, _control: control }
}

/// Encode a SOCKS5 UDP request: RSV(2) | FRAG | ATYP=IPv4 | DST.ADDR | DST.PORT | DATA.
fn udp_request(target: SocketAddr, fragment: u8, data: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(target) = target else { panic!("IPv4 target expected") };
    let mut packet = vec![0x00, 0x00, fragment, 0x01];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Assert that the association still relays: a well-formed datagram sent now
/// must reach `sink`, and the session task must not have finished.
async fn assert_still_relaying(assoc: &Association, sink: &UdpSocket, data: &[u8]) {
    assert!(!assoc.task.is_finished(), "association ended after a per-datagram failure");

    let sink_addr = sink.local_addr().unwrap();
    let packet = udp_request(sink_addr, 0, data);
    assoc.client.send_to(&packet, assoc.relay).await.unwrap();

    let mut buf = [0u8; 64];
    let received = tokio::time::timeout(DELIVERY_TIMEOUT, sink.recv_from(&mut buf))
        .await
        .expect("a later valid datagram was never relayed")
        .unwrap()
        .0;
    assert_eq!(&buf[..received], data, "relayed payload differs");
}

/// A datagram the SOCKS5 UDP parser rejects (here: non-zero RSV) must be
/// dropped on its own. Before the fix the parse error escaped the uplink
/// branch of the association's `select!`, which tore down every concurrent
/// flow of that client.
#[tokio::test]
async fn malformed_datagram_does_not_end_the_association() {
    let assoc = start_association().await;
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    let mut malformed = udp_request(sink.local_addr().unwrap(), 0, b"malformed");
    malformed[0] = 0x01;
    assoc.client.send_to(&malformed, assoc.relay).await.unwrap();
    tokio::time::sleep(SETTLE).await;

    assert_still_relaying(&assoc, &sink, b"after-malformed").await;
}

/// An unknown ATYP is rejected while decoding the target address — same
/// contract: drop the datagram, keep the association.
#[tokio::test]
async fn unknown_address_type_does_not_end_the_association() {
    let assoc = start_association().await;
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    let mut malformed = udp_request(sink.local_addr().unwrap(), 0, b"bad-atyp");
    malformed[3] = 0x07;
    assoc.client.send_to(&malformed, assoc.relay).await.unwrap();
    tokio::time::sleep(SETTLE).await;

    assert_still_relaying(&assoc, &sink, b"after-bad-atyp").await;
}

/// Reassembly rejects a repeated fragment number as out-of-order. UDP
/// reorders and duplicates by nature, so this too must cost only the
/// offending datagram.
#[tokio::test]
async fn rejected_fragment_does_not_end_the_association() {
    let assoc = start_association().await;
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    // FRAG=1 opens a fragment sequence; repeating it is out-of-order.
    let fragment = udp_request(sink.local_addr().unwrap(), 0x01, b"fragment");
    assoc.client.send_to(&fragment, assoc.relay).await.unwrap();
    tokio::time::sleep(SETTLE).await;
    assoc.client.send_to(&fragment, assoc.relay).await.unwrap();
    tokio::time::sleep(SETTLE).await;

    assert_still_relaying(&assoc, &sink, b"after-fragment").await;
}
