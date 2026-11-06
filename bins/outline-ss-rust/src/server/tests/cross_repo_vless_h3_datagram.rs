//! End-to-end VLESS-UDP over HTTP/3 DATAGRAM (RFC 9297) on both HTTP/3
//! carriers: the real client transport (`VlessUdpTransport` on
//! `TransportMode::WsH3` and on `TransportMode::XhttpH3` in its packet-up and
//! stream-one submodes) against the production HTTP/3 accept path, over
//! loopback. Server and helpers are shared with `cross_repo_ss_h3_datagram`.
//!
//! VLESS adds two rules on top of SS-UDP. The first packet carries the VLESS
//! request header and always rides the stream; the client sends datagrams only
//! once the server has answered that header, and the server answers with
//! datagrams only once the client has sent one. And only a plain VLESS-UDP
//! command uses the agreed route: a mux session (or TCP) declines it.
//! Each datagram carries one `len || payload` record, the stream's own framing.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::SinkExt;
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use outline_transport::{
    DialResumeOptions, DnsCache as ClientDnsCache, SessionId, TargetAddr, TransportDialOptions,
    TransportMode, connect_transport, vless::VlessUdpTransport,
};

use super::cross_repo_ss_h3_datagram::{
    BUSY_RECEIVED, CLIENT_DATAGRAMS, CLIENT_FALLBACK, CLIENT_SESSIONS, DOWN, DatagramTestServer,
    LARGE_PAYLOAD, SERVER_DATAGRAMS, SERVER_FALLBACK, SERVER_SESSIONS, SMALL_PAYLOAD, STALL, UP,
    client_counter, payload, serve_h3_datagram_config, spawn_udp_blaster, spawn_udp_echo,
    wait_for_park,
};
use super::{sample_config, test_endpoint};
use crate::config::EndpointKind;
use crate::protocol::vless::{VERSION, parse_uuid};

const TEST_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
const WS_PATH: &str = "/vless";
const XHTTP_PATH: &str = "/xv";
/// VLESS mux command byte.
const COMMAND_MUX: u8 = 0x03;

const VLESS: (&str, &str) = ("proto", "vless");

#[derive(Clone, Copy, Debug)]
enum Carrier {
    WsH3,
    XhttpPacketUp,
    XhttpStreamOne,
}

impl Carrier {
    fn mode(self) -> TransportMode {
        match self {
            Carrier::WsH3 => TransportMode::WsH3,
            Carrier::XhttpPacketUp | Carrier::XhttpStreamOne => TransportMode::XhttpH3,
        }
    }

    /// `transport` label of the client counters.
    fn label(self) -> (&'static str, &'static str) {
        match self {
            Carrier::WsH3 => ("transport", "ws_h3"),
            Carrier::XhttpPacketUp | Carrier::XhttpStreamOne => ("transport", "xhttp_h3"),
        }
    }

    fn url(self, port: u16) -> Result<Url> {
        let url = match self {
            Carrier::WsH3 => format!("wss://localhost:{port}{WS_PATH}"),
            Carrier::XhttpPacketUp => format!("https://localhost:{port}{XHTTP_PATH}"),
            Carrier::XhttpStreamOne => {
                format!("https://localhost:{port}{XHTTP_PATH}?mode=stream-one")
            },
        };
        Ok(Url::parse(&url)?)
    }

    /// Connections the client pool keeps warm per server for this carrier
    /// before it starts reusing them (the transport crate's `*_CARRIER_MIN`).
    fn warm_carriers(self) -> usize {
        match self {
            Carrier::WsH3 => 4,
            Carrier::XhttpPacketUp | Carrier::XhttpStreamOne => 2,
        }
    }

    /// A stream-one dial that fails falls back to packet-up and blocks
    /// stream-one for the host; no block means stream-one is under test.
    async fn assert_carrier(self, port: u16) -> Result<()> {
        if matches!(self, Carrier::XhttpStreamOne) {
            let url = self.url(port)?;
            let blocked = outline_transport::xhttp_stream_one_block_remaining(&url).await;
            assert_eq!(blocked, None, "the stream-one dial fell back to packet-up");
        }
        Ok(())
    }
}

/// `sample_config` with its user given a VLESS id and VLESS-over-WS and
/// VLESS-over-XHTTP endpoints added.
async fn setup_vless_h3_server(udp_datagrams: bool) -> Result<DatagramTestServer> {
    let mut config = sample_config(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)));
    config.session_resumption.enabled = true;
    config.h3_udp_datagrams = udp_datagrams;
    config.users[0].vless_id = Some(TEST_UUID.to_owned());
    config.endpoints.push(test_endpoint(WS_PATH, EndpointKind::WsVless));
    config
        .endpoints
        .push(test_endpoint(XHTTP_PATH, EndpointKind::XhttpVless));
    serve_h3_datagram_config(config).await
}

async fn connect(
    server: &DatagramTestServer,
    carrier: Carrier,
    upstream: SocketAddr,
) -> Result<VlessUdpTransport> {
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let target = match upstream {
        SocketAddr::V4(v4) => TargetAddr::IpV4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => TargetAddr::IpV6(*v6.ip(), v6.port()),
    };
    let transport = VlessUdpTransport::connect(
        &cache,
        &carrier.url(server.addr.port())?,
        carrier.mode(),
        &parse_uuid(TEST_UUID)?,
        &target,
        outline_transport::DialNetworkOptions::default(),
        "cross-repo-vless-h3-datagram",
        None,
    )
    .await?;
    carrier.assert_carrier(server.addr.port()).await?;
    Ok(transport)
}

async fn connect_with_resume(
    server: &DatagramTestServer,
    carrier: Carrier,
    upstream: SocketAddr,
    resume: Option<SessionId>,
) -> Result<(VlessUdpTransport, Option<SessionId>)> {
    connect_at(server.addr.port(), carrier, upstream, resume).await
}

/// [`connect_with_resume`] against whatever listens on `port`: the server
/// itself, or a relay in front of it.
async fn connect_at(
    port: u16,
    carrier: Carrier,
    upstream: SocketAddr,
    resume: Option<SessionId>,
) -> Result<(VlessUdpTransport, Option<SessionId>)> {
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let target = match upstream {
        SocketAddr::V4(v4) => TargetAddr::IpV4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => TargetAddr::IpV6(*v6.ip(), v6.port()),
    };
    let (transport, issued, downgraded, _) = VlessUdpTransport::connect_with_resume(
        &cache,
        &carrier.url(port)?,
        carrier.mode(),
        &parse_uuid(TEST_UUID)?,
        &target,
        outline_transport::DialNetworkOptions::default(),
        "cross-repo-vless-h3-datagram",
        None,
        resume,
    )
    .await?;
    assert_eq!(downgraded, None, "the dial must stay on {:?}", carrier.mode());
    carrier.assert_carrier(port).await?;
    Ok((transport, issued))
}

async fn round_trip(transport: &VlessUdpTransport, data: &[u8]) -> Result<()> {
    transport.send_packet(data).await?;
    let reply = tokio::time::timeout(Duration::from_secs(5), transport.read_packet())
        .await
        .context("echo reply timed out")??;
    assert_eq!(&reply[..], data, "echoed payload mismatch");
    Ok(())
}

async fn small_packets_ride_h3_datagrams_after_the_header(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(true).await?;
    let client_up = client_counter(CLIENT_DATAGRAMS, &[UP, label, VLESS]);
    let client_down = client_counter(CLIENT_DATAGRAMS, &[DOWN, label, VLESS]);
    let client_stream_up = client_counter(CLIENT_FALLBACK, &[UP, label, VLESS]);

    let transport = connect(&server, carrier, upstream).await?;
    // Carries the request header: the stream, whatever its size.
    round_trip(&transport, b"ping").await?;
    assert!(
        client_counter(CLIENT_FALLBACK, &[UP, label, VLESS]) - client_stream_up >= 1.0,
        "the header packet must ride the stream"
    );
    assert_eq!(server.counter(SERVER_DATAGRAMS, &[UP, VLESS]), 0.0);
    round_trip(&transport, &payload(SMALL_PAYLOAD, 7)).await?;
    round_trip(&transport, &payload(SMALL_PAYLOAD, 8)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 1.0);
    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "declined")]), 0.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[UP, VLESS]) >= 2.0, "no uplink datagram");
    assert!(server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]) >= 1.0, "no downlink datagram");
    assert_eq!(server.counter(SERVER_FALLBACK, &[UP, VLESS]), 0.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS, ("reason", "too_large")]), 0.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS, ("reason", "send_failed")]), 0.0);
    assert_eq!(server.counter(SERVER_DATAGRAMS, &[("proto", "ss")]), 0.0);
    assert!(client_counter(CLIENT_DATAGRAMS, &[UP, label, VLESS]) - client_up >= 2.0);
    assert!(
        client_counter(CLIENT_DATAGRAMS, &[DOWN, label, VLESS]) - client_down >= 1.0,
        "client received no downlink datagram"
    );

    transport.close().await?;
    Ok(())
}

async fn oversized_packet_falls_back_to_the_stream(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(true).await?;
    let client_stream_up = client_counter(CLIENT_FALLBACK, &[UP, label, VLESS]);

    let transport = connect(&server, carrier, upstream).await?;
    round_trip(&transport, b"ping").await?;
    // The first uplink datagram opens the downlink.
    round_trip(&transport, &payload(SMALL_PAYLOAD, 1)).await?;
    round_trip(&transport, &payload(LARGE_PAYLOAD, 3)).await?;
    // The session stays on datagrams for records that fit.
    round_trip(&transport, &payload(SMALL_PAYLOAD, 9)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 1.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[UP, VLESS]), 1.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS, ("reason", "too_large")]), 1.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[UP, VLESS]) >= 2.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]) >= 2.0);
    // The header packet and the oversized one.
    assert!(client_counter(CLIENT_FALLBACK, &[UP, label, VLESS]) - client_stream_up >= 2.0);

    transport.close().await?;
    Ok(())
}

async fn server_with_datagrams_off_declines_and_keeps_the_stream(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(false).await?;
    let client_declined = client_counter(CLIENT_SESSIONS, &[label, ("state", "declined")]);

    let transport = connect(&server, carrier, upstream).await?;
    round_trip(&transport, b"ping").await?;
    round_trip(&transport, &payload(SMALL_PAYLOAD, 1)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "declined")]), 1.0);
    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 0.0);
    assert_eq!(server.counter(SERVER_DATAGRAMS, &[]), 0.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[]), 0.0);
    assert!(
        client_counter(CLIENT_SESSIONS, &[label, ("state", "declined")]) - client_declined >= 1.0
    );

    transport.close().await?;
    Ok(())
}

/// A carrier that offers datagrams (as a VLESS-UDP dial would) but opens a
/// mux session: the server agrees on the CONNECT / anchor request, then drops
/// the route once the command turns out to be mux.
async fn mux_session_declines_datagrams(carrier: Carrier) -> Result<()> {
    let server = setup_vless_h3_server(true).await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = carrier.url(server.addr.port())?;
    let mut stream = connect_transport(
        TransportDialOptions::new(&cache, &url, carrier.mode(), "cross-repo-vless-h3-datagram")
            .with_resume(DialResumeOptions {
                udp_datagram_requested: true,
                ..DialResumeOptions::default()
            }),
    )
    .await?;
    carrier.assert_carrier(server.addr.port()).await?;
    let mut request = vec![VERSION];
    request.extend_from_slice(&parse_uuid(TEST_UUID)?);
    request.extend_from_slice(&[0, COMMAND_MUX]);
    stream.send(Message::Binary(Bytes::from(request))).await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.counter(SERVER_SESSIONS, &[("state", "declined")]) < 1.0 {
        assert!(tokio::time::Instant::now() < deadline, "the mux session never declined");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "declined")]), 1.0);
    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 0.0);
    assert_eq!(server.counter(SERVER_DATAGRAMS, &[]), 0.0);
    drop(stream);
    Ok(())
}

/// A googlevideo-sized record: fits one datagram on loopback.
const BUSY_FITS: usize = 1350;
/// Past every datagram size on loopback: rides the stream.
const BUSY_TOO_LARGE: usize = 1600;

const RESUME_HITS: &str = "outline_ss_orphan_resume_hit_total";
const RESUME_MISSES: &str = "outline_ss_orphan_resume_miss_total";

/// A soft switch: the session's carrier is retired and the same session comes
/// back on a new one presenting its Session ID. The parked socket must be
/// re-attached, and the downlink must follow the new carrier (datagrams
/// included) — never the retired one.
async fn resume_moves_datagrams_to_the_new_anchor(
    carrier: Carrier,
    udp_datagrams: bool,
) -> Result<()> {
    let (upstream, sources) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(udp_datagrams).await?;

    let (first, issued) = connect_with_resume(&server, carrier, upstream, None).await?;
    let session_id = issued.context("server minted no Session ID")?;
    round_trip(&first, b"ping").await?;
    round_trip(&first, &payload(SMALL_PAYLOAD, 11)).await?;
    round_trip(&first, &payload(SMALL_PAYLOAD, 12)).await?;
    let down_before = server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]);
    if udp_datagrams {
        assert!(down_before >= 1.0, "first carrier did not use downlink datagrams");
    }

    // Retire the first carrier; the server parks the socket under the id.
    first.close().await?;
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.orphans.len() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "the retired carrier was never parked");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (second, _) = connect_with_resume(&server, carrier, upstream, Some(session_id)).await?;
    for tag in 21..31 {
        round_trip(&second, &payload(SMALL_PAYLOAD, tag)).await?;
    }

    assert_eq!(
        server.counter(RESUME_HITS, &[("kind", "vless_udp_single")]),
        1.0,
        "the session was not resumed (misses: {})",
        server.counter(RESUME_MISSES, &[]),
    );
    assert_eq!(
        sources.lock().await.len(),
        1,
        "resume must keep the parked socket: the upstream saw a second source"
    );
    if udp_datagrams {
        assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 2.0);
        assert!(
            server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]) > down_before,
            "the resumed session sent no downlink datagram"
        );
        assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS, ("reason", "too_large")]), 0.0);
        assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS, ("reason", "send_failed")]), 0.0);
    } else {
        assert_eq!(server.counter(SERVER_DATAGRAMS, &[]), 0.0);
    }
    second.close().await?;
    Ok(())
}

/// Sends `data` up (which also points the blaster at this session's source)
/// and waits for [`BUSY_RECEIVED`] downlink packets. Echoes are not waited for:
/// under the blast one may be lost to a full socket buffer.
async fn downlink_flows(transport: &VlessUdpTransport, data: &[u8]) -> Result<()> {
    transport.send_packet(data).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    for received in 0..BUSY_RECEIVED {
        tokio::time::timeout_at(deadline, transport.read_packet())
            .await
            .with_context(|| format!("downlink stalled after {received} packets"))??;
    }
    Ok(())
}

/// The soft switch of the incident: the downlink is busy (a video stream) when
/// the client retires the carrier, so the server's downlink pump is mid-send —
/// a datagram, or a stream frame into a carrier the client no longer reads —
/// when the park asks it to stop. `packet` is the size the upstream streams:
/// one that fits a loopback datagram keeps the pump off the stream, one past it
/// sends everything down the stream as on a padded path in production.
async fn resume_under_a_busy_downlink(
    carrier: Carrier,
    udp_datagrams: bool,
    packet: usize,
) -> Result<()> {
    let (upstream, sources) = spawn_udp_blaster(packet).await?;
    let server = setup_vless_h3_server(udp_datagrams).await?;

    let (first, issued) = connect_with_resume(&server, carrier, upstream, None).await?;
    let session_id = issued.context("server minted no Session ID")?;
    downlink_flows(&first, b"ping").await.context("first carrier")?;
    downlink_flows(&first, &payload(SMALL_PAYLOAD, 11))
        .await
        .context("first carrier")?;
    // Let the blast run while the client keeps reading, then stop reading for
    // a while (the switch is decided), so the carrier backs up.
    let reading = tokio::time::Instant::now() + Duration::from_millis(200);
    while tokio::time::Instant::now() < reading {
        let _ = tokio::time::timeout(Duration::from_millis(50), first.read_packet()).await;
    }
    tokio::time::sleep(STALL).await;

    first.close().await?;
    drop(first);
    wait_for_park(&server).await;

    let (second, _) = connect_with_resume(&server, carrier, upstream, Some(session_id)).await?;
    for tag in 21..26 {
        downlink_flows(&second, &payload(SMALL_PAYLOAD, tag))
            .await
            .with_context(|| {
                format!(
                    "resumed carrier, packet {tag} (hits {}, misses {})",
                    server.counter(RESUME_HITS, &[]),
                    server.counter(RESUME_MISSES, &[]),
                )
            })?;
    }
    assert_eq!(
        server.counter(RESUME_HITS, &[("kind", "vless_udp_single")]),
        1.0,
        "the session was not resumed (misses: unknown {}, total {})",
        server.counter(RESUME_MISSES, &[("reason", "unknown")]),
        server.counter(RESUME_MISSES, &[]),
    );
    assert_eq!(sources.lock().await.len(), 1, "the upstream saw a second source");
    second.close().await?;
    Ok(())
}

/// Before the first uplink datagram the server keeps VLESS downlink on the
/// stream and counts each packet as an `unarmed` fallback under its carrier.
async fn unarmed_downlink_is_counted_per_carrier(carrier: Carrier) -> Result<()> {
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(true).await?;
    let transport = connect(&server, carrier, upstream).await?;
    // The header packet rides the stream; its echo comes back before any
    // uplink datagram armed the downlink.
    round_trip(&transport, b"ping").await?;
    let transport_label = carrier.label();
    assert_eq!(
        server.counter(SERVER_FALLBACK, &[DOWN, VLESS, transport_label, ("reason", "unarmed")]),
        1.0
    );
    transport.close().await?;
    Ok(())
}

/// Once the client drops its transport, the server stops sending its downlink
/// datagrams within a short grace (FIN on packet-up, the body's end on
/// stream-one, RESET on ws), instead of when the anchor request ends.
async fn dropped_client_stops_downlink_datagrams(carrier: Carrier) -> Result<()> {
    let (upstream, _) = spawn_udp_blaster(BUSY_FITS).await?;
    let server = setup_vless_h3_server(true).await?;
    let transport = connect(&server, carrier, upstream).await?;
    transport.send_packet(b"ping").await?;
    downlink_flows(&transport, &[7u8; 64]).await?;
    transport.close().await?;
    drop(transport);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = server.counter(SERVER_DATAGRAMS, &[DOWN, VLESS]);
    assert_eq!(
        after - before,
        0.0,
        "{carrier:?}: server kept sending datagrams to a closed client"
    );
    Ok(())
}

/// UDP relay standing in for the network path. It forwards every client flow
/// to the server until [`SilencingRelay::silence_existing`], after which the
/// flows it already knows are dropped both ways while new ones still pass:
/// to a pooled QUIC carrier this is a dead path or a rebinding NAT, a peer
/// that went quiet without closing anything.
struct SilencingRelay {
    port: u16,
    known: Arc<StdMutex<HashSet<SocketAddr>>>,
    silenced: Arc<StdMutex<HashSet<SocketAddr>>>,
    task: tokio::task::JoinHandle<()>,
}

impl SilencingRelay {
    fn silence_existing(&self) {
        let known = self.known.lock().expect("relay lock").clone();
        self.silenced.lock().expect("relay lock").extend(known);
    }
}

impl Drop for SilencingRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_silencing_relay(server: SocketAddr) -> Result<SilencingRelay> {
    let front = Arc::new(UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?);
    let port = front.local_addr()?.port();
    let known: Arc<StdMutex<HashSet<SocketAddr>>> = Arc::default();
    let silenced: Arc<StdMutex<HashSet<SocketAddr>>> = Arc::default();
    let task = tokio::spawn({
        let known = Arc::clone(&known);
        let silenced = Arc::clone(&silenced);
        async move {
            // Aborting the relay drops this set, which aborts every downlink pump.
            let mut pumps = tokio::task::JoinSet::new();
            let mut backs: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, client)) = front.recv_from(&mut buf).await else { return };
                if silenced.lock().expect("relay lock").contains(&client) {
                    continue;
                }
                let back = match backs.get(&client) {
                    Some(back) => Arc::clone(back),
                    None => {
                        let Ok(back) = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await
                        else {
                            return;
                        };
                        if back.connect(server).await.is_err() {
                            return;
                        }
                        let back = Arc::new(back);
                        known.lock().expect("relay lock").insert(client);
                        backs.insert(client, Arc::clone(&back));
                        let (pump_front, pump_back, pump_silenced) =
                            (Arc::clone(&front), Arc::clone(&back), Arc::clone(&silenced));
                        pumps.spawn(async move {
                            let mut buf = vec![0u8; 65_535];
                            while let Ok(n) = pump_back.recv(&mut buf).await {
                                if !pump_silenced.lock().expect("relay lock").contains(&client) {
                                    let _ = pump_front.send_to(&buf[..n], client).await;
                                }
                            }
                        });
                        back
                    },
                };
                let _ = back.send(&buf[..n]).await;
            }
        }
    });
    Ok(SilencingRelay { port, known, silenced, task })
}

/// A pooled carrier whose peer went quiet still reads as open until QUIC's
/// idle timeout. A session landing on it must not wait out the whole dial
/// budget and fall back to h2: the dial gives the pooled carrier a short
/// budget, then retires it and redials on a fresh connection.
async fn a_silent_pooled_carrier_is_redialed(carrier: Carrier) -> Result<()> {
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_vless_h3_server(false).await?;
    let relay = spawn_silencing_relay(server.addr).await?;
    // Fill every warm slot of the pool for the relay's port, so the dial below
    // can only land on a pooled carrier.
    for _ in 0..carrier.warm_carriers() {
        let (transport, _) = connect_at(relay.port, carrier, upstream, None).await?;
        round_trip(&transport, b"ping").await?;
        transport.close().await?;
    }

    relay.silence_existing();
    let started = tokio::time::Instant::now();
    let (transport, _) = connect_at(relay.port, carrier, upstream, None)
        .await
        .context("the dial did not recover from a silent pooled carrier")?;
    round_trip(&transport, b"ping").await?;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(6),
        "{carrier:?}: recovering from a silent pooled carrier took {took:?}"
    );
    transport.close().await?;
    Ok(())
}

macro_rules! carrier_tests {
    ($($module:ident => $carrier:expr),+ $(,)?) => {$(
        mod $module {
            use super::*;

            #[tokio::test]
            async fn a_silent_pooled_carrier_is_redialed() -> Result<()> {
                super::a_silent_pooled_carrier_is_redialed($carrier).await
            }

            #[tokio::test]
            async fn small_packets_ride_h3_datagrams_after_the_header() -> Result<()> {
                super::small_packets_ride_h3_datagrams_after_the_header($carrier).await
            }

            #[tokio::test]
            async fn oversized_packet_falls_back_to_the_stream() -> Result<()> {
                super::oversized_packet_falls_back_to_the_stream($carrier).await
            }

            #[tokio::test]
            async fn server_with_datagrams_off_declines_and_keeps_the_stream() -> Result<()> {
                super::server_with_datagrams_off_declines_and_keeps_the_stream($carrier).await
            }

            #[tokio::test]
            async fn unarmed_downlink_is_counted_per_carrier() -> Result<()> {
                super::unarmed_downlink_is_counted_per_carrier($carrier).await
            }

            #[tokio::test]
            async fn mux_session_declines_datagrams() -> Result<()> {
                super::mux_session_declines_datagrams($carrier).await
            }

            #[tokio::test]
            async fn resume_moves_datagrams_to_the_new_anchor() -> Result<()> {
                super::resume_moves_datagrams_to_the_new_anchor($carrier, true).await
            }

            #[tokio::test]
            async fn resume_under_a_busy_datagram_downlink() -> Result<()> {
                super::resume_under_a_busy_downlink($carrier, true, BUSY_FITS).await
            }

            #[tokio::test]
            async fn resume_under_a_busy_stream_downlink() -> Result<()> {
                super::resume_under_a_busy_downlink($carrier, true, BUSY_TOO_LARGE).await
            }

            #[tokio::test]
            async fn resume_under_a_busy_downlink_without_datagrams() -> Result<()> {
                super::resume_under_a_busy_downlink($carrier, false, BUSY_FITS).await
            }

            #[tokio::test]
            async fn resume_without_datagrams_reattaches_the_socket() -> Result<()> {
                super::resume_moves_datagrams_to_the_new_anchor($carrier, false).await
            }

            #[tokio::test]
            async fn dropped_client_stops_downlink_datagrams() -> Result<()> {
                super::dropped_client_stops_downlink_datagrams($carrier).await
            }
        }
    )+};
}

carrier_tests! {
    ws_h3 => Carrier::WsH3,
    xhttp_h3_packet_up => Carrier::XhttpPacketUp,
    xhttp_h3_stream_one => Carrier::XhttpStreamOne,
}
