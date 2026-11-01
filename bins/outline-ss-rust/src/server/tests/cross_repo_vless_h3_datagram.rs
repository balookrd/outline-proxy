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

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use outline_transport::{
    DialResumeOptions, DnsCache as ClientDnsCache, TargetAddr, TransportDialOptions, TransportMode,
    connect_transport, vless::VlessUdpTransport,
};

use super::cross_repo_ss_h3_datagram::{
    CLIENT_DATAGRAMS, CLIENT_FALLBACK, CLIENT_SESSIONS, DOWN, DatagramTestServer, LARGE_PAYLOAD,
    SERVER_DATAGRAMS, SERVER_FALLBACK, SERVER_SESSIONS, SMALL_PAYLOAD, UP, client_counter, payload,
    serve_h3_datagram_config, spawn_udp_echo,
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

    fn url(self, server: &DatagramTestServer) -> Result<Url> {
        let port = server.addr.port();
        let url = match self {
            Carrier::WsH3 => format!("wss://localhost:{port}{WS_PATH}"),
            Carrier::XhttpPacketUp => format!("https://localhost:{port}{XHTTP_PATH}"),
            Carrier::XhttpStreamOne => {
                format!("https://localhost:{port}{XHTTP_PATH}?mode=stream-one")
            },
        };
        Ok(Url::parse(&url)?)
    }

    /// A stream-one dial that fails falls back to packet-up and blocks
    /// stream-one for the host; no block means stream-one is under test.
    async fn assert_carrier(self, server: &DatagramTestServer) -> Result<()> {
        if matches!(self, Carrier::XhttpStreamOne) {
            let url = self.url(server)?;
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
        &carrier.url(server)?,
        carrier.mode(),
        &parse_uuid(TEST_UUID)?,
        &target,
        None,
        false,
        false,
        "cross-repo-vless-h3-datagram",
        None,
    )
    .await?;
    carrier.assert_carrier(server).await?;
    Ok(transport)
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
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS]), 0.0);
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
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, VLESS]), 1.0);
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
    let url = carrier.url(&server)?;
    let mut stream = connect_transport(
        TransportDialOptions::new(&cache, &url, carrier.mode(), "cross-repo-vless-h3-datagram")
            .with_resume(DialResumeOptions {
                udp_datagram_requested: true,
                ..DialResumeOptions::default()
            }),
    )
    .await?;
    carrier.assert_carrier(&server).await?;
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

macro_rules! carrier_tests {
    ($($module:ident => $carrier:expr),+ $(,)?) => {$(
        mod $module {
            use super::*;

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
            async fn mux_session_declines_datagrams() -> Result<()> {
                super::mux_session_declines_datagrams($carrier).await
            }
        }
    )+};
}

carrier_tests! {
    ws_h3 => Carrier::WsH3,
    xhttp_h3_packet_up => Carrier::XhttpPacketUp,
    xhttp_h3_stream_one => Carrier::XhttpStreamOne,
}
