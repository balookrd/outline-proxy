//! End-to-end SS-UDP over HTTP/3 DATAGRAM (RFC 9297) on both HTTP/3 carriers:
//! the real client transport (`UdpWsTransport` on `TransportMode::WsH3` and on
//! `TransportMode::XhttpH3` in its packet-up and stream-one submodes) against
//! the production HTTP/3 accept path (`serve_h3_server` on an endpoint built
//! with the production QUIC transport config), over loopback.
//!
//! The client offers `x-outline-udp-datagram: 1` on the session's anchor
//! request (the ws CONNECT, the xhttp GET, or the stream-one POST); the server
//! echoes it when `[server.h3] udp_datagrams` is on and the QUIC connection can
//! carry datagrams. Both sides then send each SS packet that fits as one
//! datagram and fall back to the stream (a WS Binary frame, or an xhttp UDP
//! record) for the rest. The counters on both sides are the observable signal:
//! the bytes on the wire look the same to the SS layer whichever way a packet
//! went.
//!
//! The client's QUIC connection starts at the 1200-byte floor, so its datagram
//! size is ~1160 until path MTU discovery raises it: the "fits" payloads stay
//! small (100 bytes) and the fallback payload (3000 bytes) is well past even the
//! server's 1452-byte UDP payload ceiling.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use url::Url;

use outline_transport::{DnsCache as ClientDnsCache, TransportMode, UdpWsTransport};

use super::super::endpoint_routes::{
    build_route_registry, build_ss_user_pool, build_vless_user_pool,
};
use super::super::h3::build_h3_quinn_server_config;
use super::super::h3::vendored::h3_ws_server_from_endpoint;
use super::super::nat::NatTable;
use super::super::resumption::{OrphanRegistry, ResumptionConfig};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, H3ServeCtx, serve_h3_server};
use super::{sample_config, test_endpoint};
use crate::config::{CipherKind, Config, EndpointKind, H3Alpn};
use crate::metrics::Metrics;

/// The `sample_config` user's password and method.
const TEST_PASSWORD: &str = "secret-b";
const TEST_CIPHER: CipherKind = CipherKind::Chacha20IetfPoly1305;
/// Fits one datagram even at the client's initial 1200-byte QUIC MTU.
pub(super) const SMALL_PAYLOAD: usize = 100;
/// Exceeds every datagram size either side can reach on this listener.
pub(super) const LARGE_PAYLOAD: usize = 3000;
/// Split SS-UDP-over-XHTTP base path added next to the `sample_config` routes.
const XHTTP_UDP_PATH: &str = "/xu";

/// The HTTP/3 carrier a test drives, with the anchor request it binds
/// datagrams to.
#[derive(Clone, Copy, Debug)]
enum Carrier {
    /// RFC 9220 WebSocket: the CONNECT stream.
    WsH3,
    /// xhttp packet-up: the long-lived GET (uplink POSTs are separate streams).
    XhttpPacketUp,
    /// xhttp stream-one: the single bidirectional POST.
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

    /// `protocol` label of the server's series for this carrier.
    fn server_protocol(self) -> &'static str {
        match self {
            Carrier::WsH3 => "http3",
            Carrier::XhttpPacketUp | Carrier::XhttpStreamOne => "xhttp_h3",
        }
    }

    fn url(self, port: u16) -> Result<Url> {
        let url = match self {
            // WS-h3 mandates `wss://`.
            Carrier::WsH3 => format!("wss://localhost:{port}/udp"),
            Carrier::XhttpPacketUp => format!("https://localhost:{port}{XHTTP_UDP_PATH}"),
            Carrier::XhttpStreamOne => {
                format!("https://localhost:{port}{XHTTP_UDP_PATH}?mode=stream-one")
            },
        };
        Ok(Url::parse(&url)?)
    }
}

pub(super) struct DatagramTestServer {
    pub(super) addr: SocketAddr,
    pub(super) metrics: Arc<Metrics>,
    pub(super) orphans: Arc<OrphanRegistry>,
    task: JoinHandle<Result<()>>,
}

impl DatagramTestServer {
    pub(super) fn counter(&self, metric: &str, labels: &[(&str, &str)]) -> f64 {
        metric_value(&self.metrics.render_prometheus(), metric, labels)
    }

    fn url(&self, carrier: Carrier) -> Result<Url> {
        carrier.url(self.addr.port())
    }
}

impl Drop for DatagramTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Real h3 listener carrying the `sample_config` `/udp` SS-UDP route plus a
/// split SS-UDP-over-XHTTP base ([`XHTTP_UDP_PATH`]), with session resumption
/// on, built from the production QUIC server config and endpoint sizing and
/// served by the production accept loop.
async fn setup_ss_udp_h3_server(udp_datagrams: bool) -> Result<DatagramTestServer> {
    let mut config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    config.session_resumption.enabled = true;
    config.h3_udp_datagrams = udp_datagrams;
    config
        .endpoints
        .push(test_endpoint(XHTTP_UDP_PATH, EndpointKind::XhttpSsUdp));
    serve_h3_datagram_config(config).await
}

/// Serves `config`'s endpoints (SS and VLESS alike) on a real h3 listener built
/// from the production QUIC server config and endpoint sizing, through the
/// production accept loop.
pub(super) async fn serve_h3_datagram_config(config: Config) -> Result<DatagramTestServer> {
    super::cross_repo_install_test_tls_root_on_client();
    let tls_config = super::cross_repo_test_server_tls_config(&[b"h3"]);
    let server_config = build_h3_quinn_server_config(tls_config, &config.tuning, None)?;
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(super::super::constants::H3_MAX_UDP_PAYLOAD_SIZE)?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let addr = endpoint.local_addr()?;
    let server =
        h3_ws_server_from_endpoint(endpoint, super::super::h3::build_h3_ws_config(&config.tuning));

    let metrics = Metrics::new(&config);
    let effective = config.effective_users()?;
    let ss_users = build_ss_user_pool(&effective, config.method)?;
    let vless_users = build_vless_user_pool(&effective)?;
    let routes = Arc::new(ArcSwap::from_pointee(build_route_registry(
        &config.endpoints,
        &ss_users,
        &vless_users,
    )));
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0, 0),
            relay_semaphore: None,
        },
        Some(Arc::clone(&orphan_registry)),
        16,
        crate::server::transport::XhttpRegistryLimits::unbounded(),
        crate::server::salt_replay::SaltReplayStore::new(Duration::from_secs(60), 0),
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            ss_users.into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let task = tokio::spawn(async move {
        serve_h3_server(
            server,
            H3ServeCtx {
                udp_datagrams: config.h3_udp_datagrams,
                routes,
                services,
                auth,
                alpn: Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
                http_fallback: None,
                cluster: None,
            },
            ShutdownSignal::never(),
        )
        .await
    });
    Ok(DatagramTestServer {
        addr,
        metrics,
        orphans: orphan_registry,
        task,
    })
}

pub(super) type Sources = Arc<Mutex<HashSet<SocketAddr>>>;

/// UDP echo upstream that records every distinct source it hears from — one
/// source across a reconnect means the server kept the same NAT socket.
pub(super) async fn spawn_udp_echo() -> Result<(SocketAddr, Sources)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let sources: Sources = Arc::new(Mutex::new(HashSet::new()));
    let seen = Arc::clone(&sources);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            seen.lock().await.insert(peer);
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    Ok((addr, sources))
}

/// SOCKS5 IPv4 target header + payload: the plaintext of one SS-UDP packet.
fn ss_first_chunk(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => chunk.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => unreachable!("test upstream is always ipv4"),
    }
    chunk.extend_from_slice(&target.port().to_be_bytes());
    chunk.extend_from_slice(payload);
    chunk
}

pub(super) fn payload(len: usize, tag: u8) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// One echo round trip: the reply is `[SOCKS5 source][echoed payload]`.
async fn round_trip(transport: &UdpWsTransport, upstream: SocketAddr, data: &[u8]) -> Result<()> {
    transport.send_packet(&ss_first_chunk(upstream, data)).await?;
    let reply = tokio::time::timeout(Duration::from_secs(5), transport.read_packet())
        .await
        .context("echo reply timed out")??;
    assert!(reply.ends_with(data), "echoed payload mismatch ({} bytes back)", reply.len());
    Ok(())
}

async fn connect(server: &DatagramTestServer, carrier: Carrier) -> Result<UdpWsTransport> {
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let transport = UdpWsTransport::connect(
        &cache,
        &server.url(carrier)?,
        carrier.mode(),
        TEST_CIPHER,
        TEST_PASSWORD,
        None,
        false,
        false,
        "cross-repo-ss-h3-datagram",
        None,
        None,
    )
    .await?;
    assert_stayed_on_stream_one(server, carrier).await?;
    Ok(transport)
}

/// A stream-one dial that fails falls back to packet-up on the same connection
/// and blocks stream-one for the host; no block means the stream-one carrier
/// is the one under test.
async fn assert_stayed_on_stream_one(server: &DatagramTestServer, carrier: Carrier) -> Result<()> {
    if matches!(carrier, Carrier::XhttpStreamOne) {
        let url = server.url(carrier)?;
        let blocked = outline_transport::xhttp_stream_one_block_remaining(&url).await;
        assert_eq!(blocked, None, "the stream-one dial fell back to packet-up");
    }
    Ok(())
}

async fn connect_with_resume(
    server: &DatagramTestServer,
    carrier: Carrier,
    resume: Option<outline_transport::SessionId>,
) -> Result<(UdpWsTransport, Option<outline_transport::SessionId>)> {
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, issued, downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &server.url(carrier)?,
        carrier.mode(),
        TEST_CIPHER,
        TEST_PASSWORD,
        None,
        false,
        false,
        "cross-repo-ss-h3-datagram",
        None,
        resume,
        None,
    )
    .await?;
    assert_eq!(downgraded, None, "the dial must stay on {:?}", carrier.mode());
    assert_stayed_on_stream_one(server, carrier).await?;
    Ok((transport, issued))
}

/// Sum of every sample of `metric` whose label set contains all of `labels`
/// (label order differs between the two exporters).
pub(super) fn metric_value(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> f64 {
    rendered
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let rest = series.strip_prefix(metric)?;
            if !(rest.is_empty() || rest.starts_with('{')) {
                return None;
            }
            labels
                .iter()
                .all(|(k, v)| rest.contains(&format!("{k}=\"{v}\"")))
                .then(|| value.parse::<f64>().ok())
                .flatten()
        })
        .fold(0.0, |total, value| total + value)
}

/// Client counters are process-global (other tests run alongside), so the
/// assertions below always read deltas.
pub(super) fn client_counter(metric: &str, labels: &[(&str, &str)]) -> f64 {
    let rendered = outline_metrics::render_prometheus(&[]).expect("client metrics render");
    metric_value(&rendered, metric, labels)
}

pub(super) const SERVER_DATAGRAMS: &str = "outline_ss_udp_h3_datagrams_total";
pub(super) const SERVER_FALLBACK: &str = "outline_ss_udp_h3_datagram_fallback_total";
pub(super) const SERVER_SESSIONS: &str = "outline_ss_udp_h3_datagram_sessions_total";
const RESPONSE_DATAGRAMS: &str = "outline_ss_udp_response_datagrams_total";
const PAYLOAD_BYTES: &str = "outline_ss_udp_payload_bytes_total";
pub(super) const CLIENT_DATAGRAMS: &str = "outline_ws_udp_h3_datagrams_total";
pub(super) const CLIENT_FALLBACK: &str = "outline_ws_udp_h3_datagram_fallback_total";
pub(super) const CLIENT_SESSIONS: &str = "outline_ws_udp_h3_datagram_sessions_total";

pub(super) const UP: (&str, &str) = ("direction", "up");
pub(super) const DOWN: (&str, &str) = ("direction", "down");
const SS: (&str, &str) = ("proto", "ss");

async fn small_packets_ride_h3_datagrams_both_ways(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_ss_udp_h3_server(true).await?;
    let client_down = client_counter(CLIENT_DATAGRAMS, &[DOWN, label, SS]);
    let client_up = client_counter(CLIENT_DATAGRAMS, &[UP, label, SS]);

    let transport = connect(&server, carrier).await?;
    round_trip(&transport, upstream, b"ping").await?;
    round_trip(&transport, upstream, &payload(SMALL_PAYLOAD, 7)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 1.0);
    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "declined")]), 0.0);
    assert!(
        server.counter(SERVER_DATAGRAMS, &[UP, SS]) >= 2.0,
        "server saw no uplink datagram"
    );
    assert!(server.counter(SERVER_DATAGRAMS, &[DOWN, SS]) >= 2.0, "server sent no datagram");
    assert_eq!(server.counter(SERVER_FALLBACK, &[UP, SS]), 0.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, SS]), 0.0);
    assert!(client_counter(CLIENT_DATAGRAMS, &[UP, label, SS]) - client_up >= 2.0);
    assert!(
        client_counter(CLIENT_DATAGRAMS, &[DOWN, label, SS]) - client_down >= 2.0,
        "client received no downlink datagram"
    );
    // The NAT downlink series carry the session's real carrier: xhttp over
    // HTTP/3 used to report `xhttp_h2` here.
    let protocol = ("protocol", carrier.server_protocol());
    assert!(
        server.counter(RESPONSE_DATAGRAMS, &[protocol]) >= 2.0,
        "no downlink on {protocol:?}"
    );
    assert!(server.counter(PAYLOAD_BYTES, &[protocol, ("direction", "down")]) > 0.0);
    for other in ["xhttp_h1", "xhttp_h2", "http1", "http2"] {
        assert_eq!(server.counter(RESPONSE_DATAGRAMS, &[("protocol", other)]), 0.0, "{other}");
        assert_eq!(server.counter(PAYLOAD_BYTES, &[("protocol", other)]), 0.0, "{other}");
    }

    transport.close().await?;
    Ok(())
}

async fn oversized_packet_falls_back_to_the_stream(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_ss_udp_h3_server(true).await?;
    let client_fallback_up = client_counter(CLIENT_FALLBACK, &[UP, label, SS]);

    let transport = connect(&server, carrier).await?;
    round_trip(&transport, upstream, &payload(LARGE_PAYLOAD, 3)).await?;
    // The session stays on datagrams for packets that fit.
    round_trip(&transport, upstream, &payload(SMALL_PAYLOAD, 9)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 1.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[UP, SS]), 1.0);
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, SS]), 1.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[UP, SS]) >= 1.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[DOWN, SS]) >= 1.0);
    assert!(client_counter(CLIENT_FALLBACK, &[UP, label, SS]) - client_fallback_up >= 1.0);

    transport.close().await?;
    Ok(())
}

async fn server_with_datagrams_off_declines_and_keeps_the_stream(carrier: Carrier) -> Result<()> {
    let label = carrier.label();
    let (upstream, _) = spawn_udp_echo().await?;
    let server = setup_ss_udp_h3_server(false).await?;
    let client_declined = client_counter(CLIENT_SESSIONS, &[label, ("state", "declined")]);

    let transport = connect(&server, carrier).await?;
    round_trip(&transport, upstream, b"ping").await?;
    round_trip(&transport, upstream, &payload(SMALL_PAYLOAD, 1)).await?;

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

async fn resume_moves_datagrams_to_the_new_anchor(carrier: Carrier) -> Result<()> {
    let (upstream, sources) = spawn_udp_echo().await?;
    let server = setup_ss_udp_h3_server(true).await?;

    let (first, issued) = connect_with_resume(&server, carrier, None).await?;
    let session_id = issued.context("server minted no Session ID")?;
    round_trip(&first, upstream, &payload(SMALL_PAYLOAD, 11)).await?;
    let up_before = server.counter(SERVER_DATAGRAMS, &[UP, SS]);
    let down_before = server.counter(SERVER_DATAGRAMS, &[DOWN, SS]);
    assert!(up_before >= 1.0 && down_before >= 1.0, "first anchor did not use datagrams");

    // Drop the anchor; the server parks the NAT keys under the Session ID.
    first.close().await?;
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.orphans.len() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "the dropped anchor was never parked");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (second, _) = connect_with_resume(&server, carrier, Some(session_id)).await?;
    round_trip(&second, upstream, &payload(SMALL_PAYLOAD, 13)).await?;

    assert_eq!(server.counter(SERVER_SESSIONS, &[("state", "negotiated")]), 2.0);
    assert!(server.counter(SERVER_DATAGRAMS, &[UP, SS]) > up_before, "no uplink datagram");
    assert!(
        server.counter(SERVER_DATAGRAMS, &[DOWN, SS]) > down_before,
        "no downlink datagram"
    );
    assert_eq!(server.counter(SERVER_FALLBACK, &[DOWN, SS]), 0.0);
    assert_eq!(
        sources.lock().await.len(),
        1,
        "resume must keep the parked NAT socket: the upstream saw a second source"
    );

    second.close().await?;
    Ok(())
}

macro_rules! carrier_tests {
    ($($module:ident => $carrier:expr),+ $(,)?) => {$(
        mod $module {
            use super::*;

            #[tokio::test]
            async fn small_packets_ride_h3_datagrams_both_ways() -> Result<()> {
                super::small_packets_ride_h3_datagrams_both_ways($carrier).await
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
            async fn resume_moves_datagrams_to_the_new_anchor() -> Result<()> {
                super::resume_moves_datagrams_to_the_new_anchor($carrier).await
            }
        }
    )+};
}

carrier_tests! {
    ws_h3 => Carrier::WsH3,
    xhttp_h3_packet_up => Carrier::XhttpPacketUp,
    xhttp_h3_stream_one => Carrier::XhttpStreamOne,
}
