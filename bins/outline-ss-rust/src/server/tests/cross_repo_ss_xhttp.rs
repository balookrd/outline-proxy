//! Cross-repo end-to-end tests for Shadowsocks-over-XHTTP (forward
//! path). The client side is exercised through the same dial entry the
//! real `outline-ws-rust` proxy uses — `connect_websocket_with_resume`
//! returns the XHTTP `TransportStream`, on top of which we run the SS
//! AEAD writer/reader exactly like `do_tcp_ss_setup` does. The server
//! side runs the real axum `build_app` router with an `xhttp_ss` route,
//! so the request lands in the SS branch of `spawn_relay` and is served
//! by `run_tcp_relay` — the same relay the SS-over-WS path uses.
//!
//! This pins the one seam unit tests cannot reach: that an XHTTP base
//! path tagged `Ss` actually decrypts an SS stream and relays it to the
//! upstream, end to end, over both packet-up and stream-one carriers.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use url::Url;

use outline_transport::{
    DnsCache as ClientDnsCache, SsPathKind, TcpShadowsocksReader, TcpShadowsocksWriter,
    TransportDialOptions, TransportMode, UdpWsTransport, UpstreamTransportGuard, connect_transport,
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::setup::{SsXhttpUserRoute, build_xhttp_ss_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_app};
use super::connect_websocket_with_resume;
use super::sample_config;
use crate::config::CipherKind;
use crate::crypto::UserKey;
use crate::metrics::Metrics;

const TEST_CIPHER: CipherKind = CipherKind::Chacha20IetfPoly1305;
const TEST_PASSWORD: &str = "ss-over-xhttp-secret";

/// Stand up a server whose only route is an SS-over-XHTTP base path,
/// authenticated by a single `UserKey` derived from `TEST_PASSWORD`.
/// `udp = false` registers the base on the TCP path (`xhttp_ss`);
/// `udp = true` registers it on the UDP path (`xhttp_ss_udp`).
async fn setup_ss_xhttp_server(
    base_path: &'static str,
    udp: bool,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let user = UserKey::new("ss-xhttp-user".to_string(), TEST_PASSWORD, None, TEST_CIPHER, None)?;
    let ss_routes = Arc::new(build_xhttp_ss_route_map(&[SsXhttpUserRoute {
        user,
        xhttp_path: Arc::from(base_path),
    }]));
    let empty = Arc::new(BTreeMap::new());
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss: if udp {
            Arc::clone(&empty)
        } else {
            Arc::clone(&ss_routes)
        },
        xhttp_ss_udp: if udp { ss_routes } else { empty },
    }));
    let services = Arc::new(Services::new(
        metrics,
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        None,
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None, None);
    let handle =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    Ok((listen_addr, handle))
}

/// SOCKS5 address header (ipv4) + payload — the first SS chunk shape the
/// server's `parse_target_addr` expects right after the salt.
fn ss_first_chunk(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.push(0x01); // ATYP = IPv4
    match target.ip() {
        std::net::IpAddr::V4(v4) => chunk.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => unreachable!("test upstream is always ipv4"),
    }
    chunk.extend_from_slice(&target.port().to_be_bytes());
    chunk.extend_from_slice(payload);
    chunk
}

/// Drive one SS-over-XHTTP round trip against an echo upstream on the
/// given XHTTP carrier mode (selected via the dial URL's `?mode=`).
async fn ss_xhttp_round_trip(url: Url) -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-ss-test",
        None,
        false,
        false,
        0,
    )
    .await?;

    // Layer the SS AEAD stream on top of the XHTTP carrier, exactly as
    // the real client's `do_tcp_ss_setup` does.
    let master_key = TEST_CIPHER.derive_master_key(TEST_PASSWORD)?;
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss-test", "tcp");
    let (sink, source) = stream.split();
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(sink, TEST_CIPHER, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(source, TEST_CIPHER, &master_key, lifetime, ctrl_tx)
        .with_request_salt(request_salt);

    writer.send_chunk(&ss_first_chunk(upstream_addr, b"ping")).await?;

    let mut echoed = Vec::new();
    while echoed.len() < 4 {
        let chunk = reader.read_chunk().await?;
        if chunk.is_empty() {
            break;
        }
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(&echoed[..4], b"pong", "SS-over-XHTTP downlink echo");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping", "SS-over-XHTTP uplink reached upstream");

    drop(writer);
    drop(reader);
    Ok(())
}

#[tokio::test]
async fn cross_repo_ss_xhttp_packet_up_h2_round_trip() -> Result<()> {
    let (listen_addr, server) = setup_ss_xhttp_server("/ssx", false).await?;
    let url = Url::parse(&format!("http://{listen_addr}/ssx"))?;
    let result = ss_xhttp_round_trip(url).await;
    server.abort();
    result
}

#[tokio::test]
async fn cross_repo_ss_xhttp_stream_one_h2_round_trip() -> Result<()> {
    let (listen_addr, server) = setup_ss_xhttp_server("/ssx", false).await?;
    // Stream-one is selected entirely by `?mode=stream-one` on the dial
    // URL — both sides parse the query, no second config knob.
    let url = Url::parse(&format!("http://{listen_addr}/ssx?mode=stream-one"))?;
    let result = ss_xhttp_round_trip(url).await;
    server.abort();
    result
}

/// SS-UDP-over-XHTTP packet-up round trip. The client uses the same
/// `UdpWsTransport` the real proxy dials with — its datagram channel
/// rides the XHTTP carrier (`from_ws_datagrams` over the XHTTP
/// `TransportStream`). The server routes the base on `xhttp_ss_udp`,
/// so `spawn_relay` runs `run_udp_relay` over `XhttpDuplex`.
#[tokio::test]
async fn cross_repo_ss_udp_xhttp_packet_up_h2_round_trip() -> Result<()> {
    // UDP echo upstream: reply with the same bytes to the sender.
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        let (n, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..n], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..n].to_vec())
    });

    let (listen_addr, server) = setup_ss_xhttp_server("/ssu", true).await?;
    let url = Url::parse(&format!("http://{listen_addr}/ssu"))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let transport = UdpWsTransport::connect(
        &cache,
        &url,
        TransportMode::XhttpH2,
        TEST_CIPHER,
        TEST_PASSWORD,
        None,
        false,
        "cross-repo-ss-udp-test",
        None,
        // Split UDP path in this test, so no combined-path discriminator.
        None,
    )
    .await?;

    // SS-UDP datagram payload = SOCKS5 target header + data; the transport
    // encrypts it as one packet.
    transport.send_packet(&ss_first_chunk(upstream_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    // The downlink datagram is `[SOCKS5 source-addr][echoed data]`; the
    // echoed payload is the trailing bytes.
    assert!(reply.ends_with(b"ping"), "SS-UDP-over-XHTTP downlink echo: {reply:?}");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping", "SS-UDP-over-XHTTP uplink reached upstream");

    transport.close().await?;
    server.abort();
    Ok(())
}

/// Stand up a server whose single base path is *combined*: registered in BOTH
/// the `xhttp_ss` and `xhttp_ss_udp` tables, so `build_app` tags it
/// `SsCombined` and the server picks the tcp or udp relay from the hidden bit
/// in each request's session id.
async fn setup_ss_combined_xhttp_server(
    base_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let user =
        UserKey::new("ss-combined-user".to_string(), TEST_PASSWORD, None, TEST_CIPHER, None)?;
    let ss_routes = Arc::new(build_xhttp_ss_route_map(&[SsXhttpUserRoute {
        user,
        xhttp_path: Arc::from(base_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        // Same route map under both keys → the base path is combined.
        xhttp_ss: Arc::clone(&ss_routes),
        xhttp_ss_udp: ss_routes,
    }));
    let services = Arc::new(Services::new(
        metrics,
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        None,
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None, None);
    let handle =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    Ok((listen_addr, handle))
}

/// The defining combined-path test: one server, one base path, both legs.
/// The TCP leg dials with the TCP discriminator and must land on the TCP
/// relay; the UDP leg dials the *same path* with the UDP discriminator and
/// must land on the UDP relay. Proves the session-id bit alone splits the two
/// on a shared base path.
#[tokio::test]
async fn cross_repo_ss_combined_xhttp_both_legs_one_path() -> Result<()> {
    let (listen_addr, server) = setup_ss_combined_xhttp_server("/ssc").await?;
    let url = Url::parse(&format!("http://{listen_addr}/ssc"))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));

    // ── TCP leg ──────────────────────────────────────────────────────────
    let tcp_upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let tcp_upstream_addr = tcp_upstream.local_addr()?;
    let tcp_upstream_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let options = TransportDialOptions::new(&cache, &url, TransportMode::XhttpH2, "combined-tcp")
        .with_combined_ss_kind(Some(SsPathKind::Tcp));
    let stream = connect_transport(options).await?;
    let master_key = TEST_CIPHER.derive_master_key(TEST_PASSWORD)?;
    let lifetime = UpstreamTransportGuard::new("combined-tcp", "tcp");
    let (sink, source) = stream.split();
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(sink, TEST_CIPHER, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(source, TEST_CIPHER, &master_key, lifetime, ctrl_tx)
        .with_request_salt(request_salt);
    writer.send_chunk(&ss_first_chunk(tcp_upstream_addr, b"ping")).await?;
    let mut echoed = Vec::new();
    while echoed.len() < 4 {
        let chunk = reader.read_chunk().await?;
        if chunk.is_empty() {
            break;
        }
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(&echoed[..4], b"pong", "combined TCP leg downlink echo");
    let tcp_bytes = tokio::time::timeout(Duration::from_secs(5), tcp_upstream_task).await???;
    assert_eq!(&tcp_bytes, b"ping", "combined TCP leg reached the TCP upstream");
    drop(writer);
    drop(reader);

    // ── UDP leg, SAME base path ──────────────────────────────────────────
    let udp_upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let udp_upstream_addr = udp_upstream.local_addr()?;
    let udp_upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        let (n, peer) = udp_upstream.recv_from(&mut buf).await?;
        udp_upstream.send_to(&buf[..n], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..n].to_vec())
    });

    let transport = UdpWsTransport::connect(
        &cache,
        &url,
        TransportMode::XhttpH2,
        TEST_CIPHER,
        TEST_PASSWORD,
        None,
        false,
        "combined-udp",
        None,
        Some(SsPathKind::Udp),
    )
    .await?;
    transport
        .send_packet(&ss_first_chunk(udp_upstream_addr, b"ping"))
        .await?;
    let reply = transport.read_packet().await?;
    assert!(reply.ends_with(b"ping"), "combined UDP leg downlink echo: {reply:?}");
    let udp_bytes = tokio::time::timeout(Duration::from_secs(5), udp_upstream_task).await???;
    assert_eq!(&udp_bytes, b"ping", "combined UDP leg reached the UDP upstream");

    transport.close().await?;
    server.abort();
    Ok(())
}
