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
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

use outline_transport::{
    DnsCache as ClientDnsCache, TcpShadowsocksReader, TcpShadowsocksWriter, TransportMode,
    UpstreamTransportGuard,
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
async fn setup_ss_xhttp_server(
    base_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let user = UserKey::new("ss-xhttp-user".to_string(), TEST_PASSWORD, None, TEST_CIPHER)?;
    let ss_routes = Arc::new(build_xhttp_ss_route_map(&[SsXhttpUserRoute {
        user,
        xhttp_path: Arc::from(base_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss: ss_routes,
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
    let app = build_app(routes, services, auth, None);
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
    let (listen_addr, server) = setup_ss_xhttp_server("/ssx").await?;
    let url = Url::parse(&format!("http://{listen_addr}/ssx"))?;
    let result = ss_xhttp_round_trip(url).await;
    server.abort();
    result
}

#[tokio::test]
async fn cross_repo_ss_xhttp_stream_one_h2_round_trip() -> Result<()> {
    let (listen_addr, server) = setup_ss_xhttp_server("/ssx").await?;
    // Stream-one is selected entirely by `?mode=stream-one` on the dial
    // URL — both sides parse the query, no second config knob.
    let url = Url::parse(&format!("http://{listen_addr}/ssx?mode=stream-one"))?;
    let result = ss_xhttp_round_trip(url).await;
    server.abort();
    result
}
