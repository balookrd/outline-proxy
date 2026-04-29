//! End-to-end tests for the XHTTP packet-up VLESS path.
//!
//! Drives the full server stack: client opens a long-lived GET on
//! `/<base>/<session-id>` to attach the downlink, fires one or
//! more sequenced POSTs to feed the uplink, and observes that the
//! VLESS relay correctly proxies bytes to a local TCP echo server.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::setup::{VlessXhttpUserRoute, build_xhttp_vless_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_app};
use super::sample_config;
use crate::metrics::Metrics;
use crate::protocol::vless::{COMMAND_TCP, VERSION, VlessUser, parse_uuid};

const TEST_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

async fn setup_xhttp_server(
    base_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let xhttp_routes = Arc::new(build_xhttp_vless_route_map(&[VlessXhttpUserRoute {
        user: vless_user,
        xhttp_path: Arc::from(base_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: xhttp_routes,
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
            Vec::<crate::crypto::UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

fn build_vless_tcp_handshake(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut req = Vec::new();
    req.push(VERSION);
    req.extend_from_slice(&parse_uuid(TEST_UUID)?);
    req.push(0); // no addons
    req.push(COMMAND_TCP);
    req.extend_from_slice(&target.port().to_be_bytes());
    let octets = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => bail!("test expects ipv4 upstream"),
    };
    req.push(0x01); // ipv4
    req.extend_from_slice(&octets);
    req.extend_from_slice(payload);
    Ok(req)
}

fn http_client() -> Client<HttpConnector, Full<Bytes>> {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn read_body_until_at_least(
    body: &mut hyper::body::Incoming,
    expected: usize,
) -> Result<Bytes> {
    let mut received = BytesMut::new();
    while received.len() < expected {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    received.extend_from_slice(&data);
                }
            },
            Some(Err(error)) => return Err(anyhow!(error)),
            None => break,
        }
    }
    Ok(received.freeze())
}

#[tokio::test]
async fn xhttp_packet_up_tcp_echo_round_trip() -> Result<()> {
    // Echo upstream: read 4 bytes of "ping", reply "pong".
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "smoke-session-001";
    let url = format!("http://{listen_addr}/xh/{session_id}");

    // Open GET first so the downlink has a consumer ready.
    let get_url = url.clone();
    let get_client = client.clone();
    let get_handle = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_url)
            .body(Full::new(Bytes::new()))?;
        let resp = get_client.request(req).await?;
        if resp.status() != StatusCode::OK {
            bail!("GET status {}", resp.status());
        }
        // Masquerade headers and X-Padding must be present.
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if content_type != "text/event-stream" {
            bail!("unexpected content-type: {content_type:?}");
        }
        if !resp.headers().contains_key("x-padding") {
            bail!("missing x-padding header");
        }
        let mut body = resp.into_body();
        // VLESS response header (2) + "pong" (4) = 6 bytes.
        let bytes = read_body_until_at_least(&mut body, 6).await?;
        Result::<_, anyhow::Error>::Ok(bytes)
    });

    // Give GET enough time to register the session and attach the
    // downlink slot before the POST creates a relay race.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // POST seq=0 carrying the VLESS handshake + "ping".
    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    let post_req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .header("x-xhttp-seq", "0")
        .body(Full::new(Bytes::from(handshake)))?;
    let post_resp = client.request(post_req).await?;
    assert_eq!(post_resp.status(), StatusCode::OK);
    assert!(post_resp.headers().contains_key("x-padding"));

    let received_upstream = tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await???;
    assert_eq!(&received_upstream, b"ping");

    let downlink = tokio::time::timeout(Duration::from_secs(5), get_handle).await???;
    assert_eq!(&downlink[..2], &[VERSION, 0x00], "vless response header");
    assert_eq!(&downlink[2..6], b"pong", "echoed payload");

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_post_to_unknown_session_with_seq_above_zero_returns_gone() -> Result<()> {
    let (listen_addr, server) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let url = format!("http://{listen_addr}/xh/no-such-session-zzz");

    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .header("x-xhttp-seq", "1")
        .body(Full::new(Bytes::from_static(b"junk")))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::GONE);

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_concurrent_get_returns_conflict() -> Result<()> {
    let (listen_addr, server) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "dup-get-session";
    let url = format!("http://{listen_addr}/xh/{session_id}");

    // First GET attaches the downlink and stays open.
    let first_url = url.clone();
    let first_client = client.clone();
    let first_get = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&first_url)
            .body(Full::new(Bytes::new()))?;
        let resp = first_client.request(req).await?;
        Result::<_, anyhow::Error>::Ok(resp)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second GET on the same id must be rejected with 409.
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Full::new(Bytes::new()))?;
    let dup_resp = client.request(req).await?;
    assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

    let _first = first_get.await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_uplink_reorder_buffers_out_of_order_posts() -> Result<()> {
    // Echo upstream that returns whatever it gets.
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 6];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"ack").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "reorder-session";
    let url = format!("http://{listen_addr}/xh/{session_id}");

    let get_url = url.clone();
    let get_client = client.clone();
    let get_handle = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_url)
            .body(Full::new(Bytes::new()))?;
        let resp = get_client.request(req).await?;
        let mut body = resp.into_body();
        let bytes = read_body_until_at_least(&mut body, 5).await?;
        Result::<_, anyhow::Error>::Ok(bytes)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The uplink will be split: handshake (seq=0), then payload "abc"
    // (seq=1), then payload "def" (seq=2). We send seq=2 *first* so
    // the server has to park it in the reorder buffer until 0 and 1
    // arrive.
    let handshake = build_vless_tcp_handshake(upstream_addr, b"")?;
    let post_seq = |seq: u64, body: Vec<u8>| {
        let url = url.clone();
        let client = client.clone();
        async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri(&url)
                .header("x-xhttp-seq", seq.to_string())
                .body(Full::new(Bytes::from(body)))?;
            let resp = client.request(req).await?;
            Result::<_, anyhow::Error>::Ok(resp.status())
        }
    };

    let r2 = post_seq(2, b"def".to_vec()).await?;
    assert_eq!(r2, StatusCode::OK);
    let r1 = post_seq(1, b"abc".to_vec()).await?;
    assert_eq!(r1, StatusCode::OK);
    let r0 = post_seq(0, handshake).await?;
    assert_eq!(r0, StatusCode::OK);

    // Upstream should observe exactly "abcdef" — 3 bytes from
    // seq=1 plus 3 bytes from seq=2, in that order, after the
    // server unblocks the reorder buffer with seq=0's handshake.
    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await???;
    assert_eq!(&upstream_bytes, b"abcdef");

    let downlink = tokio::time::timeout(Duration::from_secs(5), get_handle).await???;
    assert_eq!(&downlink[..2], &[VERSION, 0x00]);
    assert_eq!(&downlink[2..5], b"ack");

    server.abort();
    Ok(())
}
