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
use http_body_util::{StreamBody, combinators::BoxBody};
use std::convert::Infallible;
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
use super::super::transport::XhttpRegistry;
use super::super::{DnsCache, build_app};
use super::sample_config;
use crate::metrics::Metrics;
use crate::protocol::vless::{COMMAND_TCP, VERSION, VlessUser, parse_uuid};

pub(super) const TEST_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

pub(super) async fn setup_xhttp_server(
    base_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>, Arc<XhttpRegistry>)> {
    setup_xhttp_server_with_resumption(base_path, false).await
}

pub(super) async fn setup_xhttp_server_with_resumption(
    base_path: &'static str,
    resumption: bool,
) -> Result<(SocketAddr, JoinHandle<Result<()>>, Arc<XhttpRegistry>)> {
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
    // Build a real `OrphanRegistry` when resumption is requested so
    // `from_request_headers` mints a Session ID. Without this the
    // registry is the disabled stub and the resume round-trip is a
    // silent no-op (no `X-Outline-Session` ever appears).
    let orphan_registry = if resumption {
        Some(Arc::new(super::super::resumption::OrphanRegistry::new(
            super::super::resumption::ResumptionConfig::from(&crate::config::SessionResumptionConfig {
                enabled: true,
                orphan_ttl_tcp_secs: 30,
                orphan_ttl_udp_secs: 30,
                orphan_per_user_cap: 4,
                orphan_global_cap: 16,
            }),
            Arc::clone(&metrics),
        )))
    } else {
        None
    };
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
        orphan_registry,
        16,
    ));
    let xhttp_registry = Arc::clone(&services.xhttp_registry);
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<crate::crypto::UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle, xhttp_registry))
}

pub(super) fn build_vless_tcp_handshake(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
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

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
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
async fn xhttp_packet_up_path_based_seq_round_trip() -> Result<()> {
    // xray / sing-box default placement puts the per-packet seq into
    // the URL path (`<base>/<id>/<seq>`) rather than the
    // `X-Xhttp-Seq` header. Without the second axum route this POST
    // 404s and the client retries forever — the regression that
    // surfaced as `happ` timing out on every XHTTP test connection.
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "xray-style-session-001";
    let get_url = format!("http://{listen_addr}/xh/{session_id}");

    let get_client = client.clone();
    let get_url_for_task = get_url.clone();
    let get_handle = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_url_for_task)
            .body(Full::new(Bytes::new()))?;
        let resp = get_client.request(req).await?;
        if resp.status() != StatusCode::OK {
            bail!("GET status {}", resp.status());
        }
        let mut body = resp.into_body();
        let bytes = read_body_until_at_least(&mut body, 6).await?;
        Result::<_, anyhow::Error>::Ok(bytes)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // POST goes to `<base>/<id>/<seq>` with NO `X-Xhttp-Seq` header.
    // The server must pull the seq from the URL path.
    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    let post_url = format!("http://{listen_addr}/xh/{session_id}/0");
    let post_req = Request::builder()
        .method(Method::POST)
        .uri(&post_url)
        .body(Full::new(Bytes::from(handshake)))?;
    let post_resp = client.request(post_req).await?;
    assert_eq!(
        post_resp.status(),
        StatusCode::OK,
        "path-based seq POST must succeed without X-Xhttp-Seq"
    );

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
async fn xhttp_path_based_seq_overrides_header_seq() -> Result<()> {
    // When a client supplies *both* a path-based seq and a header
    // seq, the server must pick the path one. This pins the rule
    // that path-based wins, so a future refactor cannot silently
    // flip the precedence and break xray clients that happen to
    // also include the header.
    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "both-seq-session-001";

    // POST seq=1 on the URL but seq=99 in the header. seq=1 against
    // a fresh session id (no GET yet, no prior POST) means the
    // session does not exist yet → server should answer 410 GONE
    // (because seq != 0). If the server picked the header (99), it
    // would behave identically here, so use a follow-up: send seq=0
    // first to create the session, then seq=1 with header seq=42 →
    // server must accept (path seq=1 is the next-in-order packet).
    let url_seq0 = format!("http://{listen_addr}/xh/{session_id}/0");
    let req0 = Request::builder()
        .method(Method::POST)
        .uri(&url_seq0)
        .header("x-xhttp-seq", "999") // server must ignore in favour of path
        .body(Full::new(Bytes::from_static(b"")))?;
    let resp0 = client.request(req0).await?;
    assert_eq!(resp0.status(), StatusCode::OK, "seq=0 from path creates the session");

    // Now seq=1 from path, but header says seq=999. The server must
    // honour the path seq (so the in-order check succeeds), not the
    // header.
    let url_seq1 = format!("http://{listen_addr}/xh/{session_id}/1");
    let req1 = Request::builder()
        .method(Method::POST)
        .uri(&url_seq1)
        .header("x-xhttp-seq", "999")
        .body(Full::new(Bytes::from_static(b"")))?;
    let resp1 = client.request(req1).await?;
    assert_eq!(resp1.status(), StatusCode::OK, "seq=1 from path is accepted next-in-order");

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_path_based_get_returns_bad_request() -> Result<()> {
    // `<base>/<id>/<seq>` is uplink-only — a GET on this shape is a
    // misrouted client. The handler must reject it with 400 instead
    // of accidentally creating a session through the GET branch.
    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let url = format!("http://{listen_addr}/xh/some-session-000/0");

    let req = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Full::new(Bytes::new()))?;
    let resp = client.request(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_path_based_seq_non_numeric_returns_404() -> Result<()> {
    // `<base>/<id>/<not-a-number>` does not match the path-seq route
    // (axum's `Path<(String, u64)>` extractor fails on non-numeric)
    // and also does not match the plain `<base>/<id>` route (extra
    // path segment). The request falls through to the global
    // not-found handler, returning 404 — so a stray client typo
    // does not silently land on a packet-up POST.
    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let url = format!("http://{listen_addr}/xh/some-session-000/not-a-number");

    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .body(Full::new(Bytes::from_static(b"x")))?;
    let resp = client.request(req).await?;
    assert!(
        matches!(resp.status(), StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST),
        "expected 404 / 400 for non-numeric seq, got {}",
        resp.status(),
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_post_to_unknown_session_with_seq_above_zero_returns_gone() -> Result<()> {
    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
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
    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
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
async fn xhttp_resume_capable_get_returns_session_header_and_reattach_keeps_it() -> Result<()> {
    let (listen_addr, server, _registry) = setup_xhttp_server_with_resumption("/xh", true).await?;
    let client = http_client();
    let session_id = "resume-session-001";
    let url = format!("http://{listen_addr}/xh/{session_id}");

    // First GET: client advertises Resume-Capable and the server
    // mints a Session ID, surfacing it on the response.
    let first_url = url.clone();
    let first_client = client.clone();
    let first_get = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&first_url)
            .header("x-outline-resume-capable", "1")
            .body(Full::new(Bytes::new()))?;
        let resp = first_client.request(req).await?;
        let session = resp
            .headers()
            .get("x-outline-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        Result::<_, anyhow::Error>::Ok(session)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first_session = tokio::time::timeout(Duration::from_secs(5), first_get).await???;
    let token = first_session.ok_or_else(|| {
        anyhow!("server did not surface X-Outline-Session on the resume-capable GET")
    })?;
    assert_eq!(token.len(), 32, "expected 16-byte hex Session ID");

    // Subsequent POST seq=0 must surface the same token (the
    // session was created by the GET above and the POST attaches
    // to it). The client uses this round-trip to confirm both sides
    // see the same token before sending its first VLESS frame.
    let post_resp = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(&url)
                .header("x-xhttp-seq", "0")
                .body(Full::new(Bytes::from_static(b"x")))?,
        )
        .await?;
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_token = post_resp
        .headers()
        .get("x-outline-session")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or_else(|| anyhow!("POST response missing X-Outline-Session"))?;
    assert_eq!(post_token, token, "attach POST must surface the same minted token");

    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_stream_one_full_duplex_round_trip() -> Result<()> {
    use http_body_util::BodyExt;

    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    // Drive the request via a direct HTTP/2 handshake so the
    // server actually sees an h2 connection. hyper-util's legacy
    // Client speaks h1 over plain TCP unless TLS-ALPN negotiates
    // h2, which is exactly the situation stream-one rejects with
    // 505. Using the lower-level handshake matches the wire-form
    // a real `xhttp_h2` client would produce.
    let session_id = "stream-one-001";
    let target_uri = format!("http://{listen_addr}/xh/{session_id}?mode=stream-one");

    let tcp = tokio::net::TcpStream::connect(listen_addr).await?;
    let (mut send, conn) = hyper::client::conn::http2::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    )
    .handshake::<_, BoxBody<Bytes, Infallible>>(hyper_util::rt::TokioIo::new(tcp))
    .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Drive the request body through a channel so we can hold the
    // uplink half open while reading the response. Closing the body
    // immediately after the handshake would let the server-side
    // `close_uplink()` race the relay's first VLESS frame and
    // tear the session down before the upstream reply makes it
    // back through the downlink.
    let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<
        Result<hyper::body::Frame<Bytes>, Infallible>,
    >(8);
    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    frame_tx
        .send(Ok(hyper::body::Frame::data(Bytes::from(handshake))))
        .await?;
    let body_stream = futures_util::stream::unfold(frame_rx, |mut rx| async move {
        rx.recv().await.map(|frame| (frame, rx))
    });
    let stream_body = StreamBody::new(body_stream).boxed();
    let req = Request::builder()
        .method(Method::POST)
        .uri(&target_uri)
        .header(hyper::header::HOST, format!("{}", listen_addr))
        .body(stream_body)?;
    send.ready().await?;
    let resp = send.send_request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/event-stream"),
    );
    let mut body = resp.into_body();
    let mut received = bytes::BytesMut::new();
    while received.len() < 6 {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    received.extend_from_slice(&data);
                }
            },
            Some(Err(e)) => bail!("frame error: {e}"),
            None => break,
        }
    }
    assert_eq!(&received[..2], &[VERSION, 0x00]);
    assert_eq!(&received[2..6], b"pong");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await???;
    assert_eq!(&upstream_bytes, b"ping");

    // Now close the uplink half so the relay sees EOF and the
    // server-side handler can shut down cleanly.
    drop(frame_tx);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_stream_one_xray_style_no_mode_query_round_trip() -> Result<()> {
    // xray / sing-box / `happ` clients dial stream-one with NO
    // `?mode=stream-one` selector on the wire — the carrier is
    // implied by the URL shape (`<base>/<id>` with no seq segment)
    // plus the HTTP method (POST). The server must auto-detect and
    // dispatch to the stream-one handler instead of bouncing the
    // request as a packet-up POST without a seq → 400.
    use http_body_util::BodyExt;

    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
    let session_id = "stream-one-xray-001";
    // No `?mode=...` query — that's the wire shape xray emits.
    let target_uri = format!("http://{listen_addr}/xh/{session_id}");

    let tcp = tokio::net::TcpStream::connect(listen_addr).await?;
    let (mut send, conn) = hyper::client::conn::http2::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    )
    .handshake::<_, BoxBody<Bytes, Infallible>>(hyper_util::rt::TokioIo::new(tcp))
    .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<
        Result<hyper::body::Frame<Bytes>, Infallible>,
    >(8);
    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    frame_tx
        .send(Ok(hyper::body::Frame::data(Bytes::from(handshake))))
        .await?;
    let body_stream = futures_util::stream::unfold(frame_rx, |mut rx| async move {
        rx.recv().await.map(|frame| (frame, rx))
    });
    let stream_body = StreamBody::new(body_stream).boxed();
    // POST with no seq (path or header) — must NOT be 400'd as a
    // missing-seq packet-up POST. Server auto-detects stream-one.
    let req = Request::builder()
        .method(Method::POST)
        .uri(&target_uri)
        .header(hyper::header::HOST, format!("{}", listen_addr))
        .body(stream_body)?;
    send.ready().await?;
    let resp = send.send_request(req).await?;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST without seq must auto-dispatch to stream-one (not 400)",
    );
    assert_eq!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/event-stream"),
        "stream-one response masquerade headers expected",
    );
    let mut body = resp.into_body();
    let mut received = bytes::BytesMut::new();
    while received.len() < 6 {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    received.extend_from_slice(&data);
                }
            },
            Some(Err(e)) => bail!("frame error: {e}"),
            None => break,
        }
    }
    assert_eq!(&received[..2], &[VERSION, 0x00]);
    assert_eq!(&received[2..6], b"pong");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(frame_tx);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn xhttp_resume_reattaches_to_parked_upstream_across_sessions() -> Result<()> {
    // Echo upstream that accepts ONE TCP connection and serves
    // both XHTTP sessions through it. If resumption works the
    // second XHTTP session re-attaches to the parked writer/reader
    // for this socket; if it does not, this `accept` only completes
    // once and the second session would either hang or open a new
    // upstream that the test would notice through a second accept.
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut first = [0_u8; 4];
        stream.read_exact(&mut first).await?;
        stream.write_all(b"pong").await?;
        let mut second = [0_u8; 4];
        stream.read_exact(&mut second).await?;
        stream.write_all(b"ackk").await?;
        Result::<_, anyhow::Error>::Ok((first, second))
    });

    let (listen_addr, server, _registry) = setup_xhttp_server_with_resumption("/xh", true).await?;
    let client = http_client();

    // ── Session A: capability-advertise, run a real handshake,
    //    push `ping` plus FIN so the server-side relay sees uplink
    //    EOF and parks the upstream ──────────────────────────────
    let session_a_id = "resume-test-session-a";
    let url_a = format!("http://{listen_addr}/xh/{session_a_id}");

    // Open GET first so the response stream can deliver the VLESS
    // header and the upstream echo before the relay parks.
    let get_a_url = url_a.clone();
    let get_a_client = client.clone();
    let get_a = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_a_url)
            .header("x-outline-resume-capable", "1")
            .body(Full::new(Bytes::new()))?;
        let resp = get_a_client.request(req).await?;
        let issued = resp
            .headers()
            .get("x-outline-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let mut body = resp.into_body();
        let bytes = read_body_until_at_least(&mut body, 6).await?;
        Result::<_, anyhow::Error>::Ok((issued, bytes))
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let handshake_a = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    // Note: NO `X-Xhttp-Fin` here. Closing the uplink in the same
    // POST that opens the connection would race the relay's
    // upstream-reader task — by the time the reader picks up
    // `pong` from the echo socket the relay's main loop has
    // already seen `uplink_eof` and broken out, cancelling the
    // reader without forwarding the reply.
    let post_a = Request::builder()
        .method(Method::POST)
        .uri(&url_a)
        .header("x-xhttp-seq", "0")
        .body(Full::new(Bytes::from(handshake_a)))?;
    let post_a_resp = client.request(post_a).await?;
    assert_eq!(post_a_resp.status(), StatusCode::OK);

    let (issued_a, downlink_a) =
        tokio::time::timeout(Duration::from_secs(5), get_a).await???;
    assert_eq!(&downlink_a[..2], &[VERSION, 0x00], "vless response header on A");
    assert_eq!(&downlink_a[2..6], b"pong", "echo reply on A");
    let token = issued_a
        .ok_or_else(|| anyhow!("session A did not surface X-Outline-Session"))?;
    assert_eq!(token.len(), 32);

    // Now that `pong` has reached the client, send a separate
    // empty FIN POST to close the uplink half. The relay then
    // breaks out of the read loop and the cleanup path parks the
    // live upstream into the orphan registry under `token`.
    let fin_a = Request::builder()
        .method(Method::POST)
        .uri(&url_a)
        .header("x-xhttp-seq", "1")
        .header("x-xhttp-fin", "1")
        .body(Full::new(Bytes::new()))?;
    let fin_a_resp = client.request(fin_a).await?;
    assert_eq!(fin_a_resp.status(), StatusCode::OK);

    // The relay needs a moment to break out of its read loop and
    // shove the upstream into the orphan registry. Without this
    // sleep the resume on session B can race the park and miss it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Session B: brand-new path id, presents the prior token
    //    as `X-Outline-Resume`. The server should re-attach to the
    //    parked upstream instead of opening a new TCP connection ──
    let session_b_id = "resume-test-session-b";
    let url_b = format!("http://{listen_addr}/xh/{session_b_id}");

    let get_b_url = url_b.clone();
    let get_b_client = client.clone();
    let token_for_get = token.clone();
    let get_b = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_b_url)
            .header("x-outline-resume-capable", "1")
            .header("x-outline-resume", token_for_get.as_str())
            .body(Full::new(Bytes::new()))?;
        let resp = get_b_client.request(req).await?;
        let issued_b = resp
            .headers()
            .get("x-outline-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let mut body = resp.into_body();
        let bytes = read_body_until_at_least(&mut body, 6).await?;
        Result::<_, anyhow::Error>::Ok((issued_b, bytes))
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The handshake target is irrelevant to the resume path —
    // server uses the parked writer/reader and never reads
    // the target field — but the VLESS parser still needs a
    // syntactically valid one. We send `helo` as the next
    // payload so the test can distinguish the two echoes.
    //
    // Crucially, we do NOT set `X-Xhttp-Fin` here: closing the
    // uplink makes the relay break out of its read loop the
    // moment the handshake-and-leftover frame is consumed, and
    // the upstream-reader task is then cancelled before it can
    // forward `ackk` back into the downlink. Keeping the uplink
    // open lets the response complete; the test relies on the
    // downlink frame arrival to finish, then drops the request
    // futures (which closes everything cleanly).
    let handshake_b = build_vless_tcp_handshake(upstream_addr, b"helo")?;
    let post_b = Request::builder()
        .method(Method::POST)
        .uri(&url_b)
        .header("x-xhttp-seq", "0")
        .header("x-outline-resume", token.as_str())
        .body(Full::new(Bytes::from(handshake_b)))?;
    let post_b_resp = client.request(post_b).await?;
    assert_eq!(post_b_resp.status(), StatusCode::OK);

    let (issued_b, downlink_b) =
        tokio::time::timeout(Duration::from_secs(5), get_b).await???;
    // Session B mints its own resume token (the server cannot
    // know the request is a resume until it sees the VLESS
    // handshake), but its presence on the response is incidental
    // for this test — the assertion is the upstream payload.
    let _ = issued_b;
    assert_eq!(&downlink_b[..2], &[VERSION, 0x00], "vless response header on B");
    assert_eq!(&downlink_b[2..6], b"ackk", "echo reply on B (via resumed upstream)");

    // The upstream future completes only once both `read_exact`
    // calls have been served. If resumption did NOT work, the
    // second session would have opened a fresh TCP connection
    // and this `accept` would still be waiting (the first
    // upstream socket would already be closed from session A's
    // teardown), causing `read_exact(&mut second)` to never fire.
    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

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

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;
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

#[tokio::test]
async fn xhttp_get_drop_then_reconnect_resumes_downlink_ring() -> Result<()> {
    // Pins the documented "GET dropped mid-flight does not tear
    // the session down; the next GET on the same path id reads
    // bytes pushed after the disconnect" contract from xhttp/mod.rs.
    //
    // The session is pre-created via the registry so the GET handler
    // attaches without spawning a relay — that keeps the test focused
    // on the ring/detach/reattach contract and avoids racing the
    // VLESS handshake parser, which never sees any bytes here.
    let (listen_addr, server, registry) = setup_xhttp_server("/xh").await?;
    let client = http_client();
    let session_id = "drop-resume-session";
    let url = format!("http://{listen_addr}/xh/{session_id}");
    let (session, created) = registry.get_or_create(session_id, 16, None);
    assert!(created, "registry should mint a fresh session for a new id");

    // ── GET-A: read one downlink chunk, then drop the body ──────
    let get_a_url = url.clone();
    let get_a_client = client.clone();
    let get_a = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&get_a_url)
            .body(Full::new(Bytes::new()))?;
        let resp = get_a_client.request(req).await?;
        if resp.status() != StatusCode::OK {
            bail!("GET-A status {}", resp.status());
        }
        let mut body = resp.into_body();
        let bytes = read_body_until_at_least(&mut body, 5).await?;
        // `body` is dropped at end of scope, mimicking a CDN
        // ~100 s cut-off that closes the response stream while
        // the session is still healthy on the server side.
        Result::<_, anyhow::Error>::Ok(bytes)
    });
    // Give GET-A time to register and attach the downlink slot
    // before the first push.
    tokio::time::sleep(Duration::from_millis(100)).await;

    session
        .push_downlink(Bytes::from_static(b"alpha"))
        .map_err(|e| anyhow!("push_downlink alpha: {e:?}"))?;
    let downlink_a = tokio::time::timeout(Duration::from_secs(5), get_a).await???;
    assert_eq!(&downlink_a[..], b"alpha", "GET-A should observe the first chunk");

    // After the body drop the drain task is parked on
    // `downlink_notify` — channel-close alone cannot wake it. A
    // notify with no fresh bytes lets it observe `chunk_tx.is_closed()`
    // and detach the GET slot without spilling any pending chunks.
    session.downlink_notify.notify_waiters();

    // ── GET-B: reattach on the same path id and pick up bytes
    //    that arrived after GET-A's disconnect ───────────────────
    // Polling absorbs the (small) async window between the
    // notify_waiters above and the drain task actually completing
    // its detach — the server returns 409 until then.
    let mut attempts: u32 = 0;
    let resp_b = loop {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::new(Bytes::new()))?;
        let resp = client.request(req).await?;
        match resp.status() {
            StatusCode::OK => break resp,
            StatusCode::CONFLICT if attempts < 50 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            },
            other => bail!("GET-B unexpected status {other} after {attempts} attempts"),
        }
    };

    // Push the second chunk after GET-B has attached: this exercises
    // the "ring delivers fresh bytes through the new GET" half of
    // the contract. Pushing before would also work (the ring buffers
    // until a consumer attaches), but ordering it after makes the
    // assertion below trivially attributable to the new GET.
    session
        .push_downlink(Bytes::from_static(b"beta"))
        .map_err(|e| anyhow!("push_downlink beta: {e:?}"))?;

    let mut body_b = resp_b.into_body();
    let downlink_b = read_body_until_at_least(&mut body_b, 4).await?;
    assert_eq!(&downlink_b[..], b"beta", "GET-B should read the post-disconnect chunk");
    assert!(!session.is_closed(), "session must survive the GET-A disconnect");

    server.abort();
    Ok(())
}
