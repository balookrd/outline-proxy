//! Tests for [`crate::h2_profile`]: the per-family SETTINGS / window values,
//! the bytes `hyper` really writes for them (client preface captured from a
//! live handshake against an in-process `hyper` h2 server), and the order of
//! the request headers the server decodes from those bytes.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, Version};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http2;
use hyper::server::conn::http2::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::{H2Carrier, H2Shape, OperatorWindows, apply_h2_shape, carrier_windows, h2_shape};
use crate::dial_plan::DialResumeOptions;
use crate::fingerprint_profile::{PROFILES, Profile, TlsFingerprint};
use crate::resumption::SessionId;

/// Initial connection window of every h2 endpoint (RFC 9113 §6.9.2); the
/// connection WINDOW_UPDATE carries `window - 65535`.
const SPEC_CONNECTION_WINDOW: u32 = 65_535;

// ── (1) shape values ──────────────────────────────────────────────────────────

#[test]
fn shape_values_follow_the_measured_browsers() {
    let chromium = H2Shape {
        header_table_size: Some(65_536),
        max_frame_size: None,
        max_header_list_size: Some(262_144),
        max_concurrent_streams: None,
    };
    assert_eq!(h2_shape(Some(TlsFingerprint::Chromium)), chromium);
    // No profile ⇒ Chromium, like the TLS ClientHello.
    assert_eq!(h2_shape(None), chromium);
    assert_eq!(
        h2_shape(Some(TlsFingerprint::Firefox)),
        H2Shape {
            header_table_size: Some(65_536),
            max_frame_size: Some(16_384),
            max_header_list_size: None,
            max_concurrent_streams: None,
        }
    );
    assert_eq!(
        h2_shape(Some(TlsFingerprint::Safari)),
        H2Shape {
            header_table_size: None,
            max_frame_size: None,
            max_header_list_size: None,
            max_concurrent_streams: Some(100),
        }
    );
}

#[test]
fn carrier_windows_are_the_pre_series_defaults() {
    assert_eq!(carrier_windows(H2Carrier::Ws), (8_388_608, 33_554_432));
    assert_eq!(carrier_windows(H2Carrier::Xhttp), (2_097_152, 5_242_880));
}

// ── capture harness ───────────────────────────────────────────────────────────

/// Client IO that copies every byte hyper writes into `log`.
struct Tee {
    inner: DuplexStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tee {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tee {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.log.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What one request over a freshly shaped connection looked like.
struct Exchange {
    /// Every byte the client wrote, starting with the connection preface.
    client_bytes: Vec<u8>,
    /// Regular header names in the order the server decoded them.
    server_header_names: Vec<String>,
}

/// Handshake a client configured by `apply_h2_shape(shape, operator)` with an
/// in-process hyper h2 server (extended CONNECT enabled), send `request`,
/// and return the client's bytes plus the header order the server decoded.
async fn exchange(
    shape: &H2Shape,
    operator: OperatorWindows,
    request: Request<Empty<Bytes>>,
) -> Exchange {
    exchange_on(H2Carrier::Ws, shape, operator, request).await
}

/// [`exchange`] for a given carrier (selects the default windows).
async fn exchange_on(
    carrier: H2Carrier,
    shape: &H2Shape,
    operator: OperatorWindows,
    request: Request<Empty<Bytes>>,
) -> Exchange {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let log = Arc::new(Mutex::new(Vec::new()));
    let (names_tx, mut names_rx) = mpsc::unbounded_channel::<Vec<String>>();

    let server = tokio::spawn(async move {
        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let names = req.headers().keys().map(|n| n.as_str().to_owned()).collect();
            let _ = names_tx.send(names);
            async { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .enable_connect_protocol()
            .serve_connection(TokioIo::new(server_io), service)
            .await;
    });

    let mut builder = http2::Builder::new(TokioExecutor::new());
    apply_h2_shape(&mut builder, shape, carrier, operator);
    let (mut send, conn) = builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(Tee { inner: client_io, log: Arc::clone(&log) }))
        .await
        .expect("h2 handshake");
    let driver = tokio::spawn(conn);
    send.ready().await.expect("h2 ready");
    let response = send.send_request(request).await.expect("h2 request");
    assert!(response.status().is_success());
    let server_header_names = names_rx.recv().await.expect("server saw the request");
    drop(send);
    driver.abort();
    server.abort();
    let client_bytes = log.lock().unwrap().clone();
    Exchange { client_bytes, server_header_names }
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FLAG_ACK: u8 = 0x1;

/// `(type, flags, stream id, payload)` for each frame after the preface.
fn frames(bytes: &[u8]) -> Vec<(u8, u8, u32, &[u8])> {
    assert!(bytes.starts_with(PREFACE), "client must open with the h2 preface");
    let mut rest = &bytes[PREFACE.len()..];
    let mut out = Vec::new();
    while rest.len() >= 9 {
        let len = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
        let ty = rest[3];
        let flags = rest[4];
        let stream = u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff;
        if rest.len() < 9 + len {
            break;
        }
        out.push((ty, flags, stream, &rest[9..9 + len]));
        rest = &rest[9 + len..];
    }
    out
}

/// The client's SETTINGS `(id, value)` pairs in wire order, and the
/// increment of its first connection-level WINDOW_UPDATE.
fn preface_shape(bytes: &[u8]) -> (Vec<(u16, u32)>, Option<u32>) {
    let frames = frames(bytes);
    let (_, _, _, payload) = frames
        .iter()
        .find(|(ty, flags, _, _)| *ty == FRAME_SETTINGS && flags & FLAG_ACK == 0)
        .expect("client SETTINGS frame");
    let settings = payload
        .as_chunks::<6>()
        .0
        .iter()
        .map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]])))
        .collect();
    let conn_wu = frames
        .iter()
        .find(|(ty, _, stream, _)| *ty == FRAME_WINDOW_UPDATE && *stream == 0)
        .map(|(_, _, _, p)| u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
    (settings, conn_wu)
}

fn simple_get() -> Request<Empty<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri("https://example.test/xh/session")
        .version(Version::HTTP_2)
        .body(Empty::new())
        .unwrap()
}

// ── (2) SETTINGS / WINDOW_UPDATE on the wire ─────────────────────────────────

#[tokio::test]
async fn chromium_preface_matches_chrome_except_windows() {
    for fp in [None, Some(TlsFingerprint::Chromium)] {
        let ex = exchange(&h2_shape(fp), (None, None), simple_get()).await;
        let (settings, wu) = preface_shape(&ex.client_bytes);
        // Chrome: `1:65536, 2:0, 4:6291456, 6:262144`, WU 15663105. Ours keeps
        // the ws_h2 windows (8 MiB stream, 32 MiB connection).
        assert_eq!(settings, vec![(1, 65_536), (2, 0), (4, 8_388_608), (6, 262_144)], "{fp:?}");
        assert_eq!(wu, Some(33_554_432 - SPEC_CONNECTION_WINDOW), "{fp:?}");
    }
}

#[tokio::test]
async fn firefox_preface_matches_firefox_except_known_gaps() {
    let ex = exchange(&h2_shape(Some(TlsFingerprint::Firefox)), (None, None), simple_get()).await;
    let (settings, wu) = preface_shape(&ex.client_bytes);
    // Firefox: `1:65536, 2:0, 4:131072, 5:16384`. Known gaps: the windows are
    // the carrier's (see `h2_shape`), and hyper always sends `6` (16384).
    assert_eq!(settings, vec![(1, 65_536), (2, 0), (4, 8_388_608), (5, 16_384), (6, 16_384)]);
    assert_eq!(wu, Some(33_554_432 - SPEC_CONNECTION_WINDOW));
}

#[tokio::test]
async fn safari_preface_matches_urlsession_except_known_gaps() {
    let ex = exchange(&h2_shape(Some(TlsFingerprint::Safari)), (None, None), simple_get()).await;
    let (settings, wu) = preface_shape(&ex.client_bytes);
    // URLSession: `2:0, 4:4194304, 3:100, 9:1`. Known gaps: h2 writes ids in
    // numeric order (3 before 4), cannot send 9, hyper always sends 6, and the
    // windows are the carrier's.
    assert_eq!(settings, vec![(2, 0), (3, 100), (4, 8_388_608), (6, 16_384)]);
    assert_eq!(wu, Some(33_554_432 - SPEC_CONNECTION_WINDOW));
}

#[tokio::test]
async fn xhttp_windows_are_hypers_former_defaults_for_every_family() {
    for fp in [
        None,
        Some(TlsFingerprint::Chromium),
        Some(TlsFingerprint::Firefox),
        Some(TlsFingerprint::Safari),
    ] {
        let ex = exchange_on(H2Carrier::Xhttp, &h2_shape(fp), (None, None), simple_get()).await;
        let (settings, wu) = preface_shape(&ex.client_bytes);
        assert!(settings.contains(&(4, 2_097_152)), "{fp:?}: {settings:?}");
        assert_eq!(wu, Some(5_177_345), "{fp:?}");
    }
}

// ── (4) operator [h2] windows win ─────────────────────────────────────────────

#[tokio::test]
async fn operator_windows_override_the_profile() {
    for fp in [
        Some(TlsFingerprint::Chromium),
        Some(TlsFingerprint::Firefox),
        Some(TlsFingerprint::Safari),
    ] {
        let shape = h2_shape(fp);
        let (ws_stream, ws_connection) = carrier_windows(H2Carrier::Ws);
        let ex = exchange(&shape, (Some(1_000_000), Some(3_000_000)), simple_get()).await;
        let (settings, wu) = preface_shape(&ex.client_bytes);
        assert!(settings.contains(&(4, 1_000_000)), "{fp:?}: {settings:?}");
        assert!(!settings.contains(&(4, ws_stream)), "{fp:?}");
        assert_eq!(wu, Some(3_000_000 - SPEC_CONNECTION_WINDOW), "{fp:?}");

        // Each window overrides independently.
        let ex = exchange(&shape, (None, Some(3_000_000)), simple_get()).await;
        let (settings, wu) = preface_shape(&ex.client_bytes);
        assert!(settings.contains(&(4, ws_stream)), "{fp:?}");
        assert_eq!(wu, Some(3_000_000 - SPEC_CONNECTION_WINDOW), "{fp:?}");

        let ex = exchange(&shape, (Some(1_000_000), None), simple_get()).await;
        let (settings, wu) = preface_shape(&ex.client_bytes);
        assert!(settings.contains(&(4, 1_000_000)), "{fp:?}");
        assert_eq!(wu, Some(ws_connection - SPEC_CONNECTION_WINDOW), "{fp:?}");
    }
}

// ── (3) request header order on the wire ──────────────────────────────────────

/// Browser header order on h2 per family (Chrome / Firefox measured,
/// Safari = the historical order), restricted to the headers a profile adds.
fn expected_browser_order(profile: &Profile) -> Vec<&'static str> {
    let order: &[&str] = match profile.tls {
        TlsFingerprint::Chromium => &[
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
        ],
        TlsFingerprint::Firefox => &[
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
        ],
        TlsFingerprint::Safari => &[
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
        ],
    };
    order.to_vec()
}

fn resume() -> DialResumeOptions {
    DialResumeOptions {
        resume_request: Some(SessionId::from_bytes([7; 16])),
        ack_prefix_requested: true,
        symmetric_replay_requested: true,
        client_acked_offset: 42,
    }
}

const RESUME_NAMES: &[&str] = &[
    "x-outline-resume-capable",
    "x-outline-resume",
    "x-outline-resume-ack-prefix",
    "x-outline-resume-symmetric-replay",
    "x-outline-resume-down-acked",
];

fn profile_cases() -> Vec<Option<&'static Profile>> {
    let mut cases: Vec<Option<&'static Profile>> = vec![None];
    cases.extend(PROFILES.iter().map(Some));
    cases
}

#[tokio::test]
async fn ws_h2_connect_headers_follow_the_browser_order() {
    for profile in profile_cases() {
        let request = crate::h2::build_websocket_connect_request(
            "https://example.test/ws",
            &resume(),
            profile,
        )
        .unwrap();
        let fp = profile.map(|p| p.tls);
        let ex = exchange(&h2_shape(fp), (None, None), request).await;

        let mut expected: Vec<&str> = profile.map(expected_browser_order).unwrap_or_default();
        expected.push("sec-websocket-version");
        expected.extend_from_slice(RESUME_NAMES);
        assert_eq!(ex.server_header_names, expected, "profile={:?}", profile.map(|p| p.name));
        assert!(!ex.server_header_names.iter().any(|n| n == "host"));
    }
}

#[tokio::test]
async fn xhttp_h2_session_headers_follow_the_browser_order_without_host() {
    for profile in profile_cases() {
        let r = resume();
        let mut request = simple_get();
        *request.headers_mut() = crate::xhttp::build_session_request_headers(
            r.resume_request,
            r.ack_prefix_requested,
            r.symmetric_replay_requested,
            r.client_acked_offset,
            true,
            profile,
        );
        let fp = profile.map(|p| p.tls);
        let ex = exchange(&h2_shape(fp), (None, None), request).await;

        let mut expected: Vec<&str> = profile.map(expected_browser_order).unwrap_or_default();
        expected.extend_from_slice(RESUME_NAMES);
        expected.push("x-outline-udp-records");
        assert_eq!(ex.server_header_names, expected, "profile={:?}", profile.map(|p| p.name));
        assert!(!ex.server_header_names.iter().any(|n| n == "host"));
    }
}

#[test]
fn h1_insertion_order_is_unchanged() {
    // `apply` (h1 / h3) keeps the historical order; a `Host` inserted first
    // stays first.
    let profile = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Chromium).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "example.test".parse().unwrap());
    crate::fingerprint_profile::apply(
        profile,
        &mut headers,
        crate::fingerprint_profile::SecFetchPreset::WebsocketUpgrade,
    );
    let names: Vec<&str> = headers.keys().map(|n| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "host",
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
        ]
    );
}

// ── Firefox stream window: throughput measurement ────────────────────────────

/// Forwards bytes between two sockets with a fixed one-way `delay` and no
/// bandwidth limit (unbounded queue): pure RTT emulation.
async fn delay_pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send((Instant::now() + delay, buf[..n].to_vec())).is_err() {
                        break;
                    }
                },
            }
        }
    });
    while let Some((due, chunk)) = rx.recv().await {
        tokio::time::sleep_until(due.into()).await;
        if to.write_all(&chunk).await.is_err() {
            break;
        }
    }
    reader.abort();
}

/// Download `total` bytes over plain h2 through a proxy adding `rtt`, with
/// the given stream window; returns MB/s.
async fn download_rate(stream_window: u32, conn_window: u32, rtt: Duration, total: usize) -> f64 {
    download_rates(stream_window, conn_window, rtt, total, 1).await.0
}

/// Like [`download_rate`], but `flows` concurrent downloads of `total` bytes
/// each share ONE connection. Returns `(aggregate MB/s, per-flow MB/s)`; the
/// aggregate is all bytes over the wall time of the slowest flow.
async fn download_rates(
    stream_window: u32,
    conn_window: u32,
    rtt: Duration,
    total: usize,
    flows: usize,
) -> (f64, Vec<f64>) {
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = server_listener.accept().await.unwrap();
        let service = service_fn(move |_req: Request<hyper::body::Incoming>| async move {
            let chunk = Bytes::from(vec![0u8; 16 * 1024]);
            let stream = futures_util::stream::iter(
                (0..total / chunk.len())
                    .map(move |_| Ok::<_, Infallible>(Frame::data(chunk.clone()))),
            );
            Ok::<_, Infallible>(Response::new(StreamBody::new(stream)))
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .initial_connection_window_size(16 << 20)
            .serve_connection(TokioIo::new(tcp), service)
            .await;
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.unwrap();
        let upstream = TcpStream::connect(server_addr).await.unwrap();
        let (cr, cw) = client.into_split();
        let (ur, uw) = upstream.into_split();
        let half = rtt / 2;
        tokio::join!(delay_pipe(cr, uw, half), delay_pipe(ur, cw, half));
    });

    let shape = h2_shape(Some(TlsFingerprint::Firefox));
    let mut builder = http2::Builder::new(TokioExecutor::new());
    apply_h2_shape(&mut builder, &shape, H2Carrier::Ws, (Some(stream_window), Some(conn_window)));
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (mut send, conn) = builder.handshake::<_, Empty<Bytes>>(TokioIo::new(tcp)).await.unwrap();
    let driver = tokio::spawn(conn);
    send.ready().await.unwrap();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..flows {
        let mut send = send.clone();
        tasks.push(tokio::spawn(async move {
            send.ready().await.unwrap();
            let t0 = Instant::now();
            let response = send.send_request(simple_get()).await.unwrap();
            let mut body = response.into_body();
            let mut received = 0usize;
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.unwrap().into_data() {
                    received += data.len();
                }
            }
            assert!(received >= total / 2, "short body: {received}");
            (received, t0.elapsed().as_secs_f64())
        }));
    }
    let mut all = 0usize;
    let mut per_flow = Vec::new();
    for task in tasks {
        let (received, elapsed) = task.await.unwrap();
        all += received;
        per_flow.push(received as f64 / elapsed / 1e6);
    }
    let aggregate = all as f64 / started.elapsed().as_secs_f64() / 1e6;
    driver.abort();
    proxy.abort();
    server.abort();
    (aggregate, per_flow)
}

/// Measurement behind the no-browser-stream-window decision in `h2_shape`
/// (`cargo test -p outline-transport --lib firefox_stream_window_throughput
/// -- --ignored --nocapture`). Ignored: it takes seconds and only prints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "throughput measurement, run by hand"]
async fn firefox_stream_window_throughput() {
    // Firefox's connection window (12 MiB).
    let conn_window = 12_582_912;
    for rtt_ms in [50u64, 100] {
        let rtt = Duration::from_millis(rtt_ms);
        for window in [131_072u32, 6_291_456] {
            let total = if window == 131_072 { 4 << 20 } else { 32 << 20 };
            let rate = download_rate(window, conn_window, rtt, total).await;
            println!("rtt={rtt_ms}ms stream_window={window} -> {rate:.2} MB/s ({total} B)");
        }
    }
}

/// Multiplex measurement behind the carrier-default windows in `h2_shape`
/// (`cargo test --release -p outline-transport --lib ws_h2_multiplex_throughput
/// -- --ignored --nocapture`): 4 concurrent downloads over ONE connection at
/// 300 ms RTT, the Chromium windows (stream 6291456 / connection 15728640)
/// against the previous ws_h2 defaults (8388608 / 33554432).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "throughput measurement, run by hand"]
async fn ws_h2_multiplex_throughput() {
    let rtt = Duration::from_millis(300);
    for (name, stream, conn) in
        [("new chromium", 6_291_456u32, 15_728_640u32), ("old ws_h2", 8_388_608, 33_554_432)]
    {
        let (aggregate, per_flow) = download_rates(stream, conn, rtt, 48 << 20, 4).await;
        let per_flow: Vec<String> = per_flow.iter().map(|r| format!("{r:.2}")).collect();
        println!(
            "{name}: stream={stream} conn={conn} rtt=300ms flows=4 -> aggregate {aggregate:.2} MB/s, per flow [{}] MB/s",
            per_flow.join(", ")
        );
    }
}
