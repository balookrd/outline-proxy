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
use crate::tests::{MeasuredKind, measured_browser_headers};

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
    /// Regular headers `(name, value)` in the order the server decoded them.
    server_headers: Vec<(String, String)>,
}

/// Handshake a client configured by `apply_h2_shape(shape, operator)` with an
/// in-process hyper h2 server (extended CONNECT enabled), send `request`,
/// and return the client's bytes plus the header order the server decoded.
async fn exchange<B>(shape: &H2Shape, operator: OperatorWindows, request: Request<B>) -> Exchange
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    exchange_on(H2Carrier::Ws, shape, operator, request).await
}

/// [`exchange`] for a given carrier (selects the default windows).
async fn exchange_on<B>(
    carrier: H2Carrier,
    shape: &H2Shape,
    operator: OperatorWindows,
    request: Request<B>,
) -> Exchange
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let log = Arc::new(Mutex::new(Vec::new()));
    let (names_tx, mut names_rx) = mpsc::unbounded_channel::<Vec<(String, String)>>();

    let server = tokio::spawn(async move {
        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let _ = names_tx.send(crate::tests::header_pairs(req.headers()));
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
        .handshake::<_, B>(TokioIo::new(Tee { inner: client_io, log: Arc::clone(&log) }))
        .await
        .expect("h2 handshake");
    let driver = tokio::spawn(conn);
    send.ready().await.expect("h2 ready");
    let response = send.send_request(request).await.expect("h2 request");
    assert!(response.status().is_success());
    let server_headers = names_rx.recv().await.expect("server saw the request");
    drop(send);
    driver.abort();
    server.abort();
    let client_bytes = log.lock().unwrap().clone();
    Exchange { client_bytes, server_headers }
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

// ── (3) request headers on the wire ───────────────────────────────────────────
//
// What the server decodes from the HEADERS hyper/h2 really write, for each
// carrier request kind, against the measured browser requests
// (`crate::tests::measured_browser_headers`). Carrier custom headers
// (`X-Outline-*`) trail the browser ones; nothing else may differ.

fn resume() -> DialResumeOptions {
    DialResumeOptions {
        resume_request: Some(SessionId::from_bytes([7; 16])),
        ack_prefix_requested: true,
        symmetric_replay_requested: true,
        client_acked_offset: 42,
    }
}

/// `X-Outline-*` headers of [`resume`] (and `x-outline-udp-records`), in the
/// order the carriers append them after the browser headers.
fn resume_headers(udp_records: bool) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = [
        ("x-outline-resume-capable", "1".to_owned()),
        ("x-outline-resume", SessionId::from_bytes([7; 16]).to_hex()),
        ("x-outline-resume-ack-prefix", "1".to_owned()),
        ("x-outline-resume-symmetric-replay", "1".to_owned()),
        ("x-outline-resume-down-acked", "42".to_owned()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v))
    .collect();
    if udp_records {
        out.push(("x-outline-udp-records".to_owned(), "1".to_owned()));
    }
    out
}

fn profile_cases() -> Vec<Option<&'static Profile>> {
    let mut cases: Vec<Option<&'static Profile>> = vec![None];
    cases.extend(PROFILES.iter().map(Some));
    cases
}

/// The browser part of a request the measured tables do not cover (Safari's
/// historical headers, nothing without a profile), as `request_headers`
/// renders it — pinned by its own snapshot test there.
fn unmeasured_browser_headers(
    profile: Option<&Profile>,
    kind: crate::request_headers::RequestKind,
) -> Vec<(String, String)> {
    let mut headers = HeaderMap::new();
    crate::request_headers::browser_headers(
        profile,
        kind,
        crate::request_headers::HttpVersion::H2,
        crate::tests::MEASURED_ORIGIN,
        &crate::request_headers::CarrierSlots::default(),
        &mut headers,
    );
    crate::tests::header_pairs(&headers)
}

fn is_measured(profile: Option<&Profile>) -> bool {
    matches!(profile.map(|p| p.tls), Some(TlsFingerprint::Chromium | TlsFingerprint::Firefox))
}

#[tokio::test]
async fn ws_h2_connect_sends_the_browser_websocket_request() {
    use crate::request_headers::RequestKind;
    for profile in profile_cases() {
        let request = crate::h2::build_websocket_connect_request(
            "https://example.test:8443/ws",
            &resume(),
            profile,
        )
        .unwrap();
        let fp = profile.map(|p| p.tls);
        let ex = exchange(&h2_shape(fp), (None, None), request).await;

        let mut expected = match profile {
            Some(p) if is_measured(profile) => {
                measured_browser_headers(p, MeasuredKind::WebSocket, false)
            },
            _ => unmeasured_browser_headers(profile, RequestKind::WebSocket),
        };
        if profile.is_none() {
            assert_eq!(expected, [("sec-websocket-version".to_owned(), "13".to_owned())]);
        }
        expected.extend(resume_headers(false));
        assert_eq!(ex.server_headers, expected, "profile={:?}", profile.map(|p| p.name));
    }
}

#[tokio::test]
async fn xhttp_h2_session_requests_send_the_browser_fetch_request() {
    use crate::request_headers::{HttpVersion, RequestKind};
    for profile in profile_cases() {
        // The long-lived GET and the stream-one POST (a streaming body: no
        // `content-length`).
        for (kind, measured, method) in [
            (RequestKind::FetchGet, MeasuredKind::FetchGet, Method::GET),
            (RequestKind::FetchPost, MeasuredKind::FetchPost, Method::POST),
        ] {
            let r = resume();
            // Stream-one's body is a live stream (unknown length), so hyper
            // adds no `content-length`; an `Empty` POST body would get `0`.
            let body = if method == Method::POST {
                StreamBody::new(futures_util::stream::empty::<Result<Frame<Bytes>, Infallible>>())
                    .boxed()
            } else {
                Empty::<Bytes>::new().boxed()
            };
            let mut request = Request::builder()
                .method(method)
                .uri("https://example.test:8443/xh/session")
                .version(Version::HTTP_2)
                .body(body)
                .unwrap();
            *request.headers_mut() = crate::xhttp::build_session_request_headers(
                crate::xhttp::SessionRequest {
                    profile,
                    kind,
                    version: HttpVersion::H2,
                    origin: crate::tests::MEASURED_ORIGIN,
                    host: None,
                },
                r.resume_request,
                r.ack_prefix_requested,
                r.symmetric_replay_requested,
                r.client_acked_offset,
                true,
            )
            .unwrap();
            let fp = profile.map(|p| p.tls);
            let ex = exchange_on(H2Carrier::Xhttp, &h2_shape(fp), (None, None), request).await;

            let mut expected = match profile {
                Some(p) if is_measured(profile) => measured_browser_headers(p, measured, false)
                    .into_iter()
                    .filter(|(n, _)| n != "content-length")
                    .collect(),
                _ => unmeasured_browser_headers(profile, kind),
            };
            expected.extend(resume_headers(true));
            assert_eq!(
                ex.server_headers,
                expected,
                "profile={:?} kind={kind:?}",
                profile.map(|p| p.name)
            );
        }
    }
}

#[tokio::test]
async fn xhttp_h2_packet_up_post_sends_the_browser_fetch_post() {
    for profile in profile_cases() {
        // What `xhttp::h2::build_post_headers` builds, then one POST's length.
        let mut headers = crate::xhttp::build_post_template(
            profile,
            crate::request_headers::HttpVersion::H2,
            crate::tests::MEASURED_ORIGIN,
            None,
            true,
        );
        crate::xhttp::set_post_content_length(&mut headers, 4);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("https://example.test:8443/xh/session/0")
            .version(Version::HTTP_2)
            .body(http_body_util::Full::new(Bytes::from_static(b"data")))
            .unwrap();
        *request.headers_mut() = headers;
        let fp = profile.map(|p| p.tls);
        let ex = exchange_on(H2Carrier::Xhttp, &h2_shape(fp), (None, None), request).await;

        let mut expected = match profile {
            Some(p) if is_measured(profile) => {
                measured_browser_headers(p, MeasuredKind::FetchPost, false)
            },
            _ => {
                unmeasured_browser_headers(profile, crate::request_headers::RequestKind::FetchPost)
            },
        };
        expected.push(("x-outline-udp-records".to_owned(), "1".to_owned()));
        if !is_measured(profile) {
            // Safari / no profile: hyper appends its own, as before.
            expected.push(("content-length".to_owned(), "4".to_owned()));
        }
        assert_eq!(ex.server_headers, expected, "profile={:?}", profile.map(|p| p.name));
    }
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
