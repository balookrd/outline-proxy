//! Wire-level smoke test for the client XHTTP packet-up driver.
//!
//! Stands up a minimal h2-over-plain-TCP server with two route
//! handlers (one for GET, one for POST) and exercises the
//! `connect_xhttp` driver against it. The mock server is wire-form
//! only — no real VLESS framing — so we can validate exactly the
//! HTTP-level contract the client commits to: same URL on both
//! halves, monotonic `X-Xhttp-Seq` on POSTs, response body chunks
//! surfaced as `Message::Binary` on the client stream.

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::DnsCache;
use crate::config::TransportMode;
use crate::dial_plan::DialNetworkOptions;

#[derive(Default)]
struct CapturedPosts {
    seqs: Vec<u64>,
    bodies: Vec<Bytes>,
    /// DATA frames each packet-up POST body arrived in (stream-one: 1 per chunk).
    frames: Vec<usize>,
    /// Empty DATA frames seen in each packet-up POST body (a trailing
    /// END_STREAM-only frame shows up here).
    empty_frames: Vec<usize>,
    /// `content-length` request header of each packet-up POST, if any.
    content_lengths: Vec<Option<u64>>,
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_client_round_trip_through_mock_server() -> Result<()> {
    // Server-side capture for assertions.
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));

    // Bounded channel the server uses to push downlink chunks. The
    // GET handler drains it as a streaming response body so the
    // test can drive the client's downlink path explicitly.
    let (down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let captured_for_server = Arc::clone(&captured);
    let down_rx_for_server = Arc::clone(&down_rx);
    let _server = tokio::spawn(async move {
        // Single-connection mock — we only need one client.
        let (stream, _) = listener.accept().await.expect("accept");
        let io = TokioIo::new(stream);
        let captured = captured_for_server;
        let down_rx_slot = down_rx_for_server;
        let svc = service_fn(move |req: Request<Incoming>| {
            let captured = Arc::clone(&captured);
            let down_rx_slot = Arc::clone(&down_rx_slot);
            async move { handle(req, captured, down_rx_slot).await }
        });
        // h2 over plain TCP — no TLS in tests. ALPN-negotiated h2 is
        // not strictly required because we drove `prior_knowledge`
        // through the client's `http2::handshake` directly.
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    });

    // Build a `http://...` URL pointing at the mock; the client's
    // dial picks plain TCP h2 because the scheme is `http`, not
    // `https`.
    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));

    let (mut stream, issued, _ack_prefix_echo, _symmetric_replay_echo) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH2,
        DialNetworkOptions::default(),
        None,
        false,
        false,
        0,
        None,
        false,
        false,
    )
    .await?;
    // The mock server does not echo `X-Outline-Session`, so the
    // first dial should report no resume token. A follow-up test
    // exercises the populated path against an actual outline-ss-rust
    // server in the integration suite.
    assert!(issued.is_none());

    // Push two uplink frames — the client should issue them as
    // POSTs with seq=0 and seq=1.
    stream.send(Message::Binary(Bytes::from_static(b"hello"))).await?;
    stream.send(Message::Binary(Bytes::from_static(b"world"))).await?;

    // Push two downlink chunks via the mock — the GET response
    // body streams them back to the client.
    down_tx.send(Bytes::from_static(b"alpha")).await?;
    down_tx.send(Bytes::from_static(b"beta")).await?;

    // Drive the inbound side and assert we see both chunks.
    let first = read_binary(&mut stream).await?;
    assert_eq!(first.as_ref(), b"alpha");
    let second = read_binary(&mut stream).await?;
    assert_eq!(second.as_ref(), b"beta");

    // Give the POST sub-tasks a moment to drain; then snapshot the
    // server-side capture. POSTs are pipelined on h2, so the mock
    // may receive them in either order — sort by seq before asserting
    // so the test does not flake on the same wire-correct behaviour
    // the server's reorder buffer already absorbs.
    let posts = wait_for_posts(&captured, 2).await;
    let mut paired: Vec<(u64, Bytes)> =
        posts.seqs.iter().copied().zip(posts.bodies.iter().cloned()).collect();
    paired.sort_by_key(|(seq, _)| *seq);
    let seqs: Vec<u64> = paired.iter().map(|(seq, _)| *seq).collect();
    let bodies: Vec<Bytes> = paired.into_iter().map(|(_, body)| body).collect();
    assert_eq!(seqs, vec![0, 1]);
    assert_eq!(bodies[0].as_ref(), b"hello");
    assert_eq!(bodies[1].as_ref(), b"world");

    Ok(())
}

/// The packet-up client leaves the session start in one POST per write, but
/// cuts that POST's body into several DATA frames while the early-shape window
/// is open, so a large first write (the inner ClientHello) does not leave as
/// one TLS record. The body is the same bytes either way.
#[tokio::test(flavor = "multi_thread")]
async fn packet_up_h2_cuts_a_large_first_post_into_data_frames() -> Result<()> {
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));
    let (_down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let captured_for_server = Arc::clone(&captured);
    let _server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let svc = service_fn(move |req: Request<Incoming>| {
            let captured = Arc::clone(&captured_for_server);
            let down_rx_slot = Arc::clone(&down_rx);
            async move { handle(req, captured, down_rx_slot).await }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), svc)
            .await;
    });
    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, ..) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH2,
        DialNetworkOptions::default(),
        None,
        false,
        false,
        0,
        None,
        false,
        false,
    )
    .await?;

    let first: Bytes = (0..1964u32).map(|i| i as u8).collect::<Vec<u8>>().into();
    stream.send(Message::Binary(first.clone())).await?;
    stream.send(Message::Binary(Bytes::from_static(b"small"))).await?;

    let posts = wait_for_posts(&captured, 2).await;
    let mut rows: Vec<(u64, Bytes, usize, usize, Option<u64>)> = (0..posts.seqs.len())
        .map(|i| {
            (
                posts.seqs[i],
                posts.bodies[i].clone(),
                posts.frames[i],
                posts.empty_frames[i],
                posts.content_lengths[i],
            )
        })
        .collect();
    rows.sort_by_key(|(seq, ..)| *seq);
    assert_eq!(rows.len(), 2, "one POST per write");
    assert_eq!(rows[0].1, first, "the body is unchanged");
    assert!(rows[0].2 >= 3, "1964 B must arrive in >= 3 DATA frames, got {}", rows[0].2);
    assert_eq!(rows[1].1.as_ref(), b"small");
    assert_eq!(rows[1].2, 1, "a small write stays one frame");
    // END_STREAM rides the last piece: no trailing empty DATA frame (one more
    // small TLS record), and the cut body keeps its Content-Length.
    assert_eq!(rows[0].3, 0, "no trailing empty DATA frame");
    assert_eq!(rows[0].4, Some(1964), "the cut body keeps its Content-Length");
    assert_eq!(rows[1].4, Some(5));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_client_stream_one_round_trip_through_mock_server() -> Result<()> {
    // Stream-one mock: the server's POST handler captures every
    // request-body chunk and streams downlink chunks back. No GET
    // is opened, no `X-Xhttp-Seq` is sent.
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));
    let (down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let captured_for_server = Arc::clone(&captured);
    let down_rx_for_server = Arc::clone(&down_rx);
    let _server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = TokioIo::new(stream);
        let captured = captured_for_server;
        let down_rx_slot = down_rx_for_server;
        let svc = service_fn(move |req: Request<Incoming>| {
            let captured = Arc::clone(&captured);
            let down_rx_slot = Arc::clone(&down_rx_slot);
            async move { handle(req, captured, down_rx_slot).await }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    });

    // The carrier is selected purely from the URL — no extra
    // parameter to `connect_xhttp`.
    let base_url: Url = format!("http://{listen_addr}/xh?mode=stream-one").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, issued, _ack_prefix_echo, _symmetric_replay_echo) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH2,
        DialNetworkOptions::default(),
        None,
        false,
        false,
        0,
        None,
        false,
        false,
    )
    .await?;
    assert!(issued.is_none());

    // Push two uplink chunks — they should arrive on the server
    // request-body in the same order, no seq numbers.
    stream.send(Message::Binary(Bytes::from_static(b"hello"))).await?;
    stream.send(Message::Binary(Bytes::from_static(b"world"))).await?;
    // Push two downlink chunks — they should surface on the
    // client stream as Binary messages.
    down_tx.send(Bytes::from_static(b"alpha")).await?;
    down_tx.send(Bytes::from_static(b"beta")).await?;

    let first = read_binary(&mut stream).await?;
    assert_eq!(first.as_ref(), b"alpha");
    let second = read_binary(&mut stream).await?;
    assert_eq!(second.as_ref(), b"beta");

    // Wait for both uplink chunks to land in the captured store
    // and assert ordering. Stream-one is a single in-order body,
    // so the two chunks must be back-to-back.
    let posts = wait_for_posts(&captured, 2).await;
    // The mock tagged every stream-one chunk with seq=u64::MAX so
    // the assertion catches an accidental fall-through to the
    // packet-up branch.
    assert!(posts.seqs.iter().all(|&s| s == u64::MAX));
    assert_eq!(posts.bodies.len(), 2);
    let combined: Vec<u8> = posts.bodies.iter().flat_map(|b| b.iter().copied()).collect();
    assert_eq!(&combined, b"helloworld");

    Ok(())
}

async fn read_binary<S>(stream: &mut S) -> Result<Bytes>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for downlink chunk"))?;
        match next {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(Message::Close(_))) => anyhow::bail!("stream closed before payload"),
            Some(Ok(_)) => continue,
            Some(Err(error)) => return Err(error.into()),
            None => anyhow::bail!("stream ended before payload"),
        }
    }
}

async fn wait_for_posts(captured: &Arc<Mutex<CapturedPosts>>, expected: usize) -> CapturedPosts {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let guard = captured.lock();
            if guard.seqs.len() >= expected {
                return CapturedPosts {
                    seqs: guard.seqs.clone(),
                    bodies: guard.bodies.clone(),
                    frames: guard.frames.clone(),
                    empty_frames: guard.empty_frames.clone(),
                    content_lengths: guard.content_lengths.clone(),
                };
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let guard = captured.lock();
            return CapturedPosts {
                seqs: guard.seqs.clone(),
                bodies: guard.bodies.clone(),
                frames: guard.frames.clone(),
                empty_frames: guard.empty_frames.clone(),
                content_lengths: guard.content_lengths.clone(),
            };
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn handle(
    req: Request<Incoming>,
    captured: Arc<Mutex<CapturedPosts>>,
    down_rx_slot: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Bytes>>>>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let path = req.uri().path().to_owned();
    if !path.starts_with("/xh/") {
        let body = empty_body();
        return Ok(Response::builder().status(StatusCode::NOT_FOUND).body(body).unwrap());
    }
    let is_stream_one = req
        .uri()
        .query()
        .map(|q| q.split('&').any(|p| p == "mode=stream-one"))
        .unwrap_or(false);
    let method = req.method().clone();
    match (method, is_stream_one) {
        (Method::GET, _) => {
            // Drain the test-provided downlink channel as the
            // response body — first GET takes the receiver, any
            // subsequent GET sees an empty body.
            let receiver = {
                let mut slot = down_rx_slot.lock().await;
                slot.take()
            };
            let body: BoxBody<Bytes, Infallible> = match receiver {
                Some(rx) => StreamBody::new(stream_chunks(rx))
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
                None => empty_body(),
            };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(body)
                .unwrap())
        },
        (Method::POST, true) => {
            // Stream-one: take the downlink channel for the
            // response body, and spawn a task to drain the request
            // body into `captured.bodies` (one entry per chunk).
            // No `X-Xhttp-Seq` is involved — the carrier is a
            // single in-order stream.
            let receiver = {
                let mut slot = down_rx_slot.lock().await;
                slot.take()
            };
            let mut req_body = req.into_body();
            let captured_for_drain = Arc::clone(&captured);
            tokio::spawn(async move {
                while let Some(frame) = req_body.frame().await {
                    let frame = match frame {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        // Tag stream-one chunks with seq=u64::MAX
                        // so the test can tell the carrier mode
                        // apart from packet-up (which numbers
                        // them 0, 1, …). Single lock acquisition
                        // keeps the (seq, body) pair atomic.
                        let mut guard = captured_for_drain.lock();
                        guard.seqs.push(u64::MAX);
                        guard.bodies.push(data);
                        guard.frames.push(1);
                        guard.empty_frames.push(0);
                        guard.content_lengths.push(None);
                    }
                }
            });
            let body: BoxBody<Bytes, Infallible> = match receiver {
                Some(rx) => StreamBody::new(stream_chunks(rx))
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
                None => empty_body(),
            };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(body)
                .unwrap())
        },
        (Method::POST, false) => {
            // Packet-up uplink puts the per-packet `seq` in the URL
            // path: `/xh/<session>/<seq>`. Pin the parser to that
            // shape so a regression that re-introduces the old
            // header form (`X-Xhttp-Seq`) trips this assertion
            // instead of silently passing.
            let path = req.uri().path();
            let seq: u64 = path
                .rsplit_once('/')
                .and_then(|(_, tail)| tail.parse().ok())
                .unwrap_or(u64::MAX);
            // Read frame by frame (not `collect`) so the test can see how
            // many DATA frames the client cut the body into.
            let content_length = req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            let mut req_body = req.into_body();
            let mut body_bytes = Vec::new();
            let (mut frames, mut empty_frames) = (0, 0);
            while let Some(Ok(frame)) = req_body.frame().await {
                if let Ok(data) = frame.into_data() {
                    if data.is_empty() {
                        empty_frames += 1;
                    } else {
                        frames += 1;
                        body_bytes.extend_from_slice(&data);
                    }
                }
            }
            let body_bytes = Bytes::from(body_bytes);
            // Push the (seq, body) pair under ONE lock acquisition:
            // pipelined h2 POSTs run these handlers concurrently, and
            // split pushes can interleave (seq A, seq B, body B, body A),
            // mispairing the zip in the assertion phase.
            {
                let mut guard = captured.lock();
                guard.seqs.push(seq);
                guard.bodies.push(body_bytes);
                guard.frames.push(frames);
                guard.empty_frames.push(empty_frames);
                guard.content_lengths.push(content_length);
            }
            Ok(Response::builder().status(StatusCode::OK).body(empty_body()).unwrap())
        },
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(empty_body())
            .unwrap()),
    }
}

fn empty_body() -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::new()).boxed()
}

fn stream_chunks(
    rx: mpsc::Receiver<Bytes>,
) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static {
    futures_util::stream::unfold(rx, |mut rx| async move {
        let chunk = rx.recv().await?;
        Some((Ok(Frame::data(chunk)), rx))
    })
}

/// A session that never POSTed sends no FIN — unless its uplink rode HTTP/3
/// datagrams, in which case the server holds a session with seq 0 unspent and
/// only the FIN tells it the client is gone.
#[tokio::test]
async fn fin_at_seq_zero_only_when_the_uplink_rode_datagrams() {
    use std::sync::atomic::AtomicU64;

    let fired = Arc::new(Mutex::new(Vec::<u64>::new()));
    for even_unposted in [false, true] {
        let log = Arc::clone(&fired);
        let fin = super::FinOnDrop::new(Arc::new(AtomicU64::new(0)), move |seq| {
            Box::pin(async move { log.lock().push(seq) })
        })
        .even_unposted(even_unposted);
        drop(fin);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*fired.lock(), vec![0], "only the datagram session sends the seq-0 FIN");
}

/// A stalled POST must hold the uplink back instead of letting later POSTs run
/// past the server's reorder window: ours answers 503 once a POST arrives 64
/// seqs ahead, Xray once 30 are buffered. Parked POSTs are answered at once, so
/// it is the stalled seq, not the POSTs in flight, that the client must anchor on.
#[tokio::test(flavor = "multi_thread")]
async fn packet_up_h2_stays_within_the_reorder_window_behind_a_stalled_post() -> Result<()> {
    const WRITES: u64 = 3 * super::window::UPLINK_WINDOW_POSTS;
    let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let release = Arc::new(tokio::sync::Notify::new());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let (seen_srv, release_srv) = (Arc::clone(&seen), Arc::clone(&release));
    let _server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let svc = service_fn(move |req: Request<Incoming>| {
            let (seen, release) = (Arc::clone(&seen_srv), Arc::clone(&release_srv));
            async move {
                if req.method() == Method::POST {
                    let seq: u64 = req
                        .uri()
                        .path()
                        .rsplit_once('/')
                        .and_then(|(_, tail)| tail.parse().ok())
                        .unwrap_or(u64::MAX);
                    let _ = req.into_body().collect().await;
                    seen.lock().push(seq);
                    if seq == 0 {
                        release.notified().await;
                    }
                    return Ok::<_, Infallible>(
                        Response::builder().status(StatusCode::OK).body(empty_body()).unwrap(),
                    );
                }
                // GET: hold the downlink open with no data.
                let body = BodyExt::boxed(StreamBody::new(futures_util::stream::pending::<
                    Result<Frame<Bytes>, Infallible>,
                >()));
                Ok(Response::builder().status(StatusCode::OK).body(body).unwrap())
            }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), svc)
            .await;
    });
    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, ..) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH2,
        DialNetworkOptions::default(),
        None,
        false,
        false,
        0,
        None,
        false,
        false,
    )
    .await?;
    let sender = tokio::spawn(async move {
        for i in 0..WRITES {
            stream
                .send(Message::Binary(Bytes::from(i.to_be_bytes().to_vec())))
                .await?;
        }
        Ok::<_, anyhow::Error>(stream)
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let max_seen = seen.lock().iter().copied().max().unwrap_or(0);
    assert_eq!(
        max_seen,
        super::window::UPLINK_WINDOW_POSTS - 1,
        "with seq 0 stalled the client must stop at the window's edge"
    );

    release.notify_one();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while (seen.lock().len() as u64) < WRITES {
        assert!(tokio::time::Instant::now() < deadline, "the uplink did not resume");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _stream = sender.await??;
    Ok(())
}

/// A 503 is the server's "buffers full, send this seq again" (the seq is not
/// consumed). The client must re-send the same POST instead of tearing the
/// session down, which is what broke every upload that outran the server's
/// upstream.
#[tokio::test(flavor = "multi_thread")]
async fn packet_up_h2_resends_a_post_the_server_refused_as_busy() -> Result<()> {
    let accepted: Arc<Mutex<Vec<(u64, Bytes)>>> = Arc::new(Mutex::new(Vec::new()));
    let refusals = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let (accepted_srv, refusals_srv) = (Arc::clone(&accepted), Arc::clone(&refusals));
    let _server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let svc = service_fn(move |req: Request<Incoming>| {
            let (accepted, refusals) = (Arc::clone(&accepted_srv), Arc::clone(&refusals_srv));
            async move {
                if req.method() == Method::POST {
                    let seq: u64 = req
                        .uri()
                        .path()
                        .rsplit_once('/')
                        .and_then(|(_, tail)| tail.parse().ok())
                        .unwrap_or(u64::MAX);
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    if seq == 1 && refusals.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .body(empty_body())
                                .unwrap(),
                        );
                    }
                    accepted.lock().push((seq, body));
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(empty_body())
                        .unwrap());
                }
                let body = BodyExt::boxed(StreamBody::new(futures_util::stream::pending::<
                    Result<Frame<Bytes>, Infallible>,
                >()));
                Ok(Response::builder().status(StatusCode::OK).body(body).unwrap())
            }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), svc)
            .await;
    });
    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, ..) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH2,
        DialNetworkOptions::default(),
        None,
        false,
        false,
        0,
        None,
        false,
        false,
    )
    .await?;
    for body in [&b"zero"[..], b"one", b"two"] {
        stream.send(Message::Binary(Bytes::copy_from_slice(body))).await?;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while accepted.lock().len() < 3 {
        assert!(tokio::time::Instant::now() < deadline, "seq 1 was not re-sent");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut got = accepted.lock().clone();
    got.sort_by_key(|(seq, _)| *seq);
    assert_eq!(
        got,
        [
            (0, Bytes::from_static(b"zero")),
            (1, Bytes::from_static(b"one")),
            (2, Bytes::from_static(b"two"))
        ]
    );
    assert_eq!(refusals.load(std::sync::atomic::Ordering::SeqCst), 3, "two 503s, then accepted");
    // The session survived the 503s: the uplink still carries.
    stream.send(Message::Binary(Bytes::from_static(b"three"))).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while accepted.lock().len() < 4 {
        assert!(tokio::time::Instant::now() < deadline, "the session died after the 503s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}
