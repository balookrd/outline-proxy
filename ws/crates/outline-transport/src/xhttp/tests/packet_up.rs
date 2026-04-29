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

#[derive(Default)]
struct CapturedPosts {
    seqs: Vec<u64>,
    bodies: Vec<Bytes>,
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

    let (mut stream, issued) =
        super::connect_xhttp(&cache, &base_url, TransportMode::XhttpH2, None, false, None).await?;
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
    let mut paired: Vec<(u64, Bytes)> = posts
        .seqs
        .iter()
        .copied()
        .zip(posts.bodies.iter().cloned())
        .collect();
    paired.sort_by_key(|(seq, _)| *seq);
    let seqs: Vec<u64> = paired.iter().map(|(seq, _)| *seq).collect();
    let bodies: Vec<Bytes> = paired.into_iter().map(|(_, body)| body).collect();
    assert_eq!(seqs, vec![0, 1]);
    assert_eq!(bodies[0].as_ref(), b"hello");
    assert_eq!(bodies[1].as_ref(), b"world");

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

async fn wait_for_posts(
    captured: &Arc<Mutex<CapturedPosts>>,
    expected: usize,
) -> CapturedPosts {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let guard = captured.lock();
            if guard.seqs.len() >= expected {
                return CapturedPosts { seqs: guard.seqs.clone(), bodies: guard.bodies.clone() };
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let guard = captured.lock();
            return CapturedPosts { seqs: guard.seqs.clone(), bodies: guard.bodies.clone() };
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
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body)
            .unwrap());
    }
    match *req.method() {
        Method::GET => {
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
        Method::POST => {
            let seq: u64 = req
                .headers()
                .get("x-xhttp-seq")
                .and_then(|v| v.to_str().ok()?.parse().ok())
                .unwrap_or(u64::MAX);
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            captured.lock().seqs.push(seq);
            captured.lock().bodies.push(body_bytes);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(empty_body())
                .unwrap())
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
