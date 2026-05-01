//! Wire-level smoke test for the client XHTTP packet-up driver
//! over HTTP/1.1.
//!
//! Mirrors `tests/packet_up.rs` (the h2 variant) but stands up an
//! h1 server. Two differences from the h2 test:
//!
//! * The mock accepts multiple TCP connections in a loop — the h1
//!   driver dials two sockets per session (one for the long-lived
//!   GET, one for serialised POSTs) because h1 cannot multiplex.
//! * The POST loop is strictly serialised on the wire, so the
//!   captured seq order is deterministic — no sort step needed
//!   before asserting `[0, 1]`.

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
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
async fn xhttp_h1_client_round_trip_through_mock_server() -> Result<()> {
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));
    let (down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let captured_for_server = Arc::clone(&captured);
    let down_rx_for_server = Arc::clone(&down_rx);
    let _server = tokio::spawn(async move {
        // Accept loop, not single-connection — h1 driver opens two
        // sockets per session (GET + POST), so the mock has to
        // serve both. Each accepted socket is owned by its own
        // task so the GET stream-out doesn't block POST handling.
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let captured = Arc::clone(&captured_for_server);
            let down_rx_slot = Arc::clone(&down_rx_for_server);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let captured = Arc::clone(&captured);
                    let down_rx_slot = Arc::clone(&down_rx_slot);
                    async move { handle(req, captured, down_rx_slot).await }
                });
                let _ = ServerBuilder::new().serve_connection(io, svc).await;
            });
        }
    });

    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));

    let (mut stream, issued) =
        super::connect_xhttp(&cache, &base_url, TransportMode::XhttpH1, None, false, None).await?;
    // The mock does not echo `X-Outline-Session`; the resume token
    // path is exercised in the cross-repo end-to-end test against
    // a real outline-ss-rust server.
    assert!(issued.is_none());

    stream.send(Message::Binary(Bytes::from_static(b"hello"))).await?;
    stream.send(Message::Binary(Bytes::from_static(b"world"))).await?;

    down_tx.send(Bytes::from_static(b"alpha")).await?;
    down_tx.send(Bytes::from_static(b"beta")).await?;

    let first = read_binary(&mut stream).await?;
    assert_eq!(first.as_ref(), b"alpha");
    let second = read_binary(&mut stream).await?;
    assert_eq!(second.as_ref(), b"beta");

    let posts = wait_for_posts(&captured, 2).await;
    // h1 serialises POSTs on a single keep-alive socket — the
    // server sees them in seq order with no need to sort. If a
    // future change accidentally reintroduces pipelining or splits
    // the uplink across multiple connections, this assert flakes
    // and the regression surfaces cleanly.
    assert_eq!(posts.seqs, vec![0, 1]);
    assert_eq!(posts.bodies[0].as_ref(), b"hello");
    assert_eq!(posts.bodies[1].as_ref(), b"world");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_h1_rejects_stream_one_submode() -> Result<()> {
    // Stream-one is intentionally not implemented for the h1
    // carrier — the user-facing fallback chain only covers
    // packet-up. Rather than silently downgrade the carrier shape,
    // `connect_xhttp_h1` bails loudly so a misconfigured URL
    // (`?mode=stream-one` with `vless_mode = xhttp_h1`) surfaces as
    // a clear dial error instead of unexpected wire behaviour.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    // No accept loop — `connect_xhttp_h1` should bail before any
    // socket is opened.
    drop(listener);

    let base_url: Url = format!("http://{listen_addr}/xh?mode=stream-one").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));

    let result =
        super::connect_xhttp(&cache, &base_url, TransportMode::XhttpH1, None, false, None).await;
    let err = match result {
        Ok(_) => panic!("expected stream-one bail, got an open session"),
        Err(error) => error,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("packet-up only"),
        "expected `packet-up only` in error chain, got: {msg}"
    );
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
                return CapturedPosts {
                    seqs: guard.seqs.clone(),
                    bodies: guard.bodies.clone(),
                };
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let guard = captured.lock();
            return CapturedPosts {
                seqs: guard.seqs.clone(),
                bodies: guard.bodies.clone(),
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
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap());
    }
    let method = req.method().clone();
    match method {
        Method::GET => {
            // First GET takes the downlink receiver; any subsequent
            // GET on the same listener (the test only opens one)
            // gets an empty body.
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
                .header("content-type", "application/octet-stream")
                .body(body)
                .unwrap())
        },
        Method::POST => {
            // Packet-up uplink puts the per-packet seq in the URL
            // path: `/xh/<session>/<seq>`. Pin the parser to that
            // shape so a regression to the legacy header-based form
            // (`X-Xhttp-Seq`) trips this assertion instead of
            // silently passing.
            let seq: u64 = path
                .rsplit_once('/')
                .and_then(|(_, tail)| tail.parse().ok())
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
