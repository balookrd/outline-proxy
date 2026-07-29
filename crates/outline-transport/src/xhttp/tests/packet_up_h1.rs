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
    /// Whether each POST carried the `X-Xhttp-Fin` hint, positionally aligned
    /// with `seqs` / `bodies`.
    fins: Vec<bool>,
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_h1_client_round_trip_through_mock_server() -> Result<()> {
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));
    let (down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let _server = spawn_mock_server(listener, Arc::clone(&captured), Arc::clone(&down_rx));

    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));

    let (mut stream, issued, _ack_prefix_echo, _symmetric_replay_echo) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH1,
        None,
        false,
        None,
        false,
        false,
        0,
        None,
        false,
    )
    .await?;
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
    assert_eq!(posts.fins, vec![false, false], "a data POST must not carry the FIN hint");

    Ok(())
}

/// Closing the sink must put an `X-Xhttp-Fin` POST on the wire: packet-up has no
/// transport-level end-of-stream, so this header is the server's only prompt
/// signal that the carrier is done. Without it the session (and, on an SS-UDP
/// path, the park a cross-transport resume takes over) lingers until the
/// server's 180 s idle sweep.
///
/// It must be the *last* POST — the server collapses its uplink on it, so an
/// early FIN would discard the tail of the upload — and carry no payload.
#[tokio::test(flavor = "multi_thread")]
async fn xhttp_h1_close_sends_fin_post_after_the_uplink() -> Result<()> {
    let captured: Arc<Mutex<CapturedPosts>> = Arc::new(Mutex::new(CapturedPosts::default()));
    let (_down_tx, down_rx) = mpsc::channel::<Bytes>(8);
    let down_rx = Arc::new(tokio::sync::Mutex::new(Some(down_rx)));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let _server = spawn_mock_server(listener, Arc::clone(&captured), Arc::clone(&down_rx));

    let base_url: Url = format!("http://{listen_addr}/xh").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, _issued, _ack_prefix_echo, _symmetric_replay_echo) = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH1,
        None,
        false,
        None,
        false,
        false,
        0,
        None,
        false,
    )
    .await?;

    stream.send(Message::Binary(Bytes::from_static(b"hello"))).await?;
    // `Sink::close` is what the carrier's writer task calls on a client close;
    // the driver turns it into the FIN.
    stream.close().await?;

    let posts = wait_for_posts(&captured, 2).await;
    assert_eq!(posts.seqs, vec![0, 1], "the FIN takes the next seq, after every data POST");
    assert_eq!(posts.fins, vec![false, true], "only the closing POST carries the FIN hint");
    assert!(posts.bodies[1].is_empty(), "the FIN POST carries no payload");

    Ok(())
}

/// Spawns the h1 mock: an accept loop, not a single connection — the h1 driver
/// opens two sockets per session (GET + POST) because h1 cannot multiplex. Each
/// accepted socket is served by its own task so the GET's streaming body does
/// not block POST handling.
fn spawn_mock_server(
    listener: TcpListener,
    captured: Arc<Mutex<CapturedPosts>>,
    down_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Bytes>>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let captured = Arc::clone(&captured);
            let down_rx_slot = Arc::clone(&down_rx);
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
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_h1_silently_coerces_stream_one_to_packet_up() -> Result<()> {
    // The user-facing `connect_xhttp` entry point clamps stream-one
    // to packet-up whenever the carrier is `xhttp_h1` — h1 cannot
    // multiplex a streaming GET against a streaming POST on a single
    // connection, so attempting stream-one there is meaningless. The
    // clamp happens *before* dispatching to the h1 carrier so the
    // dial proceeds with packet-up shape; the h1 carrier's defensive
    // `packet-up only` bail still exists internally but is no longer
    // reachable through the public entry point.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    // No accept loop — we just want to verify the dial is attempted
    // (proving the clamp fired) rather than rejected up-front.
    drop(listener);

    let base_url: Url = format!("http://{listen_addr}/xh?mode=stream-one").parse()?;
    let cache = DnsCache::new(Duration::from_secs(30));

    let result = super::connect_xhttp(
        &cache,
        &base_url,
        TransportMode::XhttpH1,
        None,
        false,
        None,
        false,
        false,
        0,
        None,
        false,
    )
    .await;
    let err = match result {
        Ok(_) => panic!("expected dial failure (no server), got an open session"),
        Err(error) => error,
    };
    let msg = format!("{err:#}");
    assert!(
        !msg.contains("packet-up only"),
        "h1 entry must clamp stream-one silently, but the defensive bail fired: {msg}"
    );
    assert!(
        msg.contains("Connection refused") || msg.contains("connect TCP socket"),
        "expected connect-level failure after the clamp, got: {msg}"
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

async fn wait_for_posts(captured: &Arc<Mutex<CapturedPosts>>, expected: usize) -> CapturedPosts {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let guard = captured.lock();
            if guard.seqs.len() >= expected {
                return CapturedPosts {
                    seqs: guard.seqs.clone(),
                    bodies: guard.bodies.clone(),
                    fins: guard.fins.clone(),
                };
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let guard = captured.lock();
            return CapturedPosts {
                seqs: guard.seqs.clone(),
                bodies: guard.bodies.clone(),
                fins: guard.fins.clone(),
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
            let fin = req.headers().contains_key(crate::xhttp::FIN_HEADER);
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            // Push the (seq, body) pair under ONE lock acquisition so
            // concurrent handlers cannot interleave the two vecs and
            // mispair the zip in the assertion phase.
            {
                let mut guard = captured.lock();
                guard.seqs.push(seq);
                guard.bodies.push(body_bytes);
                guard.fins.push(fin);
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
