//! Bounded-resource guarantees of the XHTTP-over-h2 packet-up uplink.
//!
//! Same shape as the h3 sibling (`tests/h3.rs`): a server that accepts the
//! POST stream and then never answers must not be able to park a POST task
//! forever. On h2 the stall is even quieter than on QUIC — this carrier sets
//! no h2 keep-alive ping and the TCP socket carries no keepalive either — so
//! nothing below the POST itself ever ends the wait, while the orphaned task
//! holds a `SendRequest` clone that keeps hyper's connection (hence the TCP
//! socket and its TLS session) alive after the caller dropped the
//! `XhttpStream`.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::DnsCache;
use crate::config::TransportMode;
use crate::guards::AbortOnDrop;
use crate::xhttp::{XhttpStream, connect_xhttp};

/// Signals when the server-side POST handler is dropped, which is what
/// happens when the client resets the request stream.
struct CancelSignal(mpsc::UnboundedSender<()>);

impl Drop for CancelSignal {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct SilentServer {
    addr: SocketAddr,
    /// One item per POST the server has received.
    seen_post: mpsc::UnboundedReceiver<()>,
    /// One item per POST whose handler was dropped (client reset the stream).
    post_cancelled: mpsc::UnboundedReceiver<()>,
    /// Held so the GET response body never ends — the downlink stays open and
    /// only the uplink is under test.
    _downlink: mpsc::Sender<Bytes>,
    _task: AbortOnDrop,
}

/// Single-connection h2 server: answers the packet-up GET with a response body
/// that never ends, and takes every POST without ever answering it.
async fn silent_post_server() -> SilentServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("mock server binds");
    let addr = listener.local_addr().expect("mock server has a local addr");

    let (seen_post_tx, seen_post) = mpsc::unbounded_channel();
    let (cancelled_tx, post_cancelled) = mpsc::unbounded_channel();
    let (downlink_tx, downlink_rx) = mpsc::channel::<Bytes>(1);
    let downlink_slot = Arc::new(tokio::sync::Mutex::new(Some(downlink_rx)));

    let task = AbortOnDrop::new(tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("mock server accepts");
        let service = service_fn(move |req: Request<Incoming>| {
            let seen_post_tx = seen_post_tx.clone();
            let cancelled_tx = cancelled_tx.clone();
            let downlink_slot = Arc::clone(&downlink_slot);
            async move { handle(req, seen_post_tx, cancelled_tx, downlink_slot).await }
        });
        let _ = ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }));

    SilentServer {
        addr,
        seen_post,
        post_cancelled,
        _downlink: downlink_tx,
        _task: task,
    }
}

async fn handle(
    req: Request<Incoming>,
    seen_post_tx: mpsc::UnboundedSender<()>,
    cancelled_tx: mpsc::UnboundedSender<()>,
    downlink_slot: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Bytes>>>>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    match *req.method() {
        Method::GET => {
            let receiver = downlink_slot.lock().await.take();
            let body: BoxBody<Bytes, Infallible> = match receiver {
                // Nothing is ever pushed into this channel and the test holds
                // the sender, so the downlink simply stays open.
                Some(rx) => StreamBody::new(never_ending_chunks(rx))
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
                None => Full::new(Bytes::new()).boxed(),
            };
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(body)
                .expect("GET response builds"))
        },
        Method::POST => {
            // Read the uplink frame, then go silent: no status, no body, no
            // reset — exactly the state that leaves `send_request` pending.
            let _ = req.into_body().collect().await;
            let _cancelled = CancelSignal(cancelled_tx);
            let _ = seen_post_tx.send(());
            std::future::pending().await
        },
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()).boxed())
            .expect("405 response builds")),
    }
}

fn never_ending_chunks(
    rx: mpsc::Receiver<Bytes>,
) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static {
    futures_util::stream::unfold(rx, |mut rx| async move {
        let chunk = rx.recv().await?;
        Some((Ok(Frame::data(chunk)), rx))
    })
}

/// Dials the mock through the production XHTTP path and pushes one uplink
/// frame, returning once the server has the POST in hand.
async fn session_with_one_pending_post(server: &mut SilentServer) -> XhttpStream {
    let url: Url = format!("http://{}/xh", server.addr).parse().expect("mock url parses");
    let cache = DnsCache::new(Duration::from_secs(30));
    let (mut stream, _issued, _ack_echo, _sym_echo) = connect_xhttp(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        None,
        false,
        false,
        0,
        None,
    )
    .await
    .expect("xhttp h2 dial to the mock succeeds");

    stream
        .send(Message::Binary(Bytes::from_static(b"uplink frame")))
        .await
        .expect("the driver accepts the uplink frame");
    tokio::time::timeout(Duration::from_secs(5), server.seen_post.recv())
        .await
        .expect("the server receives the POST")
        .expect("the seen-post channel stays open");
    stream
}

#[tokio::test]
async fn a_packet_up_post_to_a_silent_server_fails_at_its_deadline() {
    let mut server = silent_post_server().await;
    let mut stream = session_with_one_pending_post(&mut server).await;

    // Dial and POST ran on the real clock; from here the deadline is all that
    // matters, so let the virtual clock run it out.
    tokio::time::pause();
    let surfaced = tokio::time::timeout(Duration::from_secs(600), stream.next()).await;

    let surfaced = surfaced.expect("the stalled POST must surface a failure at its deadline");
    assert!(
        matches!(surfaced, Some(Err(_))),
        "the caller must see the uplink failure, got: {surfaced:?}"
    );
}

#[tokio::test]
async fn dropping_the_session_kills_in_flight_posts() {
    let mut server = silent_post_server().await;
    let stream = session_with_one_pending_post(&mut server).await;

    // Dropping the `XhttpStream` aborts the driver; the POST it spawned must
    // go with it instead of holding a `SendRequest` clone — and hyper's
    // connection with it — until the POST's own deadline.
    drop(stream);

    // Real clock on purpose: with the POST owned by the driver the reset lands
    // immediately, so this window is only ever missed by a leaked task sitting
    // out the far longer per-POST deadline.
    let cancelled =
        tokio::time::timeout(Duration::from_secs(5), server.post_cancelled.recv()).await;
    assert!(
        cancelled.is_ok(),
        "an in-flight POST must not outlive the session that spawned it"
    );
}
