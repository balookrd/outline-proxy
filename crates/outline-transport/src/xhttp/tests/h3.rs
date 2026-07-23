//! Bounded-resource guarantees of the XHTTP-over-H3 carrier.
//!
//! Two leaks are covered here:
//!   * a fresh QUIC endpoint (hence a fresh UDP socket) per session even when
//!     the dial carries no fwmark — the native `ws_h3` carrier shares one
//!     endpoint per address family, and XHTTP sessions are 1:1 with their
//!     upstream, so an unshared endpoint grows the socket count with the
//!     session count;
//!   * an unbounded packet-up POST: a server that accepts the request stream
//!     and then goes silent keeps `recv_response()` pending forever while QUIC
//!     keep-alive (8–12 s) holds `max_idle_timeout` (28–35 s) off, so the
//!     detached POST task, its `SendRequest` clone and the whole QUIC
//!     connection outlive the `XhttpStream` that spawned them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h3::client::SendRequest;
use h3::quic::{
    BidiStream, ConnectionErrorIncoming, OpenStreams, RecvStream, SendStream, StreamErrorIncoming,
    StreamId, WriteBuf,
};
use http::HeaderMap;
use tokio_tungstenite::tungstenite::protocol::Message;

use super::{POST_TIMEOUT, dial_endpoint, driver_loop_h3, post_one_bounded};
use crate::xhttp::{XhttpTarget, inbound_channel, outbound_channel};

fn wildcard_v4() -> SocketAddr {
    "0.0.0.0:0".parse().expect("wildcard v4 addr parses")
}

// ── Silent-server QUIC stub ───────────────────────────────────────────────────
//
// Models the leak's trigger: the peer accepts every stream we open and takes
// all the bytes we write, but never sends a single response byte back. On a
// real connection QUIC keep-alive (8–12 s) keeps `max_idle_timeout` (28–35 s)
// from ever firing in that state, so nothing below the POST itself can end it.

#[derive(Default)]
struct StubState {
    /// Flipped when h3 tears the QUIC connection down — which it does once the
    /// last `SendRequest` clone is dropped.
    connection_closed: AtomicBool,
    next_stream_id: AtomicU64,
}

impl StubState {
    fn next_id(&self) -> StreamId {
        StreamId::try_from(self.next_stream_id.fetch_add(4, Ordering::Relaxed))
            .expect("stub stream id fits a varint")
    }
}

struct StubSend {
    id: StreamId,
}

impl SendStream<Bytes> for StubSend {
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, _data: T) -> Result<(), StreamErrorIncoming> {
        Ok(())
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, _reset_code: u64) {}

    fn send_id(&self) -> StreamId {
        self.id
    }
}

struct StubRecv {
    id: StreamId,
}

impl RecvStream for StubRecv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        // The server never answers: no data, no FIN, no error.
        Poll::Pending
    }

    fn stop_sending(&mut self, _error_code: u64) {}

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

struct StubBidi {
    send: StubSend,
    recv: StubRecv,
}

impl SendStream<Bytes> for StubBidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl RecvStream for StubBidi {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl BidiStream<Bytes> for StubBidi {
    type SendStream = StubSend;
    type RecvStream = StubRecv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

#[derive(Clone)]
struct StubOpener {
    state: Arc<StubState>,
}

impl OpenStreams<Bytes> for StubOpener {
    type BidiStream = StubBidi;
    type SendStream = StubSend;

    fn poll_open_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        Poll::Ready(Ok(StubBidi {
            send: StubSend { id: self.state.next_id() },
            recv: StubRecv { id: self.state.next_id() },
        }))
    }

    fn poll_open_send(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        Poll::Ready(Ok(StubSend { id: self.state.next_id() }))
    }

    fn close(&mut self, _code: h3::error::Code, _reason: &[u8]) {
        self.state.connection_closed.store(true, Ordering::SeqCst);
    }
}

struct StubConnection {
    state: Arc<StubState>,
}

impl OpenStreams<Bytes> for StubConnection {
    type BidiStream = StubBidi;
    type SendStream = StubSend;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        StubOpener { state: Arc::clone(&self.state) }.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        StubOpener { state: Arc::clone(&self.state) }.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        StubOpener { state: Arc::clone(&self.state) }.close(code, reason);
    }
}

impl h3::quic::Connection<Bytes> for StubConnection {
    type RecvStream = StubRecv;
    type OpenStreams = StubOpener;

    fn poll_accept_recv(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        Poll::Pending
    }

    fn poll_accept_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        Poll::Pending
    }

    fn opener(&self) -> Self::OpenStreams {
        StubOpener { state: Arc::clone(&self.state) }
    }
}

/// Brings up a real h3 client on top of the silent-server stub and drives its
/// connection task, returning the `SendRequest` a packet-up POST would clone.
async fn silent_server_h3()
-> (Arc<StubState>, SendRequest<StubOpener, Bytes>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(StubState::default());
    let (mut driver, send_request) = h3::client::new(StubConnection { state: Arc::clone(&state) })
        .await
        .expect("h3 client handshake over the stub connection");
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (state, send_request, driver_task)
}

/// Runs one packet-up POST on its own task, the way the packet-up driver does,
/// and waits far longer than any sane deadline for it to come back.
async fn spawn_post(send_request: SendRequest<StubOpener, Bytes>) -> anyhow::Result<()> {
    let post = tokio::spawn(async move {
        post_one_bounded(
            send_request,
            // Same absolute shape `XhttpTarget::uri_seq_prefix` produces.
            "https://example.com/xh/0011223344556677/",
            &HeaderMap::new(),
            0,
            Bytes::from_static(b"uplink frame"),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(600), post)
        .await
        .expect("packet-up POST must not outlive its deadline")
        .expect("packet-up POST task must not panic")
}

/// Opens the packet-up GET the driver drains, on the stub connection.
async fn open_stub_get(
    send: &mut SendRequest<StubOpener, Bytes>,
) -> h3::client::RequestStream<StubBidi, Bytes> {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://example.com/xh/0011223344556677")
        .version(http::Version::HTTP_3)
        .body(())
        .expect("stub GET request builds");
    send.send_request(request)
        .await
        .expect("stub connection accepts the GET stream")
}

fn stub_target() -> Arc<XhttpTarget> {
    Arc::new(XhttpTarget {
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        base_path: "/xh".to_string(),
        session_id: "0011223344556677".to_string(),
    })
}

#[tokio::test(start_paused = true)]
async fn dropping_the_session_kills_in_flight_posts() {
    let (state, mut send_request, _connection_driver) = silent_server_h3().await;
    let get_stream = open_stub_get(&mut send_request).await;
    let (in_tx, _in_rx) = inbound_channel();
    let (mut out_tx, out_rx) = outbound_channel();

    let driver =
        tokio::spawn(driver_loop_h3(send_request, stub_target(), in_tx, out_rx, get_stream, None));

    // One uplink frame: the driver turns it into a POST the silent server will
    // never answer.
    let frame = Bytes::from_static(b"uplink frame");
    out_tx.stage(Message::Binary(frame.clone()), frame.len());
    let queued = std::future::poll_fn(|cx| out_tx.poll_flush_queue(cx)).await;
    assert!(queued.is_ok(), "the driver must accept the uplink frame");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // What dropping the `XhttpStream` does: its `AbortOnDrop` aborts the driver
    // task. Every `SendRequest` clone must go with it — a POST left running
    // holds one, and that alone keeps the QUIC connection (and its UDP socket)
    // alive until the POST's own deadline.
    driver.abort();
    drop(out_tx);

    let closed = tokio::time::timeout(POST_TIMEOUT / 2, async {
        while !state.connection_closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "an in-flight POST must not outlive the driver that spawned it");
}

#[tokio::test(start_paused = true)]
async fn a_packet_up_post_to_a_silent_server_fails_at_its_deadline() {
    let (_state, send_request, _driver) = silent_server_h3().await;

    let error = spawn_post(send_request)
        .await
        .expect_err("a server that never answers cannot produce a successful POST");

    assert!(
        format!("{error:#}").contains("timed out"),
        "the POST must fail as a timeout, got: {error:#}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_timed_out_post_releases_the_h3_connection() {
    let (state, send_request, driver) = silent_server_h3().await;

    // The POST owns the only `SendRequest` clone, exactly as the spawned
    // per-POST task does in the packet-up driver.
    let _ = spawn_post(send_request).await;

    // Teardown chain: POST fails → its `SendRequest` clone drops → h3 closes
    // the QUIC connection → the connection driver (which owns the endpoint,
    // hence the UDP socket) exits.
    let closed = tokio::time::timeout(Duration::from_secs(60), async {
        while !state.connection_closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "dropping the last SendRequest must close the QUIC connection");

    let driver_exit = tokio::time::timeout(Duration::from_secs(60), driver).await;
    assert!(
        driver_exit.is_ok(),
        "the h3 connection driver must exit once the connection is closed"
    );
}

#[tokio::test]
async fn xhttp_h3_reuses_the_shared_endpoint_when_the_dial_has_no_fwmark() {
    let first = dial_endpoint(wildcard_v4(), None).expect("first xhttp/h3 endpoint binds");
    let second = dial_endpoint(wildcard_v4(), None).expect("second xhttp/h3 endpoint binds");

    // Two wildcard binds land on different ephemeral ports; an equal local
    // address means both dials got the same shared socket back.
    assert_eq!(
        first.local_addr().expect("first endpoint has a local addr"),
        second.local_addr().expect("second endpoint has a local addr"),
        "xhttp/h3 must not open a private UDP socket per session without fwmark"
    );
}

#[tokio::test]
async fn xhttp_h3_shares_the_endpoint_with_the_native_ws_h3_carrier() {
    let xhttp = dial_endpoint(wildcard_v4(), None).expect("xhttp/h3 endpoint binds");
    let ws = crate::h3::client_endpoint(wildcard_v4(), None).expect("ws_h3 endpoint binds");

    assert_eq!(
        xhttp.local_addr().expect("xhttp endpoint has a local addr"),
        ws.local_addr().expect("ws endpoint has a local addr"),
        "both H3 carriers must ride the same per-address-family UDP socket"
    );
}
