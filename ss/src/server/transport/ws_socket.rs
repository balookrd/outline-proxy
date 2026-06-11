use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::{CloseFrame, Message, WebSocket, close_code};
use bytes::Bytes;
use futures_util::{
    SinkExt, StreamExt,
    future::BoxFuture,
    stream::{SplitSink, SplitStream},
};
use sockudo_ws::{
    Http3 as H3Transport, Message as H3Message, SplitReader as H3SplitReader,
    SplitWriter as H3SplitWriter, Stream as H3Stream, WebSocketStream as H3WebSocketStream,
    error::CloseReason,
};
use tokio::sync::mpsc;

use crate::{
    metrics::Protocol,
    server::nat::{ResponseSender, UdpResponseSender},
};

pub(super) enum WsFrame {
    Binary(Bytes),
    Close,
    Ping(Bytes),
    Pong,
    Text,
}

pub(super) trait WsSocket: Send + Sized + 'static {
    type Msg: Send + 'static;
    type Reader: Send + 'static;
    type Writer: Send + 'static;

    fn split_io(self) -> (Self::Reader, Self::Writer);
    fn recv(
        reader: &mut Self::Reader,
    ) -> impl Future<Output = Result<Option<Self::Msg>>> + Send + '_;
    fn send(
        writer: &mut Self::Writer,
        msg: Self::Msg,
    ) -> impl Future<Output = Result<()>> + Send + '_;
    fn finish(writer: &mut Self::Writer) -> impl Future<Output = ()> + Send + '_;
    /// Flush any control-frame responses the transport buffered but has not
    /// yet written — chiefly a `Pong` the split reader queued in reply to a
    /// client keepalive `Ping`. The per-session writer task calls this on a
    /// timer (`WS_CONTROL_FLUSH_INTERVAL_SECS`) so that on a quiet datagram
    /// channel the reactive Pong still reaches the client and resets its
    /// read-idle watchdog — WITHOUT the relay ever emitting a
    /// server-originated Ping, which is unsafe on the H3 carrier.
    fn flush(writer: &mut Self::Writer) -> impl Future<Output = Result<()>> + Send + '_;
    /// Whether this carrier multiplexes WebSocket frames over an HTTP/3
    /// (QUIC) stream. On H3 a relay must NOT emit a server→client keepalive
    /// `Ping` (an unconditional Ping write races stream teardown on a
    /// `shuffle_timer` reroll and escalates to a connection-level
    /// `H3_INTERNAL_ERROR` that kills every multiplexed stream on the QUIC
    /// connection) and must NOT run pong-deadline reaping (the client's
    /// keepalive Ping is swallowed by the split reader, so `last_inbound`
    /// never refreshes and the deadline would false-fire on a live session).
    /// The QUIC layer's own keep-alive / idle-timeout detects a dead peer,
    /// and the writer task's periodic `flush` delivers the reactive Pong.
    fn is_h3() -> bool;
    fn classify(msg: Self::Msg) -> WsFrame;
    fn binary_msg(data: Bytes) -> Self::Msg;
    fn close_msg() -> Self::Msg;
    /// Close frame asking the client to retry the same request (RFC 6455 code 1013).
    /// Used when the server cannot reach the upstream target but the client
    /// may succeed if it retries on the same or a different uplink.
    fn close_try_again_msg() -> Self::Msg;
    fn ping_msg() -> Self::Msg;
    fn pong_msg(payload: Bytes) -> Self::Msg;
    fn binary_len(msg: &Self::Msg) -> Option<usize>;
    /// Approximate payload length of a frame, regardless of kind. Used by
    /// the probe-sink helper to cap how many bytes of junk a rejected peer
    /// can drain before we close: counting only `Binary` (via
    /// [`Self::binary_len`]) would let a probe spray Pings forever without
    /// ever tripping the cap. Frame-header overhead is intentionally not
    /// included — the cap is a coarse safety bound, not a billing meter.
    fn msg_len(msg: &Self::Msg) -> usize;
    fn make_udp_response_sender(
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
        app_protocol: crate::metrics::AppProtocol,
    ) -> UdpResponseSender;
}

pub(super) struct AxumWs(pub(super) WebSocket);

impl WsSocket for AxumWs {
    type Msg = Message;
    type Reader = SplitStream<WebSocket>;
    type Writer = SplitSink<WebSocket, Message>;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        let (sink, stream) = self.0.split();
        (stream, sink)
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Message>> {
        match reader.next().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(anyhow::Error::from(e).context("websocket receive failure")),
            None => Ok(None),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: Message) -> Result<()> {
        writer.send(msg).await.context("failed to write websocket frame")
    }

    async fn finish(_writer: &mut Self::Writer) {}

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        // h1/h2: the split stream surfaces an inbound Ping to the relay
        // loop, which queues the Pong reply through the writer's
        // `outbound_ctrl` channel — so the writer is already woken to send
        // it, and nothing sits buffered behind a quiet writer. axum's
        // `SplitSink::send` flushes each frame as it goes, so there is
        // nothing left to drain here.
        Ok(())
    }

    fn is_h3() -> bool {
        false
    }

    fn classify(msg: Message) -> WsFrame {
        match msg {
            Message::Binary(b) => WsFrame::Binary(b),
            Message::Close(_) => WsFrame::Close,
            Message::Ping(p) => WsFrame::Ping(p),
            Message::Pong(_) => WsFrame::Pong,
            Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> Message {
        Message::Binary(data)
    }
    fn close_msg() -> Message {
        Message::Close(None)
    }
    fn close_try_again_msg() -> Message {
        Message::Close(Some(CloseFrame {
            code: close_code::AGAIN,
            reason: "".into(),
        }))
    }
    fn ping_msg() -> Message {
        Message::Ping(Bytes::new())
    }
    fn pong_msg(p: Bytes) -> Message {
        Message::Pong(p)
    }
    fn binary_len(m: &Message) -> Option<usize> {
        if let Message::Binary(b) = m {
            Some(b.len())
        } else {
            None
        }
    }
    fn msg_len(m: &Message) -> usize {
        match m {
            Message::Binary(b) => b.len(),
            Message::Text(t) => t.len(),
            Message::Ping(p) | Message::Pong(p) => p.len(),
            Message::Close(_) => 0,
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<Message>,
        protocol: Protocol,
        app_protocol: crate::metrics::AppProtocol,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(WebSocketResponseSender { tx, protocol, app_protocol }))
    }
}

pub(super) struct H3Ws(pub(super) H3WebSocketStream<H3Stream<H3Transport>>);

impl WsSocket for H3Ws {
    type Msg = H3Message;
    type Reader = H3SplitReader<H3Stream<H3Transport>>;
    type Writer = H3SplitWriter<H3Stream<H3Transport>>;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        self.0.split()
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<H3Message>> {
        match reader.next().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(anyhow::Error::from(e).context("websocket receive failure")),
            None => Ok(None),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: H3Message) -> Result<()> {
        writer.send(msg).await.context("failed to write websocket frame")
    }

    async fn finish(writer: &mut Self::Writer) {
        let _ = writer.close(1000, "").await;
    }

    async fn flush(writer: &mut Self::Writer) -> Result<()> {
        // The vendored sockudo split reader answers a client Ping by
        // parking a Pong in an internal channel that is only drained when
        // the writer runs `process_control_requests` — which `flush` does
        // (as does `send`). On a quiet UDP datagram channel this timed
        // flush is the only thing that delivers that Pong to the client,
        // keeping its 300 s read-idle watchdog from tripping — and it does
        // so WITHOUT writing a server-originated Ping, which on H3 races
        // stream teardown and escalates to a connection-level
        // `H3_INTERNAL_ERROR`.
        writer
            .flush()
            .await
            .context("failed to flush websocket control frames")
    }

    fn is_h3() -> bool {
        true
    }

    fn classify(msg: H3Message) -> WsFrame {
        match msg {
            H3Message::Binary(b) => WsFrame::Binary(b),
            H3Message::Close(_) => WsFrame::Close,
            H3Message::Ping(p) => WsFrame::Ping(p),
            H3Message::Pong(_) => WsFrame::Pong,
            H3Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> H3Message {
        H3Message::Binary(data)
    }
    fn close_msg() -> H3Message {
        H3Message::Close(None)
    }
    fn close_try_again_msg() -> H3Message {
        H3Message::Close(Some(CloseReason::new(1013, "")))
    }
    fn ping_msg() -> H3Message {
        H3Message::Ping(Bytes::new())
    }
    fn pong_msg(p: Bytes) -> H3Message {
        H3Message::Pong(p)
    }
    fn binary_len(m: &H3Message) -> Option<usize> {
        if let H3Message::Binary(b) = m {
            Some(b.len())
        } else {
            None
        }
    }
    fn msg_len(m: &H3Message) -> usize {
        match m {
            H3Message::Binary(b) => b.len(),
            H3Message::Text(t) => t.len(),
            H3Message::Ping(p) | H3Message::Pong(p) => p.len(),
            H3Message::Close(_) => 0,
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<H3Message>,
        _protocol: Protocol,
        app_protocol: crate::metrics::AppProtocol,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(Http3ResponseSender { tx, app_protocol }))
    }
}

struct WebSocketResponseSender {
    tx: mpsc::Sender<Message>,
    protocol: Protocol,
    app_protocol: crate::metrics::AppProtocol,
}

impl ResponseSender for WebSocketResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn app_protocol(&self) -> crate::metrics::AppProtocol {
        self.app_protocol
    }
}

struct Http3ResponseSender {
    tx: mpsc::Sender<H3Message>,
    app_protocol: crate::metrics::AppProtocol,
}

impl ResponseSender for Http3ResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(H3Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http3
    }

    fn app_protocol(&self) -> crate::metrics::AppProtocol {
        self.app_protocol
    }
}
