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
    nat::{ResponseSender, UdpResponseSender},
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
    fn make_udp_response_sender(
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
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

    fn classify(msg: Message) -> WsFrame {
        match msg {
            Message::Binary(b) => WsFrame::Binary(b),
            Message::Close(_) => WsFrame::Close,
            Message::Ping(p) => WsFrame::Ping(p),
            Message::Pong(_) => WsFrame::Pong,
            Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> Message { Message::Binary(data) }
    fn close_msg() -> Message { Message::Close(None) }
    fn close_try_again_msg() -> Message {
        Message::Close(Some(CloseFrame { code: close_code::AGAIN, reason: "".into() }))
    }
    fn ping_msg() -> Message { Message::Ping(Bytes::new()) }
    fn pong_msg(p: Bytes) -> Message { Message::Pong(p) }
    fn binary_len(m: &Message) -> Option<usize> {
        if let Message::Binary(b) = m { Some(b.len()) } else { None }
    }
    fn make_udp_response_sender(tx: mpsc::Sender<Message>, protocol: Protocol) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(WebSocketResponseSender { tx, protocol }))
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

    fn classify(msg: H3Message) -> WsFrame {
        match msg {
            H3Message::Binary(b) => WsFrame::Binary(b),
            H3Message::Close(_) => WsFrame::Close,
            H3Message::Ping(p) => WsFrame::Ping(p),
            H3Message::Pong(_) => WsFrame::Pong,
            H3Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> H3Message { H3Message::Binary(data) }
    fn close_msg() -> H3Message { H3Message::Close(None) }
    fn close_try_again_msg() -> H3Message { H3Message::Close(Some(CloseReason::new(1013, ""))) }
    fn ping_msg() -> H3Message { H3Message::Ping(Bytes::new()) }
    fn pong_msg(p: Bytes) -> H3Message { H3Message::Pong(p) }
    fn binary_len(m: &H3Message) -> Option<usize> {
        if let H3Message::Binary(b) = m { Some(b.len()) } else { None }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<H3Message>,
        _protocol: Protocol,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(Http3ResponseSender { tx }))
    }
}

struct WebSocketResponseSender {
    tx: mpsc::Sender<Message>,
    protocol: Protocol,
}

impl ResponseSender for WebSocketResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }
}

struct Http3ResponseSender {
    tx: mpsc::Sender<H3Message>,
}

impl ResponseSender for Http3ResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(H3Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http3
    }
}
