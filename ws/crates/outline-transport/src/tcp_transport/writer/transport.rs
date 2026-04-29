use anyhow::{Context, Result, anyhow};
use crate::TransportOperation;
use futures_util::stream::SplitSink;
use futures_util::SinkExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::{AbortOnDrop, TransportStream};

pub(super) type WsSink = SplitSink<TransportStream, Message>;

#[allow(async_fn_in_trait)]
pub trait WriteTransport: Send + 'static {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
    fn supports_half_close(&self) -> bool;
}

#[doc(hidden)]
pub struct WsWriteTransport {
    data_tx: Option<mpsc::Sender<Message>>,
    /// Kept alive for its `AbortOnDrop` — aborts the writer task on drop.
    _writer_task: Option<AbortOnDrop>,
}

impl WsWriteTransport {
    /// Build a WS write transport by spawning the multiplexing writer task and
    /// returning the control-channel sender alongside it.  The control sender
    /// must be passed to the paired reader so that Pong responses go through
    /// the priority channel.
    pub(super) fn spawn(sink: WsSink) -> (Self, mpsc::Sender<Message>) {
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
        // Note: an earlier iteration of this writer task fired a periodic
        // WebSocket Ping (intended as an idle keepalive against HAProxy /
        // nginx `proxy_*_timeout`).  In real deployments — HAProxy →
        // outline-ss-server, plain outline-ss-server over H3 — those Pings
        // poisoned the upstream Shadowsocks state and caused immediate
        // chunk-0 EOF on the next data frame, the exact opposite of the
        // intended effect.  Application-level keepalive that the upstream
        // Shadowsocks daemon actually sees is provided by `send_keepalive`
        // (a 0-length encrypted SS2022 chunk) driven from the SOCKS uplink
        // task; nothing here injects WebSocket control frames.
        let writer_task = tokio::spawn(async move {
            let mut ws_sink = sink;
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = ctrl_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                            None => ctrl_open = false,
                        },
                        msg = data_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                            None => { let _ = ws_sink.close().await; return; }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(m) => {
                            if ws_sink.send(m).await.is_err() {
                                return;
                            }
                        },
                        None => {
                            let _ = ws_sink.close().await;
                            return;
                        },
                    }
                }
            }
        });
        (
            Self {
                data_tx: Some(data_tx),
                _writer_task: Some(AbortOnDrop::new(writer_task)),
            },
            ctrl_tx,
        )
    }
}

impl WriteTransport for WsWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?
            .send(Message::Binary(frame.into()))
            .await
            .context("failed to send encrypted frame")
    }

    async fn close(&mut self) -> Result<()> {
        // Drop the sender — the writer task sees None from data_rx,
        // sends a WebSocket Close frame, and exits on its own.
        //
        // We intentionally do NOT take and await the writer task here.
        // The previous implementation called `writer_task.take()` +
        // `task.finish().await`, which moved the real JoinHandle out of
        // its AbortOnDrop wrapper.  If this future was then cancelled
        // (e.g. by a probe timeout), the handle was *detached* instead
        // of aborted — leaking the writer task, its SplitSink, the
        // underlying H2 connection, and the TCP socket.
        //
        // Leaving the AbortOnDrop in place guarantees that when this
        // TcpShadowsocksWriter is dropped, the writer task is aborted
        // regardless of how the caller exits (normal return, error, or
        // cancellation).
        drop(self.data_tx.take());
        Ok(())
    }

    fn supports_half_close(&self) -> bool {
        false
    }
}

#[doc(hidden)]
pub struct SocketWriteTransport {
    pub(super) writer: OwnedWriteHalf,
}

impl WriteTransport for SocketWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.writer
            .write_all(&frame)
            .await
            .context("failed to write encrypted frame to socket")
    }

    async fn close(&mut self) -> Result<()> {
        self.writer.shutdown().await.context(TransportOperation::SocketShutdown)
    }

    fn supports_half_close(&self) -> bool {
        true
    }
}

#[cfg(feature = "quic")]
#[doc(hidden)]
pub struct QuicWriteTransport {
    pub(super) send: Option<quinn::SendStream>,
}

#[cfg(feature = "quic")]
impl WriteTransport for QuicWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        let send = self
            .send
            .as_mut()
            .ok_or_else(|| anyhow!("quic writer already closed"))?;
        send.write_all(&frame)
            .await
            .context("failed to write encrypted frame to quic stream")
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut send) = self.send.take() {
            // `finish()` issues FIN; quinn returns Err only on already-closed
            // streams which we treat as already-cleaned-up.
            let _ = send.finish();
        }
        Ok(())
    }

    fn supports_half_close(&self) -> bool {
        // QUIC streams support unidirectional FIN — write half can close
        // independently of the read half.
        true
    }
}
