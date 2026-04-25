use anyhow::{Context, Result, bail};
use crate::WsClosed;
use futures_util::stream::SplitStream;
use futures_util::StreamExt;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{Message, frame::coding::CloseCode};
use tracing::debug;
use crate::WsTransportStream;
use crate::TransportOperation;

pub(super) type WsStream = SplitStream<WsTransportStream>;

// Maximum time an upstream WebSocket read may sit idle without producing any
// frame (data, ping, pong, or close) before the reader assumes the stream is
// dead and lets the session fail over to a fresh uplink.  Without this bound,
// a silently-broken shared H2/H3 connection (NAT loss on the router path, or a
// middlebox that drops idle TCP without sending FIN) leaves the reader blocked
// on `stream.next()` forever — the SOCKS session idle-watcher only fires after
// 5 minutes of no payload, and during that window reconnects hit the same
// half-dead cached shared connection and fail.
//
// H2/H3 keepalive PING frames operate at the protocol multiplexer level and
// do NOT produce WS-layer messages, so stream.next() stays blocked even on a
// healthy H2/H3 connection that is merely waiting for the upstream target to
// start responding.  Long-running requests such as Codex/ChatGPT context
// compact operations can legitimately spend 2–5 minutes receiving nothing
// while the server processes the request before starting the streaming
// response.  120s was too short and caused "stream disconnected before
// completion" errors for those operations.
//
// Dead connections are detected by other mechanisms before this timeout fires:
//  • H2 keepalive: detects a dead connection in ~40s (20s interval + 20s timeout)
//  • H3 QUIC: idle timeout 120s with 10s ping interval
//  • tungstenite IO error: NAT/middlebox RST propagates immediately
// This timeout is therefore only a last-resort defence for H1 WS with a
// completely silent middlebox.  300s matches the SOCKS idle-watcher timeout,
// so both defences fire at the same time when the upstream is truly dead.
const WS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[allow(async_fn_in_trait)]
pub trait ReadTransport: Send + 'static {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>>;
}

/// Diagnostic context attached to a WebSocket reader so that stream-level EOF
/// logs include the uplink name, target, and — for H2/H3 streams — the shared
/// connection id.  Correlating bursts of EOFs with a single `conn_id` vs many
/// distinguishes "underlying transport died" from "server reset individual
/// streams at the app layer".
#[derive(Clone, Debug, Default)]
pub struct WsReadDiag {
    pub conn_id: Option<u64>,
    pub mode: &'static str,
    pub uplink: String,
    pub target: String,
}

#[doc(hidden)]
pub struct WsReadTransport {
    pub(super) stream: WsStream,
    pub(super) ctrl_tx: mpsc::Sender<Message>,
    pub(super) buffer: Vec<u8>,
    pub(super) diag: WsReadDiag,
}

impl ReadTransport for WsReadTransport {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>> {
        while self.buffer.len() < len {
            let next = match timeout(WS_READ_IDLE_TIMEOUT, self.stream.next()).await {
                Err(_elapsed) => {
                    // `closed_cleanly` stays false so the session layer reports
                    // a runtime uplink failure; this is what triggers prompt
                    // failover and cache eviction of the broken shared conn.
                    debug!(
                        target: "outline_ws_rust::session_death",
                        timeout_secs = WS_READ_IDLE_TIMEOUT.as_secs(),
                        need = len,
                        have = self.buffer.len(),
                        uplink = %self.diag.uplink,
                        target_addr = %self.diag.target,
                        mode = self.diag.mode,
                        conn_id = ?self.diag.conn_id,
                        "reader: websocket stream idle beyond timeout; treating as dead"
                    );
                    bail!(
                        "websocket upstream read idle for {}s on uplink {} target {}",
                        WS_READ_IDLE_TIMEOUT.as_secs(),
                        self.diag.uplink,
                        self.diag.target,
                    );
                },
                Ok(None) => {
                    *closed_cleanly = true;
                    debug!(
                        target: "outline_ws_rust::session_death",
                        need = len,
                        have = self.buffer.len(),
                        uplink = %self.diag.uplink,
                        target_addr = %self.diag.target,
                        mode = self.diag.mode,
                        conn_id = ?self.diag.conn_id,
                        "reader: websocket stream returned None (EOF without Close frame)"
                    );
                    return Err(anyhow::Error::from(WsClosed));
                },
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(e))) => {
                    debug!(
                        target: "outline_ws_rust::session_death",
                        need = len,
                        have = self.buffer.len(),
                        uplink = %self.diag.uplink,
                        target_addr = %self.diag.target,
                        mode = self.diag.mode,
                        conn_id = ?self.diag.conn_id,
                        error = %format!("{e}"),
                        "reader: websocket stream yielded error"
                    );
                    // Use Result-form .context() so the typed marker is
                    // preserved in the anyhow chain for downcast_ref (anyhow
                    // only preserves typed context when applied to Result,
                    // not when applied to an already-constructed Error).
                    return Err(e).context(TransportOperation::WebSocketRead);
                },
            };

            match next {
                Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
                Message::Close(frame) => {
                    // RFC 6455 code 1013 "Try Again Later" means the server
                    // could not reach the upstream target but the request
                    // itself is valid.  Treat it the same as a TCP RST:
                    // closed_cleanly stays false so the proxy layer retries
                    // on the same or a different uplink.  All other close
                    // codes are normal terminations (closed_cleanly = true).
                    let try_again = frame
                        .as_ref()
                        .map(|f| f.code == CloseCode::Again)
                        .unwrap_or(false);
                    if !try_again {
                        *closed_cleanly = true;
                    }
                    debug!(
                        target: "outline_ws_rust::session_death",
                        try_again,
                        frame = ?frame,
                        "reader: websocket received Close frame from upstream"
                    );
                    return Err(anyhow::Error::from(WsClosed));
                },
                Message::Ping(payload) => {
                    let _ = self.ctrl_tx.try_send(Message::Pong(payload));
                },
                Message::Pong(_) => {},
                Message::Text(_) => bail!("unexpected text websocket frame"),
                Message::Frame(_) => {},
            }
        }

        let tail = self.buffer.split_off(len);
        Ok(std::mem::replace(&mut self.buffer, tail))
    }
}

#[doc(hidden)]
pub struct SocketReadTransport {
    pub(super) reader: OwnedReadHalf,
}

impl ReadTransport for SocketReadTransport {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        if let Err(err) = self.reader.read_exact(&mut buf).await {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                *closed_cleanly = true;
                bail!("socket closed");
            }
            return Err(err).context("socket read failed");
        }
        Ok(buf)
    }
}

#[cfg(feature = "quic")]
#[doc(hidden)]
pub struct QuicReadTransport {
    pub(super) recv: quinn::RecvStream,
}

#[cfg(feature = "quic")]
impl ReadTransport for QuicReadTransport {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        match self.recv.read_exact(&mut buf).await {
            Ok(()) => Ok(buf),
            Err(quinn::ReadExactError::FinishedEarly(_)) => {
                *closed_cleanly = true;
                bail!("quic stream closed");
            }
            Err(e) => Err(e).context("quic stream read failed"),
        }
    }
}
