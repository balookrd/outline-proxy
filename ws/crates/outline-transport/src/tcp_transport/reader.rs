use anyhow::{Context, Result, anyhow, bail};
use crate::WebSocketClosed;
use outline_ss2022::Ss2022Error;
use futures_util::stream::SplitStream;
use futures_util::StreamExt;
use shadowsocks_crypto::{AeadCipher, CipherKind, SHADOWSOCKS_TAG_LEN, derive_subkey, increment_nonce, validate_ss2022_timestamp};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{Message, frame::coding::CloseCode};
use tracing::debug;
use crate::{UpstreamTransportGuard, WsTransportStream};
use crate::TransportOperation;

type WsStream = SplitStream<WsTransportStream>;

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

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

#[allow(async_fn_in_trait)]
pub trait ReadTransport: Send + 'static {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Concrete read transports
// ---------------------------------------------------------------------------

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
    stream: WsStream,
    ctrl_tx: mpsc::Sender<Message>,
    buffer: Vec<u8>,
    diag: WsReadDiag,
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
                    return Err(anyhow::Error::from(WebSocketClosed));
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
                    return Err(anyhow::Error::from(WebSocketClosed));
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
    reader: OwnedReadHalf,
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

// ---------------------------------------------------------------------------
// SS2022 state and helpers
// ---------------------------------------------------------------------------

pub(super) struct Ss2022TcpReaderState {
    pub request_salt: [u8; 32],
    pub response_header_read: bool,
}

pub(super) fn parse_ss2022_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<usize> {
    let expected_len = 1 + 8 + cipher.salt_len() + 2;
    if plaintext.len() != expected_len {
        bail!(Ss2022Error::InvalidResponseHeaderLength(plaintext.len()));
    }
    if plaintext[0] != 1 {
        bail!(Ss2022Error::InvalidResponseHeaderType(plaintext[0]));
    }
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[1..9]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let request_salt_start = 9;
    let request_salt_end = request_salt_start + cipher.salt_len();
    if &plaintext[request_salt_start..request_salt_end] != request_salt {
        bail!(Ss2022Error::RequestSaltMismatch);
    }

    Ok(u16::from_be_bytes([plaintext[request_salt_end], plaintext[request_salt_end + 1]]) as usize)
}

// ---------------------------------------------------------------------------
// Generic reader
// ---------------------------------------------------------------------------

pub struct TcpShadowsocksReader<T: ReadTransport> {
    transport: T,
    cipher: CipherKind,
    /// Master key stored on the stack.  Active portion: `&master_key[..cipher.key_len()]`.
    master_key: [u8; 32],
    /// Lazily-initialised session cipher (built after reading the response
    /// salt and deriving the subkey).  `None` until the first chunk arrives.
    cipher_state: Option<AeadCipher>,
    nonce: [u8; 12],
    ss2022: Option<Ss2022TcpReaderState>,
    _lifetime: Arc<UpstreamTransportGuard>,
    /// `true` when the last read ended with a clean WebSocket close (Close
    /// frame or EOF).  `false` means the stream was interrupted by a transport
    /// error (e.g. QUIC APPLICATION_CLOSE / H3_INTERNAL_ERROR).  Callers can
    /// use this to decide whether to report a runtime uplink failure.
    pub closed_cleanly: bool,
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

pub type WsTcpReader = TcpShadowsocksReader<WsReadTransport>;
pub type SocketTcpReader = TcpShadowsocksReader<SocketReadTransport>;

// ---------------------------------------------------------------------------
// TcpShadowsocksReader — WS constructor
// ---------------------------------------------------------------------------

impl TcpShadowsocksReader<WsReadTransport> {
    pub fn new(
        stream: WsStream,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
        ctrl_tx: mpsc::Sender<Message>,
    ) -> Self {
        let mut mk = [0u8; 32];
        mk[..master_key.len()].copy_from_slice(master_key);
        Self {
            transport: WsReadTransport {
                stream,
                ctrl_tx,
                buffer: Vec::new(),
                diag: WsReadDiag::default(),
            },
            cipher,
            master_key: mk,
            cipher_state: None,
            nonce: [0u8; 12],
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    /// Attach diagnostic context so that stream-level EOF logs can be
    /// correlated against the underlying shared H2/H3 connection.
    pub fn with_diag(mut self, diag: WsReadDiag) -> Self {
        self.transport.diag = diag;
        self
    }
}

// ---------------------------------------------------------------------------
// TcpShadowsocksReader — socket constructor
// ---------------------------------------------------------------------------

impl TcpShadowsocksReader<SocketReadTransport> {
    pub fn new_socket(
        reader: OwnedReadHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        let mut mk = [0u8; 32];
        mk[..master_key.len()].copy_from_slice(master_key);
        Self {
            transport: SocketReadTransport { reader },
            cipher,
            master_key: mk,
            cipher_state: None,
            nonce: [0u8; 12],
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TcpShadowsocksReader — generic methods
// ---------------------------------------------------------------------------

impl<T: ReadTransport> TcpShadowsocksReader<T> {
    pub fn with_request_salt(mut self, request_salt: Option<[u8; 32]>) -> Self {
        self.ss2022 = request_salt.map(|request_salt| Ss2022TcpReaderState {
            request_salt,
            response_header_read: false,
        });
        self
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        if self.cipher_state.is_none() {
            let salt = self.transport.read_exact(self.cipher.salt_len(), &mut self.closed_cleanly).await?;
            let key =
                derive_subkey(self.cipher, &self.master_key[..self.cipher.key_len()], &salt)?;
            self.cipher_state =
                Some(AeadCipher::new(self.cipher, &key[..self.cipher.key_len()])?);
        }

        let need_ss2022_response_header =
            self.ss2022.as_ref().is_some_and(|state| !state.response_header_read);
        if need_ss2022_response_header {
            let (request_salt, salt_len) = self
                .ss2022
                .as_ref()
                .map(|state| (state.request_salt, self.cipher.salt_len()))
                .ok_or_else(|| anyhow!("missing ss2022 request salt"))?;
            let header_len = 1 + 8 + self.cipher.salt_len() + 2 + SHADOWSOCKS_TAG_LEN;
            let mut header_buf = self.transport.read_exact(header_len, &mut self.closed_cleanly).await?;
            self.decrypt_in_place_session(&mut header_buf)?;
            let payload_len =
                parse_ss2022_response_header(self.cipher, &request_salt[..salt_len], &header_buf)?;
            let mut payload_buf =
                self.transport.read_exact(payload_len + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
            self.decrypt_in_place_session(&mut payload_buf)?;
            if let Some(state) = &mut self.ss2022 {
                state.response_header_read = true;
            }
            if !payload_buf.is_empty() {
                return Ok(payload_buf);
            }
            // Empty initial payload is valid in SS2022 (the server had no
            // target data to bundle yet).  Fall through to read the first
            // real data frame so callers never see an empty-payload return
            // that would be misinterpreted as EOF.
        }

        let mut len_buf = self.transport.read_exact(2 + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
        self.decrypt_in_place_session(&mut len_buf)?;

        if len_buf.len() != 2 {
            bail!("invalid decrypted length block");
        }
        let payload_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        if payload_len > self.cipher.max_payload_len() {
            bail!("payload length exceeds limit: {payload_len}");
        }

        let mut payload_buf = self.transport.read_exact(payload_len + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
        self.decrypt_in_place_session(&mut payload_buf)?;
        Ok(payload_buf)
    }

    /// Decrypt `buf` (layout: `[ciphertext || tag]`) in-place with the session
    /// cipher and advance the nonce.  No new allocation — `buf` is truncated to
    /// plaintext length on success.
    fn decrypt_in_place_session(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        self.cipher_state
            .as_ref()
            .ok_or_else(|| anyhow!("missing session cipher"))?
            .decrypt_in_place(&self.nonce, buf)?;
        increment_nonce(&mut self.nonce)?;
        Ok(())
    }
}
