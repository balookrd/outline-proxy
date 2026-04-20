use anyhow::{Context, Result, anyhow, bail};
use crate::WebSocketClosed;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::debug;

use shadowsocks_crypto::{
    AeadCipher, SHADOWSOCKS_TAG_LEN, derive_subkey, increment_nonce, validate_ss2022_timestamp,
};
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;

use super::{AbortOnDrop, WsTransportStream, UpstreamTransportGuard};

type WsSink = SplitSink<WsTransportStream, Message>;
type WsStream = SplitStream<WsTransportStream>;

// ---------------------------------------------------------------------------
// Transport traits
// ---------------------------------------------------------------------------

#[allow(async_fn_in_trait)]
pub trait WriteTransport: Send + 'static {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
    fn supports_half_close(&self) -> bool;
}

#[allow(async_fn_in_trait)]
pub trait ReadTransport: Send + 'static {
    async fn read_exact(&mut self, len: usize, closed_cleanly: &mut bool) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Concrete write transports
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub struct WsWriteTransport {
    data_tx: Option<mpsc::Sender<Message>>,
    /// Kept alive for its `AbortOnDrop` — aborts the writer task on drop.
    _writer_task: Option<AbortOnDrop>,
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
    writer: OwnedWriteHalf,
}

impl WriteTransport for SocketWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.writer
            .write_all(&frame)
            .await
            .context("failed to write encrypted frame to socket")
    }

    async fn close(&mut self) -> Result<()> {
        self.writer.shutdown().await.context("socket shutdown failed")
    }

    fn supports_half_close(&self) -> bool {
        true
    }
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
            let next = match self.stream.next().await {
                None => {
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
                Some(Ok(msg)) => msg,
                Some(Err(e)) => {
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
                    return Err(anyhow::Error::from(e).context("websocket read failed"));
                },
            };

            match next {
                Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
                Message::Close(frame) => {
                    *closed_cleanly = true;
                    debug!(
                        target: "outline_ws_rust::session_death",
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
// SS2022 state helpers
// ---------------------------------------------------------------------------

struct Ss2022TcpWriterState {
    request_salt: [u8; 32],
    header_sent: bool,
}

struct Ss2022TcpReaderState {
    request_salt: [u8; 32],
    response_header_read: bool,
}

// ---------------------------------------------------------------------------
// Generic writer / reader
// ---------------------------------------------------------------------------

pub struct TcpShadowsocksWriter<T: WriteTransport> {
    transport: T,
    cipher: CipherKind,
    /// Session cipher instance with the key schedule pre-computed; reused for
    /// every frame to avoid per-chunk AES key expansion.
    cipher_state: AeadCipher,
    nonce: [u8; 12],
    pending_salt: Option<[u8; 32]>,
    ss2022: Option<Ss2022TcpWriterState>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

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
// Concrete type aliases
// ---------------------------------------------------------------------------

pub type WsTcpWriter = TcpShadowsocksWriter<WsWriteTransport>;
pub type SocketTcpWriter = TcpShadowsocksWriter<SocketWriteTransport>;
pub type WsTcpReader = TcpShadowsocksReader<WsReadTransport>;
pub type SocketTcpReader = TcpShadowsocksReader<SocketReadTransport>;

// ---------------------------------------------------------------------------
// Enum wrappers for mixed-transport storage
// ---------------------------------------------------------------------------

/// Owns either a WebSocket or a plain-socket Shadowsocks writer.
/// Use the concrete aliases (`WsTcpWriter` / `SocketTcpWriter`) when the
/// transport kind is statically known at the call site.
pub enum TcpWriter {
    Ws(WsTcpWriter),
    Socket(SocketTcpWriter),
}

impl TcpWriter {
    pub fn request_salt(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ws(w) => w.request_salt(),
            Self::Socket(w) => w.request_salt(),
        }
    }

    pub fn supports_half_close(&self) -> bool {
        match self {
            Self::Ws(w) => w.supports_half_close(),
            Self::Socket(w) => w.supports_half_close(),
        }
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_chunk(payload).await,
            Self::Socket(w) => w.send_chunk(payload).await,
        }
    }

    pub async fn send_keepalive(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.send_keepalive().await,
            Self::Socket(w) => w.send_keepalive().await,
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        match self {
            Self::Ws(w) => w.close().await,
            Self::Socket(w) => w.close().await,
        }
    }
}

/// Owns either a WebSocket or a plain-socket Shadowsocks reader.
pub enum TcpReader {
    Ws(WsTcpReader),
    Socket(SocketTcpReader),
}

impl TcpReader {
    pub fn with_request_salt(self, salt: Option<[u8; 32]>) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_request_salt(salt)),
            Self::Socket(r) => Self::Socket(r.with_request_salt(salt)),
        }
    }

    /// Attach diagnostic context to a WebSocket reader; no-op for socket readers.
    pub fn with_diag(self, diag: WsReadDiag) -> Self {
        match self {
            Self::Ws(r) => Self::Ws(r.with_diag(diag)),
            other => other,
        }
    }

    pub fn closed_cleanly(&self) -> bool {
        match self {
            Self::Ws(r) => r.closed_cleanly,
            Self::Socket(r) => r.closed_cleanly,
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Ws(r) => r.read_chunk().await,
            Self::Socket(r) => r.read_chunk().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

fn build_ss2022_request_header(target: &TargetAddr) -> Result<(Vec<u8>, Vec<u8>)> {
    let target = target.to_wire_bytes()?;
    let padding_len: u16 = 16;
    let mut fixed = Vec::with_capacity(11);
    fixed.push(0);
    fixed.extend_from_slice(&unix_timestamp_secs()?.to_be_bytes());
    fixed.extend_from_slice(
        &(target.len() as u16 + 2 + usize::from(padding_len) as u16).to_be_bytes(),
    );

    let mut variable = Vec::with_capacity(target.len() + 2 + usize::from(padding_len));
    variable.extend_from_slice(&target);
    variable.extend_from_slice(&padding_len.to_be_bytes());
    let mut padding = vec![0u8; usize::from(padding_len)];
    rand::thread_rng().fill_bytes(&mut padding);
    variable.extend_from_slice(&padding);
    Ok((fixed, variable))
}

fn parse_ss2022_response_header(
    cipher: CipherKind,
    request_salt: &[u8],
    plaintext: &[u8],
) -> Result<usize> {
    let expected_len = 1 + 8 + cipher.salt_len() + 2;
    if plaintext.len() != expected_len {
        bail!("invalid ss2022 response header length: {}", plaintext.len());
    }
    if plaintext[0] != 1 {
        bail!("invalid ss2022 response header type: {}", plaintext[0]);
    }
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&plaintext[1..9]);
    validate_ss2022_timestamp(u64::from_be_bytes(timestamp_bytes))?;

    let request_salt_start = 9;
    let request_salt_end = request_salt_start + cipher.salt_len();
    if &plaintext[request_salt_start..request_salt_end] != request_salt {
        bail!("ss2022 response header request salt mismatch");
    }

    Ok(u16::from_be_bytes([plaintext[request_salt_end], plaintext[request_salt_end + 1]]) as usize)
}

// ---------------------------------------------------------------------------
// TcpShadowsocksWriter — WS constructor
// ---------------------------------------------------------------------------

impl TcpShadowsocksWriter<WsWriteTransport> {
    /// Connects the TCP shadowsocks writer.  Returns `(writer, ctrl_tx)` where
    /// `ctrl_tx` must be passed to the paired `TcpShadowsocksReader` so that
    /// Pong responses are sent through the priority channel in the writer task.
    pub async fn connect(
        sink: WsSink,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<(Self, mpsc::Sender<Message>)> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt[..cipher.salt_len()]);

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

        let key = derive_subkey(cipher, master_key, &salt[..cipher.salt_len()])?;
        let cipher_state = AeadCipher::new(cipher, &key[..cipher.key_len()])?;
        Ok((
            Self {
                transport: WsWriteTransport {
                    data_tx: Some(data_tx),
                    _writer_task: Some(AbortOnDrop::new(writer_task)),
                },
                cipher,
                cipher_state,
                nonce: [0u8; 12],
                pending_salt: Some(salt),
                ss2022: cipher
                    .is_ss2022()
                    .then_some(Ss2022TcpWriterState { request_salt: salt, header_sent: false }),
                _lifetime: lifetime,
            },
            ctrl_tx,
        ))
    }
}

// ---------------------------------------------------------------------------
// TcpShadowsocksWriter — socket constructor
// ---------------------------------------------------------------------------

impl TcpShadowsocksWriter<SocketWriteTransport> {
    pub fn connect_socket(
        writer: OwnedWriteHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<Self> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt[..cipher.salt_len()]);
        let key = derive_subkey(cipher, master_key, &salt[..cipher.salt_len()])?;
        let cipher_state = AeadCipher::new(cipher, &key[..cipher.key_len()])?;
        Ok(Self {
            transport: SocketWriteTransport { writer },
            cipher,
            cipher_state,
            nonce: [0u8; 12],
            pending_salt: Some(salt),
            ss2022: cipher
                .is_ss2022()
                .then_some(Ss2022TcpWriterState { request_salt: salt, header_sent: false }),
            _lifetime: lifetime,
        })
    }
}

// ---------------------------------------------------------------------------
// TcpShadowsocksWriter — generic methods
// ---------------------------------------------------------------------------

impl<T: WriteTransport> TcpShadowsocksWriter<T> {
    pub fn request_salt(&self) -> Option<[u8; 32]> {
        self.ss2022.as_ref().map(|state| state.request_salt)
    }

    pub fn supports_half_close(&self) -> bool {
        self.transport.supports_half_close()
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }

        if let Some(state) = &mut self.ss2022
            && !state.header_sent
        {
            let target = TargetAddr::from_wire_bytes(payload)
                .context("invalid ss2022 initial target header")?
                .0;
            let (fixed_header, variable_header) = build_ss2022_request_header(&target)?;
            let encrypted_fixed = self.cipher_state.encrypt(&self.nonce, &fixed_header)?;
            increment_nonce(&mut self.nonce)?;
            let encrypted_variable = self.cipher_state.encrypt(&self.nonce, &variable_header)?;
            increment_nonce(&mut self.nonce)?;

            let salt_len = self.pending_salt.as_ref().map_or(0, |_| self.cipher.salt_len());
            let mut frame = Vec::with_capacity(
                salt_len + encrypted_fixed.len() + encrypted_variable.len(),
            );
            if let Some(salt) = self.pending_salt.take() {
                state.request_salt = salt;
                frame.extend_from_slice(&salt[..self.cipher.salt_len()]);
            }
            frame.extend_from_slice(&encrypted_fixed);
            frame.extend_from_slice(&encrypted_variable);
            state.header_sent = true;

            self.write_frame(frame).await?;
            return Ok(());
        }

        for chunk in payload.chunks(self.cipher.max_payload_len()) {
            self.send_payload_frame(chunk).await?;
        }
        Ok(())
    }

    async fn send_payload_frame(&mut self, payload: &[u8]) -> Result<()> {
        let salt_len = self.pending_salt.as_ref().map_or(0, |_| self.cipher.salt_len());
        let frame_capacity = salt_len
            + 2 + SHADOWSOCKS_TAG_LEN   // encrypted length field
            + payload.len() + SHADOWSOCKS_TAG_LEN; // encrypted payload
        let mut frame = Vec::with_capacity(frame_capacity);
        if let Some(salt) = self.pending_salt.take() {
            frame.extend_from_slice(&salt[..self.cipher.salt_len()]);
        }
        let len = (payload.len() as u16).to_be_bytes();
        self.cipher_state.encrypt_into(&self.nonce, &len, &mut frame)?;
        increment_nonce(&mut self.nonce)?;
        self.cipher_state.encrypt_into(&self.nonce, payload, &mut frame)?;
        increment_nonce(&mut self.nonce)?;
        self.write_frame(frame).await?;
        Ok(())
    }

    /// Sends a keepalive frame through the upstream transport without
    /// delivering any application data to the destination. Used to defeat
    /// idle-connection timeouts in upstream servers and reverse proxies that
    /// look at *Shadowsocks* traffic (not just WebSocket frames) — e.g. an
    /// outline-ss-server running behind HAProxy with a short `timeout
    /// server`, where a WebSocket Ping resets only the WS leg up to HAProxy
    /// but never reaches the Shadowsocks daemon behind it.
    ///
    /// For Shadowsocks 2022 this emits an encrypted 0-length data chunk that
    /// the server will decrypt and forward as a 0-byte write to the
    /// destination socket — a no-op that nonetheless resets the server's
    /// idle timer.
    ///
    /// For Shadowsocks-1 (legacy AEAD) it is a no-op: the protocol has no
    /// chunk framing on the data path, so any extra bytes would be
    /// indistinguishable from real application data and corrupt the stream.
    /// Such uplinks rely on the WebSocket Ping that the writer task sends
    /// independently.
    pub async fn send_keepalive(&mut self) -> Result<()> {
        // SS2022 keepalive only makes sense after the request header has
        // already been sent; before that, the very first chunk on the wire
        // *is* the SS2022 header.
        let header_done = self.ss2022.as_ref().is_some_and(|state| state.header_sent);
        if !header_done {
            return Ok(());
        }
        debug!(target: "outline_ws_rust::transport::tcp_keepalive", "sending Shadowsocks 0-length keepalive chunk");
        self.send_payload_frame(&[]).await
    }

    pub async fn close(&mut self) -> Result<()> {
        self.transport.close().await
    }

    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.transport.write_frame(frame).await
    }
}

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
            let encrypted_header = self.transport.read_exact(header_len, &mut self.closed_cleanly).await?;
            let header = self.decrypt_with_session(&encrypted_header)?;
            let payload_len =
                parse_ss2022_response_header(self.cipher, &request_salt[..salt_len], &header)?;
            let encrypted_payload =
                self.transport.read_exact(payload_len + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
            let payload = self.decrypt_with_session(&encrypted_payload)?;
            if let Some(state) = &mut self.ss2022 {
                state.response_header_read = true;
            }
            if !payload.is_empty() {
                return Ok(payload);
            }
            // Empty initial payload is valid in SS2022 (the server had no
            // target data to bundle yet).  Fall through to read the first
            // real data frame so callers never see an empty-payload return
            // that would be misinterpreted as EOF.
        }

        let encrypted_len = self.transport.read_exact(2 + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
        let len = self.decrypt_with_session(&encrypted_len)?;

        if len.len() != 2 {
            bail!("invalid decrypted length block");
        }
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if payload_len > self.cipher.max_payload_len() {
            bail!("payload length exceeds limit: {payload_len}");
        }

        let encrypted_payload = self.transport.read_exact(payload_len + SHADOWSOCKS_TAG_LEN, &mut self.closed_cleanly).await?;
        self.decrypt_with_session(&encrypted_payload)
    }

    /// Decrypt `ciphertext` with the session cipher and advance the nonce.
    /// Kept as a tight helper so the session-cipher borrow does not straddle
    /// the surrounding `read_exact` `&mut self` calls.
    fn decrypt_with_session(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self
            .cipher_state
            .as_ref()
            .ok_or_else(|| anyhow!("missing session cipher"))?
            .decrypt(&self.nonce, ciphertext)?;
        increment_nonce(&mut self.nonce)?;
        Ok(plaintext)
    }
}
