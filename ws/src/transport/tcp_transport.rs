use anyhow::{Context, Result, anyhow, bail};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::crypto::{
    SHADOWSOCKS_TAG_LEN, decrypt, derive_subkey, encrypt, increment_nonce,
    validate_ss2022_timestamp,
};
use crate::types::{CipherKind, TargetAddr};

use super::{AbortOnDrop, AnyWsStream, UpstreamTransportGuard};

type WsSink = SplitSink<AnyWsStream, Message>;
type WsStream = SplitStream<AnyWsStream>;

enum TcpWriteTransport {
    Websocket {
        data_tx: Option<mpsc::Sender<Message>>,
        writer_task: Option<AbortOnDrop>,
    },
    Socket {
        writer: OwnedWriteHalf,
    },
}

enum TcpReadTransport {
    Websocket {
        stream: WsStream,
        ctrl_tx: mpsc::Sender<Message>,
    },
    Socket {
        reader: OwnedReadHalf,
    },
}

struct Ss2022TcpWriterState {
    request_salt: Vec<u8>,
    header_sent: bool,
}

struct Ss2022TcpReaderState {
    request_salt: Vec<u8>,
    response_header_read: bool,
}

pub struct TcpShadowsocksWriter {
    transport: TcpWriteTransport,
    cipher: CipherKind,
    key: Vec<u8>,
    nonce: [u8; 12],
    pending_salt: Option<Vec<u8>>,
    ss2022: Option<Ss2022TcpWriterState>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub struct TcpShadowsocksReader {
    transport: TcpReadTransport,
    cipher: CipherKind,
    master_key: Vec<u8>,
    key: Option<Vec<u8>>,
    nonce: [u8; 12],
    buffer: Vec<u8>,
    ss2022: Option<Ss2022TcpReaderState>,
    _lifetime: Arc<UpstreamTransportGuard>,
    /// `true` when the last read ended with a clean WebSocket close (Close
    /// frame or EOF).  `false` means the stream was interrupted by a transport
    /// error (e.g. QUIC APPLICATION_CLOSE / H3_INTERNAL_ERROR).  Callers can
    /// use this to decide whether to report a runtime uplink failure.
    pub closed_cleanly: bool,
}

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

impl TcpShadowsocksWriter {
    /// Connects the TCP shadowsocks writer.  Returns `(writer, ctrl_tx)` where
    /// `ctrl_tx` must be passed to the paired `TcpShadowsocksReader` so that
    /// Pong responses are sent through the priority channel in the writer task.
    pub(crate) async fn connect(
        sink: WsSink,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<(Self, mpsc::Sender<Message>)> {
        let mut salt = vec![0u8; cipher.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);

        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
        let writer_task = tokio::spawn(async move {
            let mut ws_sink = sink;
            let mut ctrl_open = true;
            // Send a WebSocket Ping every 20 s when the stream is idle.
            // Prevents server-side idle timeouts (e.g. nginx proxy_read_timeout)
            // from dropping the connection during quiet SSH sessions or any
            // other long-lived flow with no user activity.
            let mut ping_timer =
                tokio::time::interval(std::time::Duration::from_secs(20));
            ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ping_timer.tick().await; // consume the immediate first tick
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
                        _ = ping_timer.tick() => {
                            if ws_sink.send(Message::Ping(vec![].into())).await.is_err() { return; }
                        }
                    }
                } else {
                    tokio::select! {
                        msg = data_rx.recv() => match msg {
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() {
                                    return;
                                }
                            },
                            None => {
                                let _ = ws_sink.close().await;
                                return;
                            },
                        },
                        _ = ping_timer.tick() => {
                            if ws_sink.send(Message::Ping(vec![].into())).await.is_err() { return; }
                        }
                    }
                }
            }
        });

        let request_salt = salt.clone();
        Ok((
            Self {
                transport: TcpWriteTransport::Websocket {
                    data_tx: Some(data_tx),
                    writer_task: Some(AbortOnDrop::new(writer_task)),
                },
                cipher,
                key: derive_subkey(cipher, master_key, &salt)?,
                nonce: [0u8; 12],
                pending_salt: Some(salt),
                ss2022: cipher
                    .is_ss2022()
                    .then(|| Ss2022TcpWriterState { request_salt, header_sent: false }),
                _lifetime: lifetime,
            },
            ctrl_tx,
        ))
    }

    pub(crate) fn connect_socket(
        writer: OwnedWriteHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Result<Self> {
        let mut salt = vec![0u8; cipher.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        Ok(Self {
            transport: TcpWriteTransport::Socket { writer },
            cipher,
            key: derive_subkey(cipher, master_key, &salt)?,
            nonce: [0u8; 12],
            pending_salt: Some(salt.clone()),
            ss2022: cipher
                .is_ss2022()
                .then(|| Ss2022TcpWriterState { request_salt: salt, header_sent: false }),
            _lifetime: lifetime,
        })
    }

    pub fn request_salt(&self) -> Option<&[u8]> {
        self.ss2022.as_ref().map(|state| state.request_salt.as_slice())
    }

    pub fn supports_half_close(&self) -> bool {
        matches!(self.transport, TcpWriteTransport::Socket { .. })
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }

        if let Some(state) = &mut self.ss2022 {
            if !state.header_sent {
                let target = TargetAddr::from_wire_bytes(payload)
                    .context("invalid ss2022 initial target header")?
                    .0;
                let (fixed_header, variable_header) = build_ss2022_request_header(&target)?;
                let encrypted_fixed = encrypt(self.cipher, &self.key, &self.nonce, &fixed_header)?;
                increment_nonce(&mut self.nonce);
                let encrypted_variable =
                    encrypt(self.cipher, &self.key, &self.nonce, &variable_header)?;
                increment_nonce(&mut self.nonce);

                let pending_salt_len = self.pending_salt.as_ref().map_or(0, Vec::len);
                let mut frame = Vec::with_capacity(
                    pending_salt_len + encrypted_fixed.len() + encrypted_variable.len(),
                );
                if let Some(salt) = self.pending_salt.take() {
                    state.request_salt = salt.clone();
                    frame.extend_from_slice(&salt);
                }
                frame.extend_from_slice(&encrypted_fixed);
                frame.extend_from_slice(&encrypted_variable);
                state.header_sent = true;

                self.write_frame(frame).await?;
                return Ok(());
            }
        }

        for chunk in payload.chunks(self.cipher.max_payload_len()) {
            self.send_payload_frame(chunk).await?;
        }
        Ok(())
    }

    async fn send_payload_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = (payload.len() as u16).to_be_bytes();
        let encrypted_len = encrypt(self.cipher, &self.key, &self.nonce, &len)?;
        increment_nonce(&mut self.nonce);

        let encrypted_payload = encrypt(self.cipher, &self.key, &self.nonce, payload)?;
        increment_nonce(&mut self.nonce);

        let pending_salt_len = self.pending_salt.as_ref().map_or(0, Vec::len);
        let mut frame =
            Vec::with_capacity(pending_salt_len + encrypted_len.len() + encrypted_payload.len());
        if let Some(salt) = self.pending_salt.take() {
            frame.extend_from_slice(&salt);
        }
        frame.extend_from_slice(&encrypted_len);
        frame.extend_from_slice(&encrypted_payload);

        self.write_frame(frame).await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        match &mut self.transport {
            TcpWriteTransport::Websocket { data_tx, writer_task } => {
                drop(data_tx.take());
                if let Some(task) = writer_task.take() {
                    task.finish().await;
                }
            },
            TcpWriteTransport::Socket { writer } => {
                writer.shutdown().await.context("socket shutdown failed")?;
            },
        }
        Ok(())
    }

    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        match &mut self.transport {
            TcpWriteTransport::Websocket { data_tx, .. } => data_tx
                .as_ref()
                .ok_or_else(|| anyhow!("writer already closed"))?
                .send(Message::Binary(frame.into()))
                .await
                .context("failed to send encrypted frame"),
            TcpWriteTransport::Socket { writer } => writer
                .write_all(&frame)
                .await
                .context("failed to write encrypted frame to socket"),
        }
    }
}

impl TcpShadowsocksReader {
    pub(crate) fn new(
        stream: WsStream,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
        ctrl_tx: mpsc::Sender<Message>,
    ) -> Self {
        Self {
            transport: TcpReadTransport::Websocket { stream, ctrl_tx },
            cipher,
            master_key: master_key.to_vec(),
            key: None,
            nonce: [0u8; 12],
            buffer: Vec::new(),
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub(crate) fn new_socket(
        reader: OwnedReadHalf,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        Self {
            transport: TcpReadTransport::Socket { reader },
            cipher,
            master_key: master_key.to_vec(),
            key: None,
            nonce: [0u8; 12],
            buffer: Vec::new(),
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub(crate) fn with_request_salt(mut self, request_salt: Option<Vec<u8>>) -> Self {
        self.ss2022 = request_salt.map(|request_salt| Ss2022TcpReaderState {
            request_salt,
            response_header_read: false,
        });
        self
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        if self.key.is_none() {
            let salt = self.read_exact_from_ws(self.cipher.salt_len()).await?;
            self.key = Some(derive_subkey(self.cipher, &self.master_key, &salt)?);
        }
        let key = self.key.clone().ok_or_else(|| anyhow!("missing derived key"))?;

        let need_ss2022_response_header =
            self.ss2022.as_ref().is_some_and(|state| !state.response_header_read);
        if need_ss2022_response_header {
            let request_salt = self
                .ss2022
                .as_ref()
                .map(|state| state.request_salt.clone())
                .ok_or_else(|| anyhow!("missing ss2022 request salt"))?;
            {
                let header_len = 1 + 8 + self.cipher.salt_len() + 2 + SHADOWSOCKS_TAG_LEN;
                let encrypted_header = self.read_exact_from_ws(header_len).await?;
                let header = decrypt(self.cipher, &key, &self.nonce, &encrypted_header)?;
                increment_nonce(&mut self.nonce);
                let payload_len =
                    parse_ss2022_response_header(self.cipher, &request_salt, &header)?;
                let encrypted_payload =
                    self.read_exact_from_ws(payload_len + SHADOWSOCKS_TAG_LEN).await?;
                let payload = decrypt(self.cipher, &key, &self.nonce, &encrypted_payload)?;
                increment_nonce(&mut self.nonce);
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
        }

        let encrypted_len = self.read_exact_from_ws(2 + SHADOWSOCKS_TAG_LEN).await?;
        let len = decrypt(self.cipher, &key, &self.nonce, &encrypted_len)?;
        increment_nonce(&mut self.nonce);

        if len.len() != 2 {
            bail!("invalid decrypted length block");
        }
        let payload_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        if payload_len > self.cipher.max_payload_len() {
            bail!("payload length exceeds limit: {payload_len}");
        }

        let encrypted_payload = self.read_exact_from_ws(payload_len + SHADOWSOCKS_TAG_LEN).await?;
        let payload = decrypt(self.cipher, &key, &self.nonce, &encrypted_payload)?;
        increment_nonce(&mut self.nonce);
        Ok(payload)
    }

    async fn read_exact_from_ws(&mut self, len: usize) -> Result<Vec<u8>> {
        match &mut self.transport {
            TcpReadTransport::Socket { reader } => {
                let mut buf = vec![0u8; len];
                if let Err(err) = reader.read_exact(&mut buf).await {
                    if err.kind() == std::io::ErrorKind::UnexpectedEof {
                        self.closed_cleanly = true;
                        bail!("socket closed");
                    }
                    return Err(err).context("socket read failed");
                }
                Ok(buf)
            },
            TcpReadTransport::Websocket { stream, ctrl_tx } => {
                while self.buffer.len() < len {
                    let next = match stream.next().await {
                        None => {
                            self.closed_cleanly = true;
                            bail!("websocket closed");
                        },
                        Some(Ok(msg)) => msg,
                        Some(Err(e)) => return Err(anyhow!("websocket read failed: {e}")),
                    };

                    match next {
                        Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
                        Message::Close(_) => {
                            self.closed_cleanly = true;
                            bail!("websocket closed");
                        },
                        Message::Ping(payload) => {
                            let _ = ctrl_tx.try_send(Message::Pong(payload));
                        },
                        Message::Pong(_) => {},
                        Message::Text(_) => bail!("unexpected text websocket frame"),
                        Message::Frame(_) => {},
                    }
                }

                let tail = self.buffer.split_off(len);
                Ok(std::mem::replace(&mut self.buffer, tail))
            },
        }
    }
}
