use anyhow::{Context, Result, anyhow};
use crate::{Ss2022Error, TransportOperation};
use futures_util::stream::SplitSink;
use futures_util::SinkExt;
use rand::RngCore;
use shadowsocks_crypto::{AeadCipher, SHADOWSOCKS_TAG_LEN, CipherKind, derive_subkey, increment_nonce};
use socks5_proto::TargetAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::debug;
use crate::{AbortOnDrop, UpstreamTransportGuard, WsTransportStream};

type WsSink = SplitSink<WsTransportStream, Message>;

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

#[allow(async_fn_in_trait)]
pub trait WriteTransport: Send + 'static {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
    fn supports_half_close(&self) -> bool;
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
        self.writer.shutdown().await.context(TransportOperation::SocketShutdown)
    }

    fn supports_half_close(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// SS2022 state
// ---------------------------------------------------------------------------

pub(super) struct Ss2022TcpWriterState {
    pub request_salt: [u8; 32],
    pub header_sent: bool,
}

// ---------------------------------------------------------------------------
// SS2022 helpers
// ---------------------------------------------------------------------------

pub(super) fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

pub(super) fn build_ss2022_request_header(target: &TargetAddr) -> Result<(Vec<u8>, Vec<u8>)> {
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

// ---------------------------------------------------------------------------
// Generic writer
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

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

pub type WsTcpWriter = TcpShadowsocksWriter<WsWriteTransport>;
pub type SocketTcpWriter = TcpShadowsocksWriter<SocketWriteTransport>;

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
                .context(Ss2022Error::InvalidInitialTargetHeader)?
                .0;
            let (fixed_header, variable_header) = build_ss2022_request_header(&target)?;
            let salt_len = self.pending_salt.as_ref().map_or(0, |_| self.cipher.salt_len());
            let mut frame = Vec::with_capacity(
                salt_len
                    + fixed_header.len() + SHADOWSOCKS_TAG_LEN
                    + variable_header.len() + SHADOWSOCKS_TAG_LEN,
            );
            if let Some(salt) = self.pending_salt.take() {
                state.request_salt = salt;
                frame.extend_from_slice(&salt[..self.cipher.salt_len()]);
            }
            self.cipher_state.encrypt_into(&self.nonce, &fixed_header, &mut frame)?;
            increment_nonce(&mut self.nonce)?;
            self.cipher_state.encrypt_into(&self.nonce, &variable_header, &mut frame)?;
            increment_nonce(&mut self.nonce)?;
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
