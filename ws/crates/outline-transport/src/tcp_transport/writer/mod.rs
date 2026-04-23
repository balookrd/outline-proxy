mod ss2022;
mod transport;

use anyhow::{Context, Result};
use outline_ss2022::Ss2022Error;
use rand::RngCore;
use shadowsocks_crypto::{AeadCipher, SHADOWSOCKS_TAG_LEN, CipherKind, derive_subkey, increment_nonce};
use socks5_proto::TargetAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::debug;
use crate::UpstreamTransportGuard;

use ss2022::{Ss2022TcpWriterState, build_ss2022_request_header};
use transport::{SocketWriteTransport, WriteTransport, WsSink, WsWriteTransport};

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

pub type WsTcpWriter = TcpShadowsocksWriter<WsWriteTransport>;
pub type SocketTcpWriter = TcpShadowsocksWriter<SocketWriteTransport>;

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

        let (transport, ctrl_tx) = WsWriteTransport::spawn(sink);

        let key = derive_subkey(cipher, master_key, &salt[..cipher.salt_len()])?;
        let cipher_state = AeadCipher::new(cipher, &key[..cipher.key_len()])?;
        Ok((
            Self {
                transport,
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

impl TcpShadowsocksWriter<SocketWriteTransport> {
    pub fn connect_socket(
        writer: tokio::net::tcp::OwnedWriteHalf,
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

        let max = self.cipher.max_payload_len();
        if payload.len() <= max {
            self.send_payload_frame(payload).await?;
        } else {
            // Coalesce all SS2022 frames into one write (one WS message / one
            // syscall) to avoid N separate send() calls for large payloads.
            // The reader accumulates bytes across WS messages, so batching is
            // transparent to it.
            let salt_len = self.pending_salt.as_ref().map_or(0, |_| self.cipher.salt_len());
            let n_chunks = payload.chunks(max).count();
            let mut frame = Vec::with_capacity(
                salt_len + payload.len() + n_chunks * (2 + 2 * SHADOWSOCKS_TAG_LEN),
            );
            for chunk in payload.chunks(max) {
                self.encrypt_payload_frame_into(chunk, &mut frame)?;
            }
            self.write_frame(frame).await?;
        }
        Ok(())
    }

    async fn send_payload_frame(&mut self, payload: &[u8]) -> Result<()> {
        let salt_len = self.pending_salt.as_ref().map_or(0, |_| self.cipher.salt_len());
        let mut frame = Vec::with_capacity(
            salt_len + 2 + SHADOWSOCKS_TAG_LEN + payload.len() + SHADOWSOCKS_TAG_LEN,
        );
        self.encrypt_payload_frame_into(payload, &mut frame)?;
        self.write_frame(frame).await
    }

    // Encrypt one SS2022 payload chunk and append it (plus salt prefix, if pending)
    // to `frame`.  No allocation — the caller pre-sizes the buffer.
    fn encrypt_payload_frame_into(&mut self, payload: &[u8], frame: &mut Vec<u8>) -> Result<()> {
        if let Some(salt) = self.pending_salt.take() {
            frame.extend_from_slice(&salt[..self.cipher.salt_len()]);
        }
        let len = (payload.len() as u16).to_be_bytes();
        self.cipher_state.encrypt_into(&self.nonce, &len, frame)?;
        increment_nonce(&mut self.nonce)?;
        self.cipher_state.encrypt_into(&self.nonce, payload, frame)?;
        increment_nonce(&mut self.nonce)?;
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
