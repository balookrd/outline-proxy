mod ss2022;
mod transport;

#[cfg(test)]
mod tests;

pub use transport::WsReadDiag;

use anyhow::{Result, anyhow, bail};
use shadowsocks_crypto::{AeadCipher, CipherKind, SHADOWSOCKS_TAG_LEN, derive_subkey, increment_nonce};
use std::sync::Arc;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::UpstreamTransportGuard;
use crate::ack_prefix::{FRAME_LEN_V1, ParseResult, parse_v1};

use ss2022::{Ss2022TcpReaderState, parse_ss2022_response_header};
use transport::{ReadTransport, SocketReadTransport, WsReadTransport, WsStream};
#[cfg(feature = "quic")]
use transport::QuicReadTransport;

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
    /// Set by the caller when the WS upgrade negotiated the Ack-Prefix
    /// Protocol v1 (server echoed `X-Outline-Resume-Ack-Prefix: 1`). When
    /// `true`, the very first decrypted SS-AEAD payload is treated as
    /// the 14-byte control frame defined in
    /// `docs/SESSION-RESUMPTION.md` (server repo) § Ack-Prefix Protocol;
    /// `read_chunk` parses it transparently, stores the result in
    /// [`Self::up_acked`], and then continues to the first real data
    /// chunk so callers never observe the protocol bytes.
    expect_ack_prefix: bool,
    /// Server-reported `up_acked` byte count from the v1 control frame,
    /// or `None` when the protocol was not negotiated, the prefix has
    /// not yet been parsed, or the frame was malformed (in which case
    /// `read_chunk` errored out and the session is dropped). Stable
    /// after the first chunk is decrypted.
    up_acked: Option<u64>,
}

pub type WsTcpReader = TcpShadowsocksReader<WsReadTransport>;
pub type SocketTcpReader = TcpShadowsocksReader<SocketReadTransport>;
#[cfg(feature = "quic")]
pub type QuicTcpReader = TcpShadowsocksReader<QuicReadTransport>;

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
            expect_ack_prefix: false,
            up_acked: None,
        }
    }

    /// Attach diagnostic context so that stream-level EOF logs can be
    /// correlated against the underlying shared H2/H3 connection.
    pub fn with_diag(mut self, diag: WsReadDiag) -> Self {
        self.transport.diag = diag;
        self
    }
}

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
            // Plain-socket Shadowsocks (no WebSocket upgrade) does not
            // carry the Ack-Prefix capability — the protocol is gated on
            // a successful WS upgrade response. Always off here.
            expect_ack_prefix: false,
            up_acked: None,
        }
    }
}

#[cfg(feature = "quic")]
impl TcpShadowsocksReader<QuicReadTransport> {
    pub fn new_quic(
        recv: quinn::RecvStream,
        cipher: CipherKind,
        master_key: &[u8],
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        let mut mk = [0u8; 32];
        mk[..master_key.len()].copy_from_slice(master_key);
        Self {
            transport: QuicReadTransport { recv },
            cipher,
            master_key: mk,
            cipher_state: None,
            nonce: [0u8; 12],
            ss2022: None,
            _lifetime: lifetime,
            closed_cleanly: false,
            // Raw QUIC bypasses the WS upgrade entirely; no Ack-Prefix
            // negotiation surfaces here. Always off.
            expect_ack_prefix: false,
            up_acked: None,
        }
    }
}

impl<T: ReadTransport> TcpShadowsocksReader<T> {
    pub fn with_request_salt(mut self, request_salt: Option<[u8; 32]>) -> Self {
        self.ss2022 = request_salt.map(|request_salt| Ss2022TcpReaderState {
            request_salt,
            response_header_read: false,
        });
        self
    }

    /// Tells the reader to expect a v1 Ack-Prefix control frame as the
    /// very first decrypted SS-AEAD payload. Set this when (and only
    /// when) the WS upgrade response carried
    /// `X-Outline-Resume-Ack-Prefix: 1` — i.e.
    /// [`crate::TransportStream::ack_prefix_advertised_by_server`] is
    /// `true`. The first call to [`Self::read_chunk`] consumes the 14
    /// prefix bytes, parks the reported offset on
    /// [`Self::upstream_acked_offset`], and returns the next real
    /// payload chunk (or recurses if the prefix occupied a chunk by
    /// itself, as the server's emit always does).
    pub fn with_expect_ack_prefix(mut self, expect: bool) -> Self {
        self.expect_ack_prefix = expect;
        self
    }

    /// Server-reported `up_acked` byte offset from the v1 Ack-Prefix
    /// control frame, or `None` when the protocol was not negotiated or
    /// the prefix has not yet been parsed. Stable after the first
    /// [`Self::read_chunk`] call returns successfully on a stream where
    /// [`Self::with_expect_ack_prefix`] was set.
    pub fn upstream_acked_offset(&self) -> Option<u64> {
        self.up_acked
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
                return self.intercept_ack_prefix_or_return(payload_buf).await;
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
        self.intercept_ack_prefix_or_return(payload_buf).await
    }

    /// Decision point for the very first decrypted payload: when the
    /// reader was told to expect a v1 control frame, parse it
    /// transparently, store `up_acked`, and recurse to fetch the next
    /// chunk so callers never observe the protocol bytes. Otherwise
    /// hand the payload through unchanged.
    ///
    /// On any parse failure the session is dropped (per spec strict
    /// handling): the prefix bytes are unrecognised and continuing
    /// would risk treating control bytes as upstream payload.
    async fn intercept_ack_prefix_or_return(
        &mut self,
        payload_buf: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if !self.expect_ack_prefix {
            return Ok(payload_buf);
        }
        match parse_v1(&payload_buf) {
            ParseResult::Valid { up_acked } => {
                self.up_acked = Some(up_acked);
                self.expect_ack_prefix = false;
                if payload_buf.len() > FRAME_LEN_V1 {
                    // Spec says the server emits the prefix as its own
                    // AEAD chunk, but we tolerate trailing payload
                    // bytes — the parser test
                    // `extra_trailing_bytes_ignored` covers this — by
                    // returning them as the first data chunk so no
                    // upstream bytes are dropped.
                    Ok(payload_buf[FRAME_LEN_V1..].to_vec())
                } else {
                    // Exact 14 bytes (the expected case): recurse to
                    // fetch the next chunk so callers never see an
                    // empty payload that would be misinterpreted as
                    // EOF.
                    Box::pin(self.read_chunk()).await
                }
            },
            ParseResult::TooShort => bail!(
                "ack-prefix v1 control frame is shorter than {} bytes (got {})",
                FRAME_LEN_V1,
                payload_buf.len()
            ),
            ParseResult::BadMagic => {
                bail!("ack-prefix v1 control frame has unexpected magic; dropping session")
            },
            ParseResult::UnsupportedVersion(v) => bail!(
                "ack-prefix control frame announces unsupported version {v}; dropping session"
            ),
            ParseResult::ReservedFlagsSet(f) => bail!(
                "ack-prefix v1 control frame has reserved flags 0x{f:02x} set; dropping session"
            ),
        }
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
