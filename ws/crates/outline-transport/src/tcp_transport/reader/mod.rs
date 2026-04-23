mod ss2022;
mod transport;

pub use transport::WsReadDiag;

use anyhow::{Result, anyhow, bail};
use shadowsocks_crypto::{AeadCipher, CipherKind, SHADOWSOCKS_TAG_LEN, derive_subkey, increment_nonce};
use std::sync::Arc;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::UpstreamTransportGuard;

use ss2022::{Ss2022TcpReaderState, parse_ss2022_response_header};
use transport::{ReadTransport, SocketReadTransport, WsReadTransport, WsStream};

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

pub type WsTcpReader = TcpShadowsocksReader<WsReadTransport>;
pub type SocketTcpReader = TcpShadowsocksReader<SocketReadTransport>;

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
