use anyhow::{Context, Result, anyhow, bail};
use crate::WebSocketClosed;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::warn;
use url::Url;

use shadowsocks_crypto::{
    SHADOWSOCKS_MAX_PAYLOAD, decrypt_udp_packet, decrypt_udp_packet_2022, encrypt_udp_packet,
    encrypt_udp_packet_2022,
};
use shadowsocks_crypto::CipherKind;
use crate::config::WsTransportMode;

use super::{AbortOnDrop, DnsCache, UpstreamTransportGuard, WsTransportStream, connect_websocket_with_source};

const MAX_UDP_SOCKET_PACKET_SIZE: usize = 65_507;
const OVERSIZED_UDP_UPLINK_DROP_ERR: &str = "oversized UDP packet dropped before uplink send";

struct Ss2022UdpState {
    client_session_id: u64,
    next_client_packet_id: u64,
    server_session_id: Option<u64>,
    last_server_packet_id: Option<u64>,
}

enum UdpTransport {
    Websocket {
        data_tx: mpsc::Sender<Message>,
        downlink_rx: Mutex<mpsc::Receiver<Result<Vec<u8>>>>,
        _writer_task: AbortOnDrop,
        _reader_task: AbortOnDrop,
        _keepalive_task: Option<AbortOnDrop>,
    },
    Socket {
        socket: UdpSocket,
    },
}

pub struct UdpWsTransport {
    transport: UdpTransport,
    cipher: CipherKind,
    master_key: Vec<u8>,
    ss2022: Option<Mutex<Ss2022UdpState>>,
    close_signal: watch::Sender<bool>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

pub fn is_dropped_oversized_udp_error(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains(OVERSIZED_UDP_UPLINK_DROP_ERR)
}

impl UdpWsTransport {
    pub fn from_websocket(
        ws_stream: WsTransportStream,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let master_key = cipher.derive_master_key(password)?;
        let (close_signal, _close_rx) = watch::channel(false);
        let (sink, stream) = ws_stream.split();
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
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
                            Some(Message::Close(_)) | None => {
                                let _ = ws_sink.close().await;
                                return;
                            }
                            Some(m) => {
                                if ws_sink.send(m).await.is_err() { return; }
                            }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(Message::Close(_)) | None => {
                            let _ = ws_sink.close().await;
                            return;
                        },
                        Some(m) => {
                            if ws_sink.send(m).await.is_err() {
                                return;
                            }
                        },
                    }
                }
            }
        });
        let keepalive_task = keepalive_interval.map(|interval| {
            let keepalive_ctrl_tx = ctrl_tx.clone();
            AbortOnDrop(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // skip the first immediate tick
                loop {
                    ticker.tick().await;
                    if keepalive_ctrl_tx.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }))
        });
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Vec<u8>>>(64);
        let reader_ctrl_tx = ctrl_tx.clone();
        let mut close_rx = close_signal.subscribe();
        let reader_task = tokio::spawn(async move {
            let mut stream = stream;
            loop {
                let msg = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            let _ = downlink_tx.send(Err(anyhow!("udp transport closed"))).await;
                            return;
                        }
                        continue;
                    }
                    msg = stream.next() => msg,
                };
                match msg {
                    None => return,
                    Some(Err(e)) => {
                        let _ = downlink_tx
                            .send(Err(anyhow::Error::from(e).context("websocket read failed")))
                            .await;
                        return;
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if downlink_tx.send(Ok(bytes.into())).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        let _ = downlink_tx.send(Err(anyhow::Error::from(WebSocketClosed))).await;
                        return;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = reader_ctrl_tx.try_send(Message::Pong(payload));
                    }
                    Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Text(_))) => {
                        let _ = downlink_tx
                            .send(Err(anyhow!("unexpected text websocket frame")))
                            .await;
                        return;
                    }
                }
            }
        });
        Ok(Self {
            transport: UdpTransport::Websocket {
                data_tx,
                downlink_rx: Mutex::new(downlink_rx),
                _writer_task: AbortOnDrop(writer_task),
                _reader_task: AbortOnDrop(reader_task),
                _keepalive_task: keepalive_task,
            },
            cipher,
            master_key,
            ss2022: cipher.is_ss2022().then(|| {
                Mutex::new(Ss2022UdpState {
                    client_session_id: rand::random::<u64>(),
                    next_client_packet_id: 0,
                    server_session_id: None,
                    last_server_packet_id: None,
                })
            }),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    pub fn from_socket(
        socket: UdpSocket,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
    ) -> Result<Self> {
        let (close_signal, _close_rx) = watch::channel(false);
        let master_key = cipher.derive_master_key(password)?;
        Ok(Self {
            transport: UdpTransport::Socket { socket },
            cipher,
            master_key,
            ss2022: cipher.is_ss2022().then(|| {
                Mutex::new(Ss2022UdpState {
                    client_session_id: rand::random::<u64>(),
                    next_client_packet_id: 0,
                    server_session_id: None,
                    last_server_packet_id: None,
                })
            }),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        cache: &DnsCache,
        url: &Url,
        mode: WsTransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let ws_stream = connect_websocket_with_source(cache, url, mode, fwmark, ipv6_first, source)
            .await
            .with_context(|| format!("failed to connect to {}", url))?;
        Self::from_websocket(ws_stream, cipher, password, source, keepalive_interval)
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        let packet = if let Some(state) = &self.ss2022 {
            let mut state = state.lock().await;
            let packet = encrypt_udp_packet_2022(
                self.cipher,
                &self.master_key,
                state.client_session_id,
                state.next_client_packet_id,
                payload,
            )?;
            state.next_client_packet_id += 1;
            packet
        } else {
            encrypt_udp_packet(self.cipher, &self.master_key, payload)?
        };
        match &self.transport {
            UdpTransport::Websocket { data_tx, .. } => data_tx
                .send(Message::Binary(packet.into()))
                .await
                .context("failed to send UDP websocket frame"),
            UdpTransport::Socket { socket } => {
                if packet.len() > MAX_UDP_SOCKET_PACKET_SIZE {
                    warn!(
                        packet_len = packet.len(),
                        limit = MAX_UDP_SOCKET_PACKET_SIZE,
                        cipher = %self.cipher,
                        "dropping oversized UDP packet before shadowsocks uplink send"
                    );
                    outline_metrics::record_dropped_oversized_udp_packet("outgoing");
                    bail!(OVERSIZED_UDP_UPLINK_DROP_ERR);
                }
                socket
                    .send(&packet)
                    .await
                    .context("failed to send UDP shadowsocks packet")
                    .map(|_| ())
            },
        }
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        match &self.transport {
            UdpTransport::Socket { socket } => {
                let mut close_rx = self.close_signal.subscribe();
                let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD + 128];
                if *close_rx.borrow() {
                    bail!("udp transport closed");
                }
                let len = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            bail!("udp transport closed");
                        }
                        bail!("udp transport close state changed unexpectedly");
                    }
                    len = socket.recv(&mut buf) => {
                        len.context("failed to read UDP shadowsocks packet")?
                    }
                };
                self.decrypt_udp_bytes(&buf[..len]).await.map(Bytes::from)
            },
            UdpTransport::Websocket { downlink_rx, .. } => {
                let bytes = {
                    let mut rx = downlink_rx.lock().await;
                    rx.recv().await.ok_or_else(|| anyhow::Error::from(WebSocketClosed))??
                };
                self.decrypt_udp_bytes(&bytes).await.map(Bytes::from)
            },
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        if let UdpTransport::Websocket { data_tx, .. } = &self.transport {
            let _ = data_tx.send(Message::Close(None)).await;
        }
        Ok(())
    }

    async fn decrypt_udp_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        if let Some(state) = &self.ss2022 {
            let expected_client_session_id = state.lock().await.client_session_id;
            let (session_id, packet_id, payload) = decrypt_udp_packet_2022(
                self.cipher,
                &self.master_key,
                expected_client_session_id,
                bytes,
            )?;
            let mut state = state.lock().await;
            if let Some(last_server_packet_id) = state.last_server_packet_id
                && state.server_session_id == Some(session_id) && packet_id <= last_server_packet_id
                {
                    bail!("duplicate or out-of-order ss2022 UDP packet");
                }
            state.server_session_id = Some(session_id);
            state.last_server_packet_id = Some(packet_id);
            return Ok(payload);
        }
        Ok(decrypt_udp_packet(self.cipher, &self.master_key, bytes)?)
    }
}
