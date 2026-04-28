use anyhow::{Context, Result, bail};
use crate::{TransportOperation};
use outline_ss2022::Ss2022Error;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};
use tracing::warn;
use url::Url;

use shadowsocks_crypto::{
    SHADOWSOCKS_MAX_PAYLOAD, decrypt_udp_packet, decrypt_udp_packet_2022, encrypt_udp_packet,
    encrypt_udp_packet_2022,
};
use shadowsocks_crypto::CipherKind;
use crate::config::WsTransportMode;
use crate::frame_io::DatagramChannel;
use crate::frame_io_ws::{WS_READ_IDLE_TIMEOUT, from_ws_datagrams};

use super::{
    DnsCache, UpstreamTransportGuard, WsTransportStream, connect_websocket_with_resume,
    connect_websocket_with_source,
};
use crate::resumption::SessionId;

const MAX_UDP_SOCKET_PACKET_SIZE: usize = 65_507;

struct Ss2022UdpState {
    client_session_id: u64,
    next_client_packet_id: u64,
    server_session_id: Option<u64>,
    last_server_packet_id: Option<u64>,
}

enum UdpTransport {
    /// Datagram-oriented transport (WebSocket today; QUIC datagrams in
    /// future). All control (Ping/Pong, Close) is hidden inside the impl.
    Channel(Arc<dyn DatagramChannel>),
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

/// Marker error for "the upstream UDP transport rejected this datagram
/// because it exceeds a hard size limit it cannot fragment around"
/// (e.g. QUIC `max_datagram_size`, the 64 KiB VLESS UDP frame ceiling).
/// Surfaced via `bail!(OversizedUdpDatagram { ... })` so callers can
/// distinguish "too big to send, drop the packet" from a real transport
/// failure that should mark the uplink unhealthy.
#[derive(Debug, thiserror::Error)]
#[error("oversized UDP datagram: {payload_len} > {limit} ({transport})")]
pub struct OversizedUdpDatagram {
    pub transport: &'static str,
    pub payload_len: usize,
    pub limit: usize,
}

pub fn is_dropped_oversized_udp_error(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        matches!(e.downcast_ref::<Ss2022Error>(), Some(Ss2022Error::OversizedUdpUplink))
            || e.downcast_ref::<OversizedUdpDatagram>().is_some()
    })
}

impl UdpWsTransport {
    pub fn from_websocket(
        ws_stream: WsTransportStream,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let channel: Arc<dyn DatagramChannel> = Arc::new(from_ws_datagrams(
            ws_stream,
            Some(WS_READ_IDLE_TIMEOUT),
            keepalive_interval,
        ));
        Self::from_channel(channel, cipher, password, source)
    }

    /// Build an SS UDP transport over an arbitrary [`DatagramChannel`]. The
    /// channel is opaque — the SS layer cares only about send/recv of
    /// already-encrypted datagrams.
    pub fn from_channel(
        channel: Arc<dyn DatagramChannel>,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
    ) -> Result<Self> {
        let master_key = cipher.derive_master_key(password)?;
        let (close_signal, _close_rx) = watch::channel(false);
        Ok(Self {
            transport: UdpTransport::Channel(channel),
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
            .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        Self::from_websocket(ws_stream, cipher, password, source, keepalive_interval)
    }

    /// Same as [`Self::connect`] but participates in cross-transport
    /// session resumption: presents `resume_request` (if any) on the
    /// upgrade as `X-Outline-Resume`, and returns the Session ID the
    /// server assigned via `X-Outline-Session` so the caller can stash
    /// it for the next reconnect.
    ///
    /// Returns `(transport, Option<SessionId>)` — the second tuple
    /// element is `Some` iff the server's WS Upgrade response carried
    /// `X-Outline-Session`. A feature-disabled server will leave it
    /// `None`, in which case the caller behaves like `connect()`.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_resume(
        cache: &DnsCache,
        url: &Url,
        mode: WsTransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        resume_request: Option<SessionId>,
    ) -> Result<(Self, Option<SessionId>)> {
        let ws_stream = connect_websocket_with_resume(
            cache,
            url,
            mode,
            fwmark,
            ipv6_first,
            source,
            resume_request,
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        // Snapshot the Session ID before consuming the stream — the
        // SS-encryption layer doesn't need it but the caller does.
        let issued = ws_stream.issued_session_id();
        let transport =
            Self::from_websocket(ws_stream, cipher, password, source, keepalive_interval)?;
        Ok((transport, issued))
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
            UdpTransport::Channel(chan) => chan.send_datagram(Bytes::from(packet)).await,
            UdpTransport::Socket { socket } => {
                if packet.len() > MAX_UDP_SOCKET_PACKET_SIZE {
                    warn!(
                        packet_len = packet.len(),
                        limit = MAX_UDP_SOCKET_PACKET_SIZE,
                        cipher = %self.cipher,
                        "dropping oversized UDP packet before shadowsocks uplink send"
                    );
                    outline_metrics::record_dropped_oversized_udp_packet("outgoing");
                    bail!(Ss2022Error::OversizedUdpUplink);
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
            UdpTransport::Channel(chan) => {
                let bytes = chan
                    .recv_datagram()
                    .await?
                    .ok_or_else(|| anyhow::Error::from(crate::WsClosed))?;
                self.decrypt_udp_bytes(&bytes).await.map(Bytes::from)
            },
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        if let UdpTransport::Channel(chan) = &self.transport {
            chan.close().await;
        }
        Ok(())
    }

    /// Wrap this SS transport as the protocol-agnostic `UdpSessionTransport`.
    pub fn into_session(self) -> UdpSessionTransport {
        UdpSessionTransport::Ss(self)
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
                    bail!(Ss2022Error::DuplicateOrOutOfOrderUdpPacket);
                }
            state.server_session_id = Some(session_id);
            state.last_server_packet_id = Some(packet_id);
            return Ok(payload);
        }
        Ok(decrypt_udp_packet(self.cipher, &self.master_key, bytes)?)
    }
}

/// Protocol-agnostic UDP session transport. Present as a single public type
/// across the proxy, TUN, and uplink layers so callers don't need to branch
/// on Shadowsocks vs. VLESS at every send/read site. Each variant accepts
/// payloads pre-framed as `SOCKS5 UDP header || data` and returns downlink
/// datagrams in the same shape — VLESS absorbs the framing delta internally
/// (strip on send, prepend on receive) so the rest of the stack stays
/// protocol-unaware.
pub enum UdpSessionTransport {
    Ss(UdpWsTransport),
    Vless(crate::vless::VlessUdpSessionMux),
    /// VLESS UDP over raw QUIC, wrapped in a hybrid envelope that pivots
    /// to WS over H2 if the QUIC path fails before any session succeeds.
    /// Multiple targets are multiplexed on a shared QUIC connection by
    /// server-allocated `session_id` while QUIC is active.
    #[cfg(feature = "quic")]
    VlessQuic(crate::vless_udp_hybrid::VlessUdpHybridMux),
}

impl UdpSessionTransport {
    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        match self {
            Self::Ss(t) => t.send_packet(socks5_payload).await,
            Self::Vless(t) => t.send_packet(socks5_payload).await,
            #[cfg(feature = "quic")]
            Self::VlessQuic(t) => t.send_packet(socks5_payload).await,
        }
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        match self {
            Self::Ss(t) => t.read_packet().await,
            Self::Vless(t) => t.read_packet().await,
            #[cfg(feature = "quic")]
            Self::VlessQuic(t) => t.read_packet().await,
        }
    }

    pub async fn close(&self) -> Result<()> {
        match self {
            Self::Ss(t) => t.close().await,
            Self::Vless(t) => t.close().await,
            #[cfg(feature = "quic")]
            Self::VlessQuic(t) => t.close().await,
        }
    }
}
