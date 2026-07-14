use crate::TransportOperation;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use outline_net::RelayReadBuf;
use outline_wire::padding::PaddingDecoder;
use outline_wire::ss2022::Ss2022Error;
use parking_lot::Mutex as SyncMutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, watch};
use tracing::warn;
use url::Url;

use crate::carrier_padding::{self, CarrierPadding};
use crate::config::TransportMode;
use crate::frame_io::DatagramChannel;
use crate::frame_io_ws::{carrier_liveness, from_ws_datagrams};
use shadowsocks_crypto::CipherKind;
use shadowsocks_crypto::{
    SHADOWSOCKS_MAX_PAYLOAD, decrypt_udp_packet, decrypt_udp_packet_2022, encrypt_udp_packet,
    encrypt_udp_packet_2022,
};

use super::{
    DialNetworkOptions, DialResumeOptions, DnsCache, SsPathKind, TransportDialOptions,
    TransportStream, UplinkConnectionBinding, UpstreamTransportGuard, connect_transport,
};
use crate::resumption::SessionId;

const MAX_UDP_SOCKET_PACKET_SIZE: usize = 65_507;
/// Receive window for the raw-socket SS path: the largest SS payload plus room
/// for the AEAD framing that rides in front of it.
const UDP_SOCKET_RECV_CAPACITY: usize = SHADOWSOCKS_MAX_PAYLOAD + 128;

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
        /// Receive buffer reused across datagrams. `read_packet` is the only
        /// reader, so the lock is uncontended — it exists solely to reach the
        /// buffer through `&self`. Sized for the largest datagram the socket
        /// can deliver: a short window would truncate it. Boxed to keep
        /// `UdpWsTransport` (and every enum that carries it by value) the same
        /// size as before — the raw-socket path allocates it exactly once.
        recv_buf: Box<Mutex<RelayReadBuf>>,
    },
}

pub struct UdpWsTransport {
    transport: UdpTransport,
    cipher: CipherKind,
    master_key: Vec<u8>,
    ss2022: Option<Mutex<Ss2022UdpState>>,
    /// Carrier padding for the datagram channel, read at construction. When
    /// enabled, each already-encrypted SS-AEAD packet is wrapped in one padding
    /// frame (`real` = the ciphertext, plus a random pad tail) before
    /// `send_datagram`, and inbound datagrams are decoded before SS decrypt.
    /// Only set on the WS / XHTTP datagram carrier (`from_websocket`); the raw
    /// socket and raw-QUIC datagram channel stay plain (padding is a WS-carrier
    /// fingerprint feature, mirroring VLESS-UDP). Per-datagram, no cover frames
    /// on the uplink — UDP preserves packet boundaries so one frame wraps one
    /// packet.
    padding: CarrierPadding,
    /// `Some` iff [`Self::padding`] is enabled: inbound datagrams run through
    /// this decoder before SS decryption. `read_packet` is the only reader; the
    /// `SyncMutex` keeps the type `Send` without holding the guard across the
    /// decrypt await. One WS Binary frame carries exactly one padding frame
    /// (the sender emits one per `send_packet`), so the decoder always lands on
    /// a frame boundary — a `real_len = 0` cover frame decodes to nothing and
    /// is skipped.
    recv_decoder: Option<SyncMutex<PaddingDecoder>>,
    /// Reaction for a recognised carrier control signal (server-initiated
    /// downstream throttle), set by the dispatch layer. `None` keeps the
    /// transport inert. Only meaningful when `recv_decoder` is `Some`, since
    /// the signal rides a padding cover datagram.
    throttle: Option<crate::ThrottleSignalHandle>,
    /// Fires the throttle handler at most once per carrier. `read_packet` is
    /// `&self`, so this is interior-mutable.
    throttle_fired: std::sync::atomic::AtomicBool,
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
        ws_stream: TransportStream,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        // On H3 the QUIC layer owns liveness, so the WS read-idle watchdog
        // and client keepalive Ping are both disabled (the latter is unsafe
        // on H3) — see `carrier_liveness`.
        let (idle_timeout, keepalive) = carrier_liveness(ws_stream.is_h3(), keepalive_interval);
        let channel: Arc<dyn DatagramChannel> =
            Arc::new(from_ws_datagrams(ws_stream, idle_timeout, keepalive));
        // Padding is a WS / XHTTP-carrier feature, read here (after the dial,
        // inside the manager's `with_uplink_padding_scope`). The raw-QUIC
        // datagram channel reaches `from_channel` directly with padding
        // disabled, so raw QUIC stays plain — matching VLESS-UDP.
        let padding = carrier_padding::effective_carrier_padding();
        Self::from_channel(channel, cipher, password, source, padding)
    }

    /// Build an SS UDP transport over an arbitrary [`DatagramChannel`]. The
    /// channel is opaque — the SS layer cares only about send/recv of
    /// already-encrypted datagrams. `padding` is resolved by the caller:
    /// [`Self::from_websocket`] reads the per-dial carrier padding, while the
    /// raw-QUIC datagram path passes [`CarrierPadding::disabled`] (raw QUIC is
    /// not a WS carrier, so it is never framed — same scope as VLESS-UDP).
    pub fn from_channel(
        channel: Arc<dyn DatagramChannel>,
        cipher: CipherKind,
        password: &str,
        source: &'static str,
        padding: CarrierPadding,
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
            recv_decoder: padding
                .scheme
                .is_enabled()
                .then(|| SyncMutex::new(PaddingDecoder::new())),
            throttle: None,
            throttle_fired: std::sync::atomic::AtomicBool::new(false),
            padding,
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    /// Installs a carrier control-signal handler (server-initiated downstream
    /// throttle). Builder form, called before the transport is shared. No-op at
    /// runtime unless padding is on (the signal rides a cover datagram).
    pub fn with_throttle_handle(mut self, handle: crate::ThrottleSignalHandle) -> Self {
        self.throttle = Some(handle);
        self
    }

    /// Invokes the throttle handler for `signal`, once per carrier.
    fn fire_throttle(&self, signal: outline_wire::padding::ControlSignal) {
        if let Some(handle) = &self.throttle
            && !self.throttle_fired.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            handle(signal);
        }
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
            transport: UdpTransport::Socket {
                socket,
                recv_buf: Box::new(Mutex::new(RelayReadBuf::fixed(UDP_SOCKET_RECV_CAPACITY))),
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
            // Raw socket is not a WS carrier — never framed.
            padding: CarrierPadding::disabled(),
            recv_decoder: None,
            throttle: None,
            throttle_fired: std::sync::atomic::AtomicBool::new(false),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        cache: &DnsCache,
        url: &Url,
        mode: TransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        combined_ss_kind: Option<SsPathKind>,
    ) -> Result<Self> {
        let ws_stream = connect_transport(
            TransportDialOptions::new(cache, url, mode, source)
                .with_network(DialNetworkOptions { fwmark, ipv6_first })
                .with_combined_ss_kind(combined_ss_kind),
        )
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
    /// Returns `(transport, issued_session_id, downgraded_from)`:
    /// - `issued_session_id` is `Some` iff the server's WS Upgrade response
    ///   carried `X-Outline-Session`.
    /// - `downgraded_from` is `Some(requested_mode)` iff the underlying
    ///   `connect_transport` produced a stream at a lower mode
    ///   than requested (clamp via `ws_mode_cache` or inline H3→H2/H1
    ///   fallback). The uplink-manager caller mirrors this into its
    ///   per-uplink `mode_downgrade_until` window so routing/metrics see a
    ///   consistent state.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_resume(
        cache: &DnsCache,
        url: &Url,
        mode: TransportMode,
        cipher: CipherKind,
        password: &str,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        resume_request: Option<SessionId>,
        combined_ss_kind: Option<SsPathKind>,
    ) -> Result<(Self, Option<SessionId>, Option<TransportMode>)> {
        let ws_stream = connect_transport(
            TransportDialOptions::new(cache, url, mode, source)
                .with_network(DialNetworkOptions { fwmark, ipv6_first })
                .with_combined_ss_kind(combined_ss_kind)
                .with_resume(DialResumeOptions {
                    resume_request,
                    // Ack-Prefix Protocol is a TCP-side mid-session retry feature;
                    // SS-UDP transports do not need it and the server only emits
                    // the control frame on the SS-WS path. Always opt out here.
                    ack_prefix_requested: false,
                    // v2 Symmetric Downlink Replay is gated on v1 and likewise
                    // does not apply to UDP; opt out.
                    symmetric_replay_requested: false,
                    // No prior downstream offset to claim on UDP transports.
                    client_acked_offset: 0,
                }),
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        // Snapshot the Session ID and downgrade marker before consuming
        // the stream — the SS-encryption layer doesn't need either, but
        // the caller does.
        let issued = ws_stream.issued_session_id();
        let downgraded_from = ws_stream.downgraded_from();
        let transport =
            Self::from_websocket(ws_stream, cipher, password, source, keepalive_interval)?;
        Ok((transport, issued, downgraded_from))
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
            UdpTransport::Channel(chan) => {
                // When padding is on, wrap the encrypted SS packet in one
                // padding frame so the datagram size no longer tracks the SS
                // payload; the server decodes it back before SS-UDP decrypt.
                // One frame per packet (a datagram never exceeds the u16
                // segment ceiling), mirroring VLESS-UDP. Otherwise hand it
                // through unchanged (plain wire).
                let datagram = if self.padding.scheme.is_enabled() {
                    let mut out = Vec::with_capacity(packet.len() + 8);
                    carrier_padding::frame_payload_into(
                        self.padding.scheme,
                        &packet,
                        &mut rand::rng(),
                        &mut out,
                    );
                    Bytes::from(out)
                } else {
                    Bytes::from(packet)
                };
                chan.send_datagram(datagram).await
            },
            UdpTransport::Socket { socket, .. } => {
                if packet.len() > MAX_UDP_SOCKET_PACKET_SIZE {
                    warn!(
                        packet_len = packet.len(),
                        limit = MAX_UDP_SOCKET_PACKET_SIZE,
                        cipher = %self.cipher,
                        "dropping oversized UDP packet before shadowsocks uplink send"
                    );
                    outline_metrics::record_dropped_oversized_udp_packet("down", "ss_socket");
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

    /// Attribute this UDP transport to a concrete uplink so its lifetime
    /// participates in `outline_ws_uplink_open_connections` and the
    /// matching close-classification counter. Must be called before the
    /// transport is wrapped in any further `Arc<>` or shared state — the
    /// inner guard is mutated through `Arc::get_mut`, which only succeeds
    /// while the constructor is the sole owner.
    pub fn with_uplink_binding(mut self, binding: UplinkConnectionBinding) -> Self {
        UpstreamTransportGuard::attach_uplink_binding(&mut self._lifetime, binding);
        self
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        match &self.transport {
            UdpTransport::Socket { socket, recv_buf } => {
                let mut close_rx = self.close_signal.subscribe();
                if *close_rx.borrow() {
                    bail!("udp transport closed");
                }
                let mut recv_buf = recv_buf.lock().await;
                loop {
                    let ready = async {
                        tokio::select! {
                            _ = close_rx.changed() => {
                                if *close_rx.borrow() {
                                    bail!("udp transport closed");
                                }
                                bail!("udp transport close state changed unexpectedly");
                            }
                            ready = socket.readable() => {
                                ready.context("failed to await UDP shadowsocks socket")
                            }
                        }
                    };
                    // The buffer is reused across datagrams while the flow is
                    // busy and handed back once the park outlives the idle
                    // grace, so an idle UDP flow still holds no receive buffer.
                    recv_buf.park(ready).await?;
                    match socket.try_recv_buf(recv_buf.ready()) {
                        Ok(_) => {
                            return self
                                .decrypt_udp_bytes(recv_buf.filled())
                                .await
                                .map(Bytes::from);
                        },
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        },
                        Err(error) => {
                            return Err(error).context("failed to read UDP shadowsocks packet");
                        },
                    }
                }
            },
            UdpTransport::Channel(chan) => {
                loop {
                    let bytes = chan
                        .recv_datagram()
                        .await?
                        .ok_or_else(|| anyhow::Error::from(crate::WsClosed))?;
                    match &self.recv_decoder {
                        // Padding off: the datagram is a bare SS packet.
                        None => return self.decrypt_udp_bytes(&bytes).await.map(Bytes::from),
                        // Padding on: strip the frame before SS decrypt. A
                        // cover frame (`real_len = 0`) decodes to nothing, so
                        // read the next datagram. The guard is dropped before
                        // the decrypt await.
                        Some(decoder) => {
                            let mut decoded = Vec::with_capacity(bytes.len());
                            let signal = {
                                let mut guard = decoder.lock();
                                guard.push(&bytes, &mut decoded);
                                guard.take_control()
                            };
                            if let Some(sig) = signal {
                                self.fire_throttle(sig);
                            }
                            if decoded.is_empty() {
                                continue;
                            }
                            return self.decrypt_udp_bytes(&decoded).await.map(Bytes::from);
                        },
                    }
                }
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
            // One lock spans the whole read-decrypt-update path: the SS2022
            // decrypt is synchronous, so there is no await between reading
            // `client_session_id` and committing the replay state. Holding a
            // single guard both halves the per-datagram lock traffic (was two
            // acquire/release round trips) and makes the replay check + update
            // atomic against a concurrent reader instead of racing across the
            // gap the old two-lock form left open. Mirrors `send_packet`,
            // which already holds one lock across the synchronous encrypt.
            let mut state = state.lock().await;
            let (session_id, packet_id, payload) = decrypt_udp_packet_2022(
                self.cipher,
                &self.master_key,
                state.client_session_id,
                bytes,
            )?;
            if let Some(last_server_packet_id) = state.last_server_packet_id
                && state.server_session_id == Some(session_id)
                && packet_id <= last_server_packet_id
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

#[cfg(test)]
#[path = "tests/udp_transport.rs"]
mod tests;

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
}

impl UdpSessionTransport {
    /// Installs a carrier control-signal handler (server-initiated downstream
    /// throttle) on the underlying datagram transport. `None` leaves it inert.
    /// Acts on the padded WS/XHTTP carriers — SS-UDP and VLESS-UDP — whose
    /// decoders surface the control cover datagram.
    pub fn with_throttle_handle(self, handle: Option<crate::ThrottleSignalHandle>) -> Self {
        match self {
            Self::Ss(t) => match handle {
                Some(h) => Self::Ss(t.with_throttle_handle(h)),
                None => Self::Ss(t),
            },
            Self::Vless(t) => Self::Vless(t.with_throttle_handle(handle)),
        }
    }

    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        match self {
            Self::Ss(t) => t.send_packet(socks5_payload).await,
            Self::Vless(t) => t.send_packet(socks5_payload).await,
        }
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        match self {
            Self::Ss(t) => t.read_packet().await,
            Self::Vless(t) => t.read_packet().await,
        }
    }

    pub async fn close(&self) -> Result<()> {
        match self {
            Self::Ss(t) => t.close().await,
            Self::Vless(t) => t.close().await,
        }
    }
}
