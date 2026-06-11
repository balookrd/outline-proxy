use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};

use crate::{
    metrics::{Metrics, PerUserCounters, Protocol, TcpUpstreamGuard},
    outbound::OutboundIpv6,
    protocol::vless::VlessUser,
};

use super::super::super::{
    abort::AbortOnDrop,
    dns_cache::DnsCache,
    resumption::{OrphanRegistry, SessionId},
};
use super::super::tcp::ResumeContext;
use super::super::vless_mux::MuxState;

pub(in crate::server::transport) const MAX_VLESS_HEADER_BUFFER: usize = 512;

/// Outcome of [`relay_vless_upstream_to_client`] (TCP) and the
/// `vless_udp` / `vless_mux` helpers. Made `pub(super)` so the UDP
/// and Mux modules can construct the cancel variants when wrapping
/// their own relay task return values into [`VlessRelayTaskOutput`].
pub(in crate::server::transport) enum VlessRelayOutcome {
    /// Upstream EOF or sink error; reader is consumed.
    Closed,
    /// TCP cancel: the caller fired the notify; the harvested
    /// `OwnedReadHalf` is returned for hand-off into the orphan
    /// registry.
    Cancelled(tokio::net::tcp::OwnedReadHalf),
    /// UDP cancel: nothing to harvest because the `Arc<UdpSocket>`
    /// already lives in `UpstreamSession::Udp`. The variant exists so
    /// the park path can tell "we asked it to stop" from "the upstream
    /// EOF'd on its own".
    UdpCancelled,
}

/// Failure modes returned by [`handle_vless_binary_frame`] and the upstream
/// establishers. [`run_vless_relay`] matches on this to decide whether to
/// send the client a "try again" close frame (RFC 6455 code 1013) — so the
/// client can retry on the same or a different uplink — or a plain close
/// for terminal errors (parser/auth/protocol). Mirrors `tcp::FrameError`.
pub(in crate::server::transport) enum VlessFrameError {
    UpstreamConnectFailed(anyhow::Error),
    Fatal(anyhow::Error),
}

impl VlessFrameError {
    pub(super) fn into_inner(self) -> anyhow::Error {
        match self {
            Self::UpstreamConnectFailed(e) | Self::Fatal(e) => e,
        }
    }
}

impl From<anyhow::Error> for VlessFrameError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(e)
    }
}

pub(in crate::server) struct VlessWsServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) outbound_ipv6: Option<Arc<OutboundIpv6>>,
    /// Cross-transport session-resumption registry. No-op when disabled
    /// in config.
    pub(in crate::server) orphan_registry: Arc<OrphanRegistry>,
    /// Per-session bounded mpsc capacity for the upstream-reader →
    /// WS-writer fan-in. Resolved from `tuning.ws_data_channel_capacity`
    /// — sized too low and a momentary WS writer stall back-pressures
    /// the upstream TCP read, visible as video buffer underrun.
    pub(in crate::server) ws_data_channel_capacity: usize,
}

pub(in crate::server) struct VlessWsRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

/// Return type of the VLESS-TCP relay task. Carries either a closed
/// outcome (no parking possible) or the harvested reader half so that
/// [`run_vless_relay`] can move it into the orphan registry on
/// disconnect.
pub(in crate::server::transport) type VlessRelayTaskOutput = Result<VlessRelayOutcome>;

/// Single-target VLESS-TCP upstream. Holds every TCP-only piece of
/// state — none of these fields are meaningful for UDP or Mux, so
/// packing them here lets the type system enforce the invariant.
pub(in crate::server::transport) struct TcpUpstream {
    pub(in crate::server::transport) writer: tokio::net::tcp::OwnedWriteHalf,
    /// `AbortOnDrop` ensures the upstream→client task is cancelled on
    /// every exit path of the owning `run_vless_relay` future,
    /// including `?`-returns and panics.
    pub(in crate::server::transport) reader_task: AbortOnDrop<VlessRelayTaskOutput>,
    /// Notify used to ask the spawned reader to stop and hand over its
    /// read half on park-on-drop.
    pub(in crate::server::transport) cancel: Arc<Notify>,
    /// Human-readable target host:port. Used for logging and to
    /// populate `ParkedTcp::target_display` on park.
    pub(in crate::server::transport) target_display: Arc<str>,
    pub(in crate::server::transport) guard: TcpUpstreamGuard,
}

/// Single-target VLESS-UDP upstream. UDP-only counterpart of
/// [`TcpUpstream`].
pub(in crate::server::transport) struct UdpUpstream {
    pub(in crate::server::transport) socket: Arc<UdpSocket>,
    /// See [`TcpUpstream::reader_task`]. Critical for UDP because
    /// `socket.recv` has no shutdown signal — without `AbortOnDrop`
    /// the reader would block forever and orphan its `Arc<UdpSocket>`
    /// + 64 KiB buffer.
    pub(in crate::server::transport) reader_task: AbortOnDrop<VlessRelayTaskOutput>,
    pub(in crate::server::transport) cancel: Arc<Notify>,
    pub(in crate::server::transport) target_display: Arc<str>,
    /// Partial-frame reassembly buffer for the 2-byte-length-prefixed
    /// VLESS-UDP framing.
    pub(in crate::server::transport) client_buffer: BytesMut,
}

pub(in crate::server::transport) enum UpstreamSession {
    None,
    Tcp(TcpUpstream),
    Udp(UdpUpstream),
    Mux(MuxState),
}

pub(in crate::server::transport) struct VlessRelayState {
    pub(in crate::server::transport) header_buffer: Vec<u8>,
    pub(in crate::server::transport) upstream: UpstreamSession,
    pub(in crate::server::transport) authenticated_user: Option<VlessUser>,
    pub(in crate::server::transport) user_counters: Option<Arc<PerUserCounters>>,
    /// Session ID we minted at WS-Upgrade time and surfaced via
    /// `X-Outline-Session`. Used as the registry key on park.
    pub(in crate::server::transport) issued_session_id: Option<SessionId>,
    /// Session ID the client offered for resumption. Consumed (`take()`)
    /// on the first authenticated VLESS-TCP / VLESS-UDP / VLESS-MUX frame.
    pub(in crate::server::transport) pending_resume_request: Option<SessionId>,
    /// Whether the client advertised `X-Outline-Resume-Ack-Prefix: 1` on
    /// the WebSocket upgrade. When true, a successful resume hit
    /// triggers emission of the 14-byte v1 control frame as the first
    /// WS Binary message AFTER the standard VLESS response header.
    pub(in crate::server::transport) ack_prefix_requested: bool,
    /// Whether the client advertised the v2 Symmetric Downlink Replay
    /// capability AND the server has v2 enabled. When true on a
    /// resume hit the relay emits the v2 `"ORDR"` frame as a
    /// separate WS Binary message immediately after the v1 frame.
    /// Implies `ack_prefix_requested == true`.
    pub(in crate::server::transport) symmetric_replay_requested: bool,
    /// Client-reported `X-Outline-Resume-Down-Acked` offset from the
    /// request side. Used by the resume-emit path to compute
    /// `replay_from(offset)` against the parked downlink ring. `0`
    /// when no v2 negotiation occurred or the request did not carry
    /// the header.
    pub(in crate::server::transport) client_acked_offset_request: u64,
    /// Per-session bounded ring buffer for the v2 Symmetric Downlink
    /// Replay protocol. Allocated lazily at upstream-handshake time
    /// when [`Self::symmetric_replay_requested`] is `true`. The
    /// VLESS-WS relay loop pushes every plaintext chunk into the
    /// ring before the WS Binary send; on park the same `Arc` is
    /// moved into [`ParkedTcp::downlink_ring`] and back on resume
    /// hit. `None` means v2 is not engaged on this session.
    pub(in crate::server::transport) downlink_ring:
        Option<Arc<parking_lot::Mutex<crate::server::resumption::downlink_ring::DownlinkRing>>>,
    /// Per-session counter of plaintext bytes the relay has forwarded
    /// to the upstream socket. Same units the client tracks on its
    /// uplink ring buffer; survives park/resume because the `Arc` is
    /// moved into `ParkedTcp` on park and back into the state on the
    /// next resume hit. The counter underpins the
    /// [Ack-Prefix Protocol v1] `up_acked` field reported in the
    /// 14-byte control frame.
    ///
    /// [Ack-Prefix Protocol v1]: ../../../../docs/SESSION-RESUMPTION.md
    pub(in crate::server::transport) upstream_bytes_acked: Arc<AtomicU64>,
}

pub(in crate::server::transport) struct VlessWsOutbound<'a, Msg> {
    pub(in crate::server::transport) data_tx: &'a mpsc::Sender<Msg>,
    pub(in crate::server::transport) make_binary: fn(Bytes) -> Msg,
    pub(in crate::server::transport) make_close: fn() -> Msg,
}

impl VlessRelayState {
    pub(super) fn new(resume: ResumeContext) -> Self {
        Self {
            header_buffer: Vec::with_capacity(128),
            upstream: UpstreamSession::None,
            authenticated_user: None,
            user_counters: None,
            issued_session_id: resume.issued_session_id,
            pending_resume_request: resume.requested_resume,
            ack_prefix_requested: resume.ack_prefix_requested,
            symmetric_replay_requested: resume.symmetric_replay_requested,
            client_acked_offset_request: resume.client_acked_offset,
            upstream_bytes_acked: Arc::new(AtomicU64::new(0)),
            // v2 ring is allocated lazily at upstream-handshake time.
            // On resume hit it is restored from `ParkedTcp::downlink_ring`.
            downlink_ring: None,
        }
    }
}
