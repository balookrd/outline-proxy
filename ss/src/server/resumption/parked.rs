//! Parked upstream state that is reattached to a resuming client stream.
//!
//! Three variants are implemented today:
//! - `Tcp` — single-target SS-over-WS or single-target VLESS-over-WS.
//! - `VlessUdpSingle` — single-target VLESS-UDP-over-WS, where one
//!   `UdpSocket` is pinned to one upstream target for the lifetime of
//!   the WS stream.
//! - `VlessMux` — atomic park of an entire VLESS mux session, including
//!   every TCP and UDP sub-connection multiplexed inside it.
//!
//! Direct SS-UDP and SS-over-raw-QUIC are non-goals per the spec; the
//! SS-UDP-over-WS variant requires NAT-table API changes and is left
//! for a follow-up revision.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use bytes::BytesMut;
use tokio::net::{
    UdpSocket,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

use crate::{
    crypto::UserKey,
    metrics::{PerUserCounters, Protocol, TcpUpstreamGuard},
    protocol::{TargetAddr, vless::VlessUser},
    server::nat::NatKey,
};

/// Variant-erased payload of a parked session entry.
pub(crate) enum Parked {
    Tcp(ParkedTcp),
    VlessUdpSingle(ParkedVlessUdpSingle),
    VlessMux(ParkedVlessMux),
    SsUdpStream(ParkedSsUdpStream),
}

impl Parked {
    /// Stable label used as the `kind` metric dimension.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::VlessUdpSingle(_) => "vless_udp_single",
            Self::VlessMux(_) => "vless_mux",
            Self::SsUdpStream(_) => "ss_udp_stream",
        }
    }

    /// All kind labels the registry can produce. Used by the sweeper to
    /// refresh per-kind gauges after evictions.
    pub(crate) fn all_kinds() -> &'static [&'static str] {
        &["tcp", "vless_udp_single", "vless_mux", "ss_udp_stream"]
    }
}

/// Per-protocol context preserved alongside a parked TCP upstream.
///
/// On resume the relay path needs different inner state depending on
/// which proxy protocol authenticated the original session:
///
/// - SS-over-WebSocket needs the original [`UserKey`] so the new client
///   stream can build a fresh `AeadStreamEncryptor` for the same user.
/// - VLESS-over-WebSocket does not encrypt the relay payload at all —
///   the proxy passes raw bytes between the WS frame layer and the
///   upstream socket, so no inner crypto context is preserved.
///
/// Resume-attach paths must match on the variant they expect; a request
/// to resume an SS session through a VLESS handler (or vice versa) is
/// treated as a miss to avoid cross-protocol confusion attacks.
pub(crate) enum TcpProtocolContext {
    /// Shadowsocks-over-WebSocket session. Carries the per-user
    /// `UserKey` needed to derive a fresh response cipher for the new
    /// client stream.
    Ss(UserKey),
    /// VLESS-over-WebSocket session (single-target). No inner crypto
    /// state is kept; the new client stream simply forwards raw bytes.
    Vless,
}

impl TcpProtocolContext {
    /// Stable label for metrics and structured logs.
    #[allow(dead_code)]
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Ss(_) => "ss",
            Self::Vless => "vless",
        }
    }
}

/// Upstream TCP relay state preserved for cross-transport resumption.
///
/// At park time the relay loop has already split the upstream `TcpStream`
/// into `(reader, writer)` halves; both halves move into this struct and
/// remain idle while the session is parked.
pub(crate) struct ParkedTcp {
    pub(crate) upstream_writer: OwnedWriteHalf,
    pub(crate) upstream_reader: OwnedReadHalf,
    /// Human-readable target host:port, kept for logging only.
    pub(crate) target_display: Arc<str>,
    /// Protocol of the original session. Stashed for future log/metric
    /// dimensioning at resume time; not read by the MVP code path.
    #[allow(dead_code)]
    pub(crate) protocol: Protocol,
    pub(crate) owner: Arc<str>,
    /// Per-protocol context preserved across the resume hand-off; see
    /// [`TcpProtocolContext`].
    pub(crate) protocol_context: TcpProtocolContext,
    pub(crate) user_counters: Arc<PerUserCounters>,
    pub(crate) upstream_guard: TcpUpstreamGuard,
}

/// Atomic park of a VLESS mux session. The whole multiplex — every
/// TCP and UDP sub-connection inside it — is preserved as a single
/// unit; partial resume is not supported.
///
/// At park time each sub-connection's reader task has been cancelled
/// and its harvested half (TCP reader / UDP socket reference) lives
/// under [`ParkedMuxSubConn::kind`]. On resume the relay code re-
/// spawns one reader task per sub-connection against the new client
/// stream's outbound channel, restoring the multiplex without
/// reopening any upstream socket.
pub(crate) struct ParkedVlessMux {
    pub(crate) sub_conns: HashMap<u16, ParkedMuxSubConn>,
    /// Partially-parsed mux frame buffer. Carrying it across the park
    /// preserves any half-decoded inbound frame the client already
    /// sent before the WebSocket dropped — without this the resume
    /// would have to re-buffer the partial frame from scratch.
    pub(crate) buffer: BytesMut,
    pub(crate) user: VlessUser,
    pub(crate) owner: Arc<str>,
    /// Protocol of the original session (HTTP/1, HTTP/2, HTTP/3).
    /// Currently informational only; the resume path discovers its
    /// own protocol from the new client stream.
    #[allow(dead_code)]
    pub(crate) protocol: Protocol,
    pub(crate) user_counters: Arc<PerUserCounters>,
}

/// One entry in a parked mux's `sub_conns` map. Mirrors the live
/// `MuxSubConn` shape but with the reader-task replaced by its
/// harvested handle (`OwnedReadHalf` for TCP, `Arc<UdpSocket>` for
/// UDP — already shared, so no harvest required).
pub(crate) struct ParkedMuxSubConn {
    pub(crate) kind: ParkedMuxSubKind,
}

pub(crate) enum ParkedMuxSubKind {
    Tcp {
        writer: OwnedWriteHalf,
        reader: OwnedReadHalf,
    },
    Udp {
        socket: Arc<UdpSocket>,
        default_target: SocketAddr,
    },
}

/// Single-target VLESS UDP session over WebSocket. The whole upstream
/// is one connected `UdpSocket` plus the partial 2-byte-length-prefixed
/// frame buffer that was being decoded when the WS stream dropped.
///
/// No back-buffer for upstream-bound packets is kept while parked:
/// the kernel UDP receive buffer fills, and overflow packets drop
/// silently. UDP is loss-tolerant by design; a future revision can
/// add an in-process ring buffer per the spec's
/// `udp_orphan_backbuf_bytes` knob.
pub(crate) struct ParkedVlessUdpSingle {
    pub(crate) socket: Arc<UdpSocket>,
    /// Target the socket is `connect()`ed to. Stored as the original
    /// `TargetAddr` (host:port, possibly a domain) so the logging at
    /// resume time still shows the human form.
    #[allow(dead_code)]
    pub(crate) target: TargetAddr,
    /// Display string for the target — cheaper than re-formatting.
    pub(crate) target_display: Arc<str>,
    /// Protocol (HTTP/1, HTTP/2, HTTP/3) of the original session;
    /// informational only.
    #[allow(dead_code)]
    pub(crate) protocol: Protocol,
    pub(crate) owner: Arc<str>,
    /// VLESS user identity. Unlike the SS-TCP path we do not need a
    /// full `crypto::UserKey` here — VLESS doesn't encrypt the relay
    /// payload — but keeping the original `VlessUser` lets the resume
    /// path log/account against the same identity without re-running
    /// UUID match against the route.
    pub(crate) user: VlessUser,
    pub(crate) user_counters: Arc<PerUserCounters>,
    /// Partially-decoded inbound 2-byte-length-prefixed buffer. Carrying
    /// it across the park preserves any half-frame the client already
    /// pushed before disconnect; without this the resume would have to
    /// re-buffer it from scratch on the new stream.
    pub(crate) udp_client_buffer: BytesMut,
}

/// Park bundle for a single SS-UDP-over-WebSocket stream. The
/// underlying `NatEntry` records live in the process-wide `NatTable`
/// and continue to age normally — `Parked::SsUdpStream` only keeps
/// the *list of NAT keys* that this stream had registered as the
/// active outbound responder, plus the owner identity used for the
/// authenticate-then-resume check.
///
/// Park behaviour: for each key, the relay called
/// `entry.detach_session_for_stream(stream_id)` so upstream-bound
/// packets fall on the floor while no client is attached.
/// Resume behaviour: on the next authenticated packet, the relay
/// calls `entry.register_session(new_sender, session, new_stream_id)`
/// for each preserved key — re-pointing the NAT entry's sender slot
/// at the new client without re-binding the UDP socket.
pub(crate) struct ParkedSsUdpStream {
    /// NAT keys the original stream was the registered owner of.
    /// Stored as a `Vec` (insertion order, possible duplicates after
    /// dedup) — the full `HashSet`-style guarantee is maintained at
    /// build time.
    pub(crate) nat_keys: Vec<NatKey>,
    pub(crate) owner: Arc<str>,
    /// Protocol of the original session. Informational only; the
    /// resume side discovers its own protocol from the new
    /// `UdpResponseSender`.
    #[allow(dead_code)]
    pub(crate) protocol: Protocol,
}
