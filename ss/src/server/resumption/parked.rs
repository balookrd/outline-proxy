//! Parked upstream state that is reattached to a resuming client stream.
//!
//! Two variants are implemented today:
//! - `Tcp` — single-target SS-over-WS or single-target VLESS-over-WS.
//! - `VlessMux` — atomic park of an entire VLESS mux session, including
//!   every TCP and UDP sub-connection multiplexed inside it.
//!
//! UDP-only single-target and raw-QUIC variants are out of scope for
//! the current revision but slot into the same enum.

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
    protocol::vless::VlessUser,
};

/// Variant-erased payload of a parked session entry.
pub(crate) enum Parked {
    Tcp(ParkedTcp),
    VlessMux(ParkedVlessMux),
}

impl Parked {
    /// Stable label used as the `kind` metric dimension.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::VlessMux(_) => "vless_mux",
        }
    }

    /// All kind labels the registry can produce. Used by the sweeper to
    /// refresh per-kind gauges after evictions.
    pub(crate) fn all_kinds() -> &'static [&'static str] {
        &["tcp", "vless_mux"]
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
