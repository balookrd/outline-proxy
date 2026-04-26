//! Parked upstream state that is reattached to a resuming client stream.
//!
//! Only the TCP variant is implemented for the MVP. UDP / VLESS-mux /
//! raw-QUIC variants are added in subsequent stages but live in the same
//! enum so that the registry interface does not change.

use std::sync::Arc;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::{
    crypto::UserKey,
    metrics::{PerUserCounters, Protocol, TcpUpstreamGuard},
};

/// Variant-erased payload of a parked session entry.
pub(crate) enum Parked {
    Tcp(ParkedTcp),
}

impl Parked {
    /// Stable label used as the `kind` metric dimension.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
        }
    }

    /// All kind labels the registry can produce. Used by the sweeper to
    /// refresh per-kind gauges after evictions.
    pub(crate) fn all_kinds() -> &'static [&'static str] {
        &["tcp"]
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
