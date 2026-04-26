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
    pub(crate) protocol: Protocol,
    pub(crate) owner: Arc<str>,
    pub(crate) user: UserKey,
    pub(crate) user_counters: Arc<PerUserCounters>,
    pub(crate) upstream_guard: TcpUpstreamGuard,
}
