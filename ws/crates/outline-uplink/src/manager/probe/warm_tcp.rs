//! Long-lived TCP transport reused across HTTP probe cycles.
//!
//! Mirrors [`super::warm_udp`] for the TCP/HEAD probe path. The original HTTP
//! probe re-dialled a fresh VLESS TCP tunnel each cycle, which on the server
//! cost: a fresh upstream TCP `connect()` to the probe URL host:port, a fresh
//! VLESS handshake on the tunnel, and a fresh HTTP/1.1 request from the
//! upstream server's perspective.
//!
//! Caching the dialled `(TcpWriter, TcpReader)` pair plus switching the probe
//! request to `Connection: keep-alive` lets all three layers stay warm across
//! probe cycles. The slot is invalidated on any error, on a TCP
//! `mode_downgrade` (cached carrier no longer matches), or when the upstream
//! server signals it intends to close (`Connection: close` or HTTP/1.0).
//!
//! Scope: VLESS only. Plain Shadowsocks TCP probes still dial fresh.

use std::sync::Arc;

use parking_lot::Mutex;

use outline_transport::{TcpReader, TcpWriter};

use crate::config::TransportMode;

/// Cached TCP probe pipe.
///
/// `Vless` covers both VLESS/WS and VLESS/XHTTP carriers; the difference is
/// only in the `mode` field which [`take_if_matches`] uses to discard a
/// stale clamp.
pub(crate) enum WarmTcpProbe {
    Vless { writer: TcpWriter, reader: TcpReader, mode: TransportMode },
}

impl WarmTcpProbe {
    fn mode(&self) -> TransportMode {
        match self {
            Self::Vless { mode, .. } => *mode,
        }
    }
}

pub(crate) type WarmTcpProbeSlot = Arc<Mutex<Option<WarmTcpProbe>>>;

pub(crate) fn new_slot() -> WarmTcpProbeSlot {
    Arc::new(Mutex::new(None))
}

/// Take the cached pipe iff its carrier mode matches `expected_mode`. A
/// mismatch drops the stored pipe (the carrier moved while we were idle —
/// the next dial will pick the new effective mode and the cached pipe is
/// stale).
pub(crate) fn take_if_matches(
    slot: &WarmTcpProbeSlot,
    expected_mode: TransportMode,
) -> Option<WarmTcpProbe> {
    let mut guard = slot.lock();
    match guard.as_ref().map(WarmTcpProbe::mode) {
        Some(mode) if mode == expected_mode => guard.take(),
        Some(_) => {
            *guard = None;
            None
        },
        None => None,
    }
}

/// Re-insert the pipe after a successful probe round-trip *and* a
/// keep-alive-capable response.
pub(crate) fn put_back(slot: &WarmTcpProbeSlot, warm: WarmTcpProbe) {
    let mut guard = slot.lock();
    if guard.is_none() {
        *guard = Some(warm);
    }
}

/// Drop the cached pipe (UDP `mode_downgrade` analog for TCP).
pub(crate) fn clear(slot: &WarmTcpProbeSlot) {
    *slot.lock() = None;
}
