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

/// True when the slot holds a transport whose carrier mode matches
/// `expected_mode`. Used by the WS sub-probe to skip a redundant
/// fresh WS handshake when a cached pipe (which is itself proof the
/// WS layer is working) is already on hand.
pub(crate) fn peek_matches(slot: &WarmTcpProbeSlot, expected_mode: TransportMode) -> bool {
    matches!(slot.lock().as_ref(), Some(w) if w.mode() == expected_mode)
}

/// Drop the cached pipe (UDP `mode_downgrade` analog for TCP).
pub(crate) fn clear(slot: &WarmTcpProbeSlot) {
    *slot.lock() = None;
}

/// Send a HEAD/keep-alive request through the cached pipe (if any) and
/// re-stash it on success. Used by the keepalive loop so the upstream
/// HTTP server's keep-alive idle timer (and the VLESS tunnel's WS-level
/// keepalive) does not lapse between regular probe cycles. An empty slot
/// is left empty — keepalive does not dial.
///
/// Returns `true` if the slot was non-empty and the request succeeded
/// with a status the regular probe would have accepted *and* the server
/// signalled keep-alive. Otherwise the cached pipe is closed.
pub(crate) async fn keepalive_tick(
    slot: &WarmTcpProbeSlot,
    request: &[u8],
) -> bool {
    let warm = match slot.lock().take() {
        Some(w) => w,
        None => return false,
    };
    let WarmTcpProbe::Vless { mut writer, mut reader, mode } = warm;
    let outcome = async {
        writer.send_chunk(request).await.ok()?;
        const MAX_HEADER_BYTES: usize = 16 * 1024;
        let mut accum: Vec<u8> = Vec::with_capacity(256);
        loop {
            let chunk = reader.read_chunk().await.ok()?;
            if chunk.is_empty() {
                return None;
            }
            accum.extend_from_slice(&chunk);
            if accum.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if accum.len() >= MAX_HEADER_BYTES {
                return None;
            }
        }
        // Status check: 2xx/3xx is acceptable.
        let head = String::from_utf8_lossy(&accum);
        let mut lines = head.split("\r\n");
        let status_line = lines.next()?;
        let mut status_parts = status_line.split_whitespace();
        let version = status_parts.next().unwrap_or("");
        let status = status_parts.next().and_then(|s| s.parse::<u16>().ok())?;
        if !(200..400).contains(&status) {
            return None;
        }
        // Keep-alive check.
        let mut explicit_close = false;
        let mut explicit_keepalive = false;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("connection") {
                    let v = value.trim();
                    if v.eq_ignore_ascii_case("close") {
                        explicit_close = true;
                    } else if v.eq_ignore_ascii_case("keep-alive") {
                        explicit_keepalive = true;
                    }
                }
            }
        }
        let server_will_close = if explicit_close {
            true
        } else if explicit_keepalive {
            false
        } else {
            !version.eq_ignore_ascii_case("HTTP/1.1")
        };
        if server_will_close { None } else { Some(()) }
    }
    .await;
    if outcome.is_some() {
        put_back(slot, WarmTcpProbe::Vless { writer, reader, mode });
        true
    } else {
        let _ = writer.close().await;
        false
    }
}
