//! Long-lived UDP transport reused across DNS probe cycles.
//!
//! The DNS probe used to dial a fresh `VlessUdpWsTransport` for every cycle,
//! which on the server side meant: bind a new NAT socket, spawn a new reader
//! task, and pay a cold DNS resolve for the probe target. With one probe
//! every few seconds those costs dominate the measured latency and skew
//! UDP probe RTT well above what the data path actually exhibits.
//!
//! This module owns one slot per uplink that caches a single open VLESS UDP
//! transport. The DNS probe takes the transport out, sends + reads through
//! it, and puts it back if both halves succeeded. On any error — or when
//! the manager records a UDP `mode_downgrade` (the cached carrier is no
//! longer the one fresh dials would pick) — the slot is cleared so the
//! next probe re-establishes from scratch.
//!
//! Scope is intentionally narrow: only the VLESS-XHTTP/WS family uses the
//! warm slot. Plain Shadowsocks and raw-QUIC paths still dial fresh; the
//! cost profile there differs and is not the bottleneck this module
//! targets.

use std::sync::Arc;

use parking_lot::Mutex;

use outline_transport::{UdpWsTransport, VlessUdpWsTransport};

use crate::config::TransportMode;

/// Cached UDP transport reused by the DNS probe.
///
/// The variant stores the carrier mode the transport was dialled with;
/// [`take_if_matches`] discards it if the next probe would request a
/// different mode (a `mode_downgrade` clamp shifted the effective carrier
/// while the slot was idle).
///
/// `VlessUdpWsTransport` underlies both VLESS/WS and VLESS/XHTTP carriers
/// (the type alias name is a historical leftover from the WS-only era); a
/// single `Vless` variant covers both because the only thing that
/// distinguishes them at this layer is `mode`.
///
/// `Ws` covers Shadowsocks-over-WebSocket UDP. The wire form already
/// encodes the target on every datagram (per SS-UDP framing), so reuse
/// is just "keep the WS open" — no per-session prefix to worry about.
pub(crate) enum WarmUdpProbe {
    Vless { transport: VlessUdpWsTransport, mode: TransportMode },
    Ws { transport: UdpWsTransport, mode: TransportMode },
}

impl WarmUdpProbe {
    fn mode(&self) -> TransportMode {
        match self {
            Self::Vless { mode, .. } | Self::Ws { mode, .. } => *mode,
        }
    }
}

/// Per-uplink slot guarding at most one cached transport.
///
/// `Arc` so the scheduler can clone it into the spawned probe task without
/// holding a borrow on `UplinkManagerInner`.
pub(crate) type WarmUdpProbeSlot = Arc<Mutex<Option<WarmUdpProbe>>>;

pub(crate) fn new_slot() -> WarmUdpProbeSlot {
    Arc::new(Mutex::new(None))
}

/// Take the cached transport iff it was dialled with `expected_mode`.
///
/// A mode mismatch drops the cached transport on the floor — its carrier
/// is no longer the one fresh dials should use, so reusing it would defeat
/// the point of the downgrade window.
pub(crate) fn take_if_matches(
    slot: &WarmUdpProbeSlot,
    expected_mode: TransportMode,
) -> Option<WarmUdpProbe> {
    let mut guard = slot.lock();
    match guard.as_ref().map(WarmUdpProbe::mode) {
        Some(mode) if mode == expected_mode => guard.take(),
        Some(_) => {
            *guard = None;
            None
        },
        None => None,
    }
}

/// Re-insert the transport after a successful probe round-trip.
///
/// If the slot already holds a value (a concurrent probe attempt put one
/// back first) this drops the newer transport — single-flight semantics
/// are sufficient here.
pub(crate) fn put_back(slot: &WarmUdpProbeSlot, warm: WarmUdpProbe) {
    let mut guard = slot.lock();
    if guard.is_none() {
        *guard = Some(warm);
    }
}

/// Clear the slot (e.g. after a UDP `mode_downgrade` so the next probe
/// re-dials on the new effective carrier).
pub(crate) fn clear(slot: &WarmUdpProbeSlot) {
    *slot.lock() = None;
}

/// Send a single DNS query through the cached transport (if any) and
/// re-stash it on success. Used by the keepalive loop to keep the
/// server-side NAT entry's `last_active_secs` ticking between regular
/// probe cycles. An empty slot is left empty — keepalive does not dial.
///
/// Errors are intentionally swallowed: a failed keepalive just drops
/// the cached transport, and the next regular probe will dial fresh.
/// The caller logs the outcome at debug level. Returns `true` if the
/// slot was non-empty and the round-trip succeeded.
pub(crate) async fn keepalive_tick(
    slot: &WarmUdpProbeSlot,
    query: &[u8],
    ss_payload: &[u8],
) -> bool {
    let warm = match slot.lock().take() {
        Some(w) => w,
        None => return false,
    };
    match warm {
        WarmUdpProbe::Vless { transport, mode } => {
            let ok = vless_round_trip(&transport, query).await;
            if ok {
                put_back(slot, WarmUdpProbe::Vless { transport, mode });
                true
            } else {
                let _ = transport.close().await;
                false
            }
        },
        WarmUdpProbe::Ws { transport, mode } => {
            let ok = ws_round_trip(&transport, ss_payload, query).await;
            if ok {
                put_back(slot, WarmUdpProbe::Ws { transport, mode });
                true
            } else {
                let _ = transport.close().await;
                false
            }
        },
    }
}

async fn vless_round_trip(transport: &VlessUdpWsTransport, query: &[u8]) -> bool {
    async {
        transport.send_packet(query).await.ok()?;
        let response = transport.read_packet().await.ok()?;
        validate_dns_response_inline(&response, query)
    }
    .await
    .is_some()
}

async fn ws_round_trip(transport: &UdpWsTransport, ss_payload: &[u8], query: &[u8]) -> bool {
    use crate::config::TargetAddr;
    async {
        transport.send_packet(ss_payload).await.ok()?;
        let response = transport.read_packet().await.ok()?;
        // SS-UDP framing prefixes upstream replies with the source
        // address; strip it before validating the DNS payload.
        let (_, consumed) = TargetAddr::from_wire_bytes(&response).ok()?;
        validate_dns_response_inline(&response[consumed..], query)
    }
    .await
    .is_some()
}

/// Inline `transaction id match + rcode == 0` check. Avoids depending on
/// the probe-internal helper from this manager-side module.
fn validate_dns_response_inline(dns: &[u8], query: &[u8]) -> Option<()> {
    if dns.len() < 4 || dns[..2] != query[..2] || dns[3] & 0x0f != 0 {
        None
    } else {
        Some(())
    }
}
