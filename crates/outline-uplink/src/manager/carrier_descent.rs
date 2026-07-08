//! The carrier-descent ladder: the pure transition table behind the
//! per-uplink carrier downgrade/recovery machinery.
//!
//! This module owns *which* carrier follows which — descent on failure
//! ([`one_step_down`]), recovery walk-up ([`one_step_up`]), the family
//! split and rank ordering, and the floor predicate. It is deliberately
//! state-free: windows, caps, failure streaks and grace counters live in
//! [`super::status::PerTransportStatus`] and are driven by
//! [`super::mode_downgrade`]. Keeping the ladder separate means the
//! protocol-shaped part (the transition table) is auditable and tested in
//! one place, independent of the bookkeeping.

use outline_transport::TransportMode;

/// Family designator for [`one_step_down`] / [`rank`]. The downgrade
/// chain is split into the WS family (`WsH1` ≺ `WsH2` ≺ `WsH3`) and the
/// XHTTP family (`XhttpH1` ≺ `XhttpH2` ≺ `XhttpH3`). Cap updates inside an
/// active window only respect rank within the same family — a cross-family
/// previous cap is treated as stale and overwritten.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Ws,
    Xhttp,
}

pub(super) fn family(mode: TransportMode) -> Family {
    match mode {
        TransportMode::WsH1 | TransportMode::WsH2 | TransportMode::WsH3 => Family::Ws,
        TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3 => Family::Xhttp,
    }
}

/// Rank inside a family. Lower = more downgraded. Used to enforce the
/// "monotonically downward" rule on the cap field. Cross-family
/// comparisons are not meaningful — the caller checks [`family`] first.
pub(super) fn rank(mode: TransportMode) -> u8 {
    match mode {
        TransportMode::WsH1 => 0,
        TransportMode::WsH2 => 1,
        TransportMode::WsH3 => 2,
        TransportMode::XhttpH1 => 0,
        TransportMode::XhttpH2 => 1,
        TransportMode::XhttpH3 => 2,
    }
}

/// Map a failed carrier to the carrier the next dial should attempt.
/// Returns `None` when the failed carrier is already the deepest
/// fallback in its family — there is no further step to cap to.
///
/// Both family chains walk three ranks deep:
/// `WsH3 → WsH2 → WsH1` and `XhttpH3 → XhttpH2 → XhttpH1`. The WS
/// chain's `WsH2 → WsH1` step duplicates the cross-uplink per-host
/// `ws_mode_cache` clamp at the dial layer — that's intentional:
/// without the per-uplink cap rank visible on the dashboard,
/// operators observing `H2 ↘ DOWN` couldn't tell whether the dial
/// loop had already fallen back to H1 (via `ws_mode_cache`) or
/// was still spinning on a doomed H2 attempt. The minor double
/// log on a one-off `WsH2` failure is the price.
pub(super) fn one_step_down(failed: TransportMode) -> Option<TransportMode> {
    match failed {
        TransportMode::WsH3 => Some(TransportMode::WsH2),
        TransportMode::WsH2 => Some(TransportMode::WsH1),
        TransportMode::XhttpH3 => Some(TransportMode::XhttpH2),
        TransportMode::XhttpH2 => Some(TransportMode::XhttpH1),
        TransportMode::WsH1 | TransportMode::XhttpH1 => None,
    }
}

/// `true` when this transport mode is the bottom of its carrier-downgrade
/// stack — i.e. [`one_step_down`] would return `None`. Used by the
/// shuffle_wires wire-advance gate: as long as the active wire's
/// effective mode is **above** the floor, a runtime / probe / dial
/// failure on this wire is funnelled into the carrier-cascade
/// machinery (`extend_mode_downgrade` caps one rank lower) instead of
/// the per-wire failure streak, so the wire never advances away from
/// h3 / h2 before its own carrier stack has been walked down to
/// h1. Once the wire is at h1, failures resume their normal role of
/// driving wire-rotation.
pub(crate) fn is_carrier_floor_mode(mode: TransportMode) -> bool {
    one_step_down(mode).is_none()
}

/// Inverse of [`one_step_down`]: map a capped carrier to the next
/// higher rank in its own family. Drives the walk-up path that lifts
/// a probe-confirmed cap one rank at a time toward the configured
/// carrier when the capped carrier itself proves healthy. Returns
/// `None` for the deepest fallbacks (`WsH3`, `XhttpH3`) — they have
/// nothing higher to walk to.
pub(super) fn one_step_up(capped: TransportMode) -> Option<TransportMode> {
    match capped {
        TransportMode::WsH1 => Some(TransportMode::WsH2),
        TransportMode::WsH2 => Some(TransportMode::WsH3),
        TransportMode::XhttpH1 => Some(TransportMode::XhttpH2),
        TransportMode::XhttpH2 => Some(TransportMode::XhttpH3),
        TransportMode::WsH3 | TransportMode::XhttpH3 => None,
    }
}

#[cfg(test)]
#[path = "tests/carrier_descent.rs"]
mod tests;
