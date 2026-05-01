//! Single source of truth for the per-uplink mode-downgrade window.
//!
//! The window is family-aware: it covers the WS chain (`H3` → `H2`,
//! raw `QUIC` → `H2`) and the XHTTP chain (`XhttpH3` → `XhttpH2`,
//! `XhttpH2` → `XhttpH1`). Four independent events can (re)set
//! [`PerTransportStatus::mode_downgrade_until`]: runtime traffic failure,
//! probe transport failure, probe connect failure, and a recovery
//! re-probe that failed to confirm recovery. All of them go through
//! [`UplinkManager::extend_mode_downgrade`] so the guard conditions
//! (Ws/Vless transport, downgrade-eligible mode), the "set or extend —
//! never shorten" rule, and the "log once per window start" rule live
//! in exactly one place.
//!
//! Multi-step downgrades (`XhttpH3` → `XhttpH2` → `XhttpH1`) converge
//! over consecutive dials: each fallback observed by the dispatcher
//! lowers [`PerTransportStatus::mode_downgrade_capped_to`] by one
//! family rank, never raising it inside an active window. After two
//! dials the cap reaches the deepest fallback the chain can produce,
//! so probe / refill / fresh-dial paths stop paying the doomed
//! handshake cost for the broken upper carriers.
//!
//! [`PerTransportStatus::mode_downgrade_until`]: crate::types::PerTransportStatus::mode_downgrade_until
//! [`PerTransportStatus::mode_downgrade_capped_to`]: crate::types::PerTransportStatus::mode_downgrade_capped_to

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{UplinkTransport, TransportMode};

use super::super::types::{TransportKind, UplinkManager};

/// Why a downgrade window is being set or extended.  Controls the log
/// message and level emitted when the call starts a *new* window (silent
/// when it extends one that is already active).
pub(crate) enum ModeDowngradeTrigger<'a> {
    /// Real traffic observed a transport-level failure on an H3 session.
    RuntimeFailure(&'a anyhow::Error),
    /// Probe task completed but the per-transport check failed
    /// (e.g. `tcp_ok=false` in `ProbeOutcome`).
    ProbeTransportFailure,
    /// Probe task itself errored out (ws connect failure, timeout).
    ProbeConnectFailure(&'a anyhow::Error),
    /// Explicit H3 recovery re-probe failed to confirm H3 liveness.
    RecoveryReprobeFail,
    /// A dial succeeded but at a lower mode than requested — the host-level
    /// `ws_mode_cache` clamp or inline H3→H2/H1 fallback inside
    /// `connect_websocket_with_resume` silently produced a downgraded
    /// stream. Carries the originally-requested mode for the log message.
    /// Fired from probe / refill / fresh-dial / mux paths so the per-uplink
    /// `mode_downgrade_until` window stays in sync with the actually-dialable
    /// transport even when the operation itself reports success.
    SilentTransportFallback(TransportMode),
}

impl UplinkManager {
    /// Set or extend the H3→H2 downgrade window for `(index, transport)`.
    ///
    /// No-op when the uplink is not a WS transport or its WS mode for this
    /// transport is not H3.  The deadline is only advanced (never shortened),
    /// so a fresh trigger with a shorter configured duration cannot cut an
    /// already-longer window short.
    ///
    /// A log line is emitted only when this call *starts* a new window
    /// (previous deadline absent or expired).  Extensions inside an active
    /// window are silent, except [`ModeDowngradeTrigger::RecoveryReprobeFail`]
    /// which still emits a debug breadcrumb when it actually advances the
    /// deadline (preserves the pre-refactor recovery log).
    pub(crate) fn extend_mode_downgrade(
        &self,
        index: usize,
        transport: TransportKind,
        trigger: ModeDowngradeTrigger<'_>,
    ) {
        let uplink = &self.inner.uplinks[index];
        if !matches!(uplink.transport, UplinkTransport::Ws | UplinkTransport::Vless) {
            return;
        }
        let configured_mode = match transport {
            TransportKind::Tcp => uplink.tcp_dial_mode(),
            TransportKind::Udp => uplink.udp_dial_mode(),
        };
        // The "what just failed" mode: explicit for `SilentTransportFallback`
        // (which carries the originally-requested carrier from the dial
        // result), otherwise the configured dial mode — probe and runtime
        // triggers don't carry their own mode field, but for those triggers
        // the failure is by definition on the configured carrier.
        let failed_mode = match &trigger {
            ModeDowngradeTrigger::SilentTransportFallback(requested) => *requested,
            _ => configured_mode,
        };
        // Map the failed carrier to the carrier the next dial should
        // try. Returning `None` here means the failed carrier is already
        // the deepest fallback in its family — there is nothing left to
        // cap to, so skip the window update entirely.
        let new_cap = match one_step_down(failed_mode) {
            Some(cap) => cap,
            None => return,
        };
        // Sanity gate: cap must be a real downgrade relative to the
        // configured mode and live in the same family. This catches
        // two bogus shapes:
        //
        // * A `SilentTransportFallback(WsH3)` trigger fired against an
        //   uplink configured at `WsH2` (or below) would otherwise
        //   *raise* the effective mode from `WsH1` to `WsH2`.
        // * A cross-family trigger (an `XhttpH3` failure note arriving
        //   on a `WsH3`-configured uplink) would clamp the WS uplink
        //   to an XHTTP carrier the dispatcher cannot dial.
        //
        // Both indicate a wiring bug somewhere upstream; the right
        // response is to ignore the trigger rather than mis-park the
        // uplink.
        if family(new_cap) != family(configured_mode) || rank(new_cap) >= rank(configured_mode) {
            return;
        }

        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let new_until = now + duration;

        let (prev_until, prev_cap) = {
            let per = self.inner.read_status(index);
            let snapshot = per.of(transport);
            (snapshot.mode_downgrade_until, snapshot.mode_downgrade_capped_to)
        };
        let window_active = prev_until.is_some_and(|t| t > now);
        let newly_started = prev_until.is_none_or(|t| t < now);
        let advances_deadline = prev_until.is_none_or(|t| t < new_until);

        // Cap update rule: monotonically downward inside an active
        // window. If the previous cap is in the same family and already
        // ranks lower than `new_cap`, keep it — a `XhttpH3 → XhttpH2`
        // re-trigger after a previous `XhttpH2 → XhttpH1` step must not
        // raise the ceiling back to `XhttpH2`. Outside an active window
        // the previous cap is stale, so always overwrite.
        let updated_cap = match prev_cap {
            Some(prev) if window_active && family(prev) == family(new_cap)
                && rank(prev) < rank(new_cap) =>
            {
                prev
            },
            _ => new_cap,
        };

        if advances_deadline || updated_cap != prev_cap.unwrap_or(updated_cap) {
            self.inner.with_status_mut(index, |status| {
                let per = match transport {
                    TransportKind::Tcp => &mut status.tcp,
                    TransportKind::Udp => &mut status.udp,
                };
                if advances_deadline {
                    per.mode_downgrade_until = Some(new_until);
                }
                per.mode_downgrade_capped_to = Some(updated_cap);
            });
        }

        let downgrade_secs = duration.as_secs();
        let kind_label = match transport {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
        };
        if newly_started {
            match &trigger {
                ModeDowngradeTrigger::RuntimeFailure(err) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} runtime error on {failed_mode}, capping carrier to {updated_cap}"
                ),
                ModeDowngradeTrigger::ProbeTransportFailure => warn!(
                    uplink = %uplink.name,
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} probe failed on {failed_mode}, capping carrier to {updated_cap} for next probe cycle"
                ),
                ModeDowngradeTrigger::ProbeConnectFailure(err) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} probe connection failed on {failed_mode}, capping carrier to {updated_cap}"
                ),
                ModeDowngradeTrigger::RecoveryReprobeFail => debug!(
                    uplink = %uplink.name,
                    kind = ?transport,
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "advanced carrier still unreachable, starting downgrade window after recovery probe"
                ),
                ModeDowngradeTrigger::SilentTransportFallback(requested) => warn!(
                    uplink = %uplink.name,
                    requested_mode = %requested,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} dial silently fell back from {requested}, syncing per-uplink downgrade window to {updated_cap}"
                ),
            }
        } else if matches!(trigger, ModeDowngradeTrigger::RecoveryReprobeFail) && advances_deadline {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                failed_mode = %failed_mode,
                capped_to = %updated_cap,
                downgrade_secs,
                "advanced carrier still unreachable after recovery probe, extending downgrade window"
            );
        }
    }

    /// Public entry-point for dial-time fallback: a synchronous QUIC (or H3)
    /// dial just failed, so mark the downgrade window the same way a runtime
    /// failure would.  The next call to `effective_*_mode` will return the
    /// one-step-down carrier (`WsH2` for `WsH3` / `Quic`,
    /// `XhttpH2` for `XhttpH3`, `XhttpH1` for `XhttpH2`) for the rest of
    /// the window.
    pub fn note_advanced_mode_dial_failure(
        &self,
        index: usize,
        transport: TransportKind,
        error: &anyhow::Error,
    ) {
        self.extend_mode_downgrade(index, transport, ModeDowngradeTrigger::RuntimeFailure(error));
    }

    /// Public entry-point for callers that observe a transport-level WS-mode
    /// downgrade after a *successful* dial — the `ws_mode_cache` clamped the
    /// requested mode or `connect_websocket_with_resume` ran an inline
    /// fallback. Distinct from `note_advanced_mode_dial_failure` so the log
    /// reflects "silent fallback" rather than "runtime error", which makes
    /// the operational signal accurate when this fires from the probe loop,
    /// the standby-refill loop, or fresh-dial paths.
    pub fn note_silent_transport_fallback(
        &self,
        index: usize,
        transport: TransportKind,
        requested: TransportMode,
    ) {
        self.extend_mode_downgrade(
            index,
            transport,
            ModeDowngradeTrigger::SilentTransportFallback(requested),
        );
    }

    /// Clear the downgrade window for `(index, transport)`. Resets both
    /// the deadline and the cap so the next dial returns to the
    /// configured mode. Called when an explicit H3 recovery re-probe
    /// confirms that H3 is back; the XHTTP path has no equivalent
    /// recovery probe and relies on the natural TTL expiry path
    /// (`effective_*_mode` checks `until > now` and ignores a stale
    /// cap on its own).
    pub(crate) fn clear_mode_downgrade(&self, index: usize, transport: TransportKind) {
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => {
                status.tcp.mode_downgrade_until = None;
                status.tcp.mode_downgrade_capped_to = None;
            },
            TransportKind::Udp => {
                status.udp.mode_downgrade_until = None;
                status.udp.mode_downgrade_capped_to = None;
            },
        });
    }
}

/// Family designator for [`one_step_down`] / [`rank`]. The downgrade
/// chain is split into the WS family (`WsH1` ≺ `WsH2` ≺ `WsH3`, with
/// `Quic` clamping to `WsH2` on fallback) and the XHTTP family
/// (`XhttpH1` ≺ `XhttpH2` ≺ `XhttpH3`). Cap updates inside an active
/// window only respect rank within the same family — a cross-family
/// previous cap is treated as stale and overwritten.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Ws,
    Xhttp,
}

fn family(mode: TransportMode) -> Family {
    match mode {
        TransportMode::WsH1
        | TransportMode::WsH2
        | TransportMode::WsH3
        | TransportMode::Quic => Family::Ws,
        TransportMode::XhttpH1
        | TransportMode::XhttpH2
        | TransportMode::XhttpH3 => Family::Xhttp,
    }
}

/// Rank inside a family. Lower = more downgraded. Used to enforce the
/// "monotonically downward" rule on the cap field. Cross-family
/// comparisons are not meaningful — the caller checks [`family`] first.
fn rank(mode: TransportMode) -> u8 {
    match mode {
        TransportMode::WsH1 => 0,
        TransportMode::WsH2 => 1,
        TransportMode::WsH3 => 2,
        TransportMode::Quic => 3,
        TransportMode::XhttpH1 => 0,
        TransportMode::XhttpH2 => 1,
        TransportMode::XhttpH3 => 2,
    }
}

/// Map a failed carrier to the carrier the next dial should attempt.
/// Returns `None` when the failed carrier is already the deepest
/// fallback in its family — there is no further step to cap to.
///
/// `Quic` clamps to `WsH2` to match the legacy raw-QUIC fallback
/// behaviour. `WsH2` does *not* downgrade through this window — the
/// per-host `ws_mode_cache` already handles `WsH2 → WsH1` clamping
/// across uplinks; adding a per-uplink hop on top would log twice
/// for the same observed failure.
fn one_step_down(failed: TransportMode) -> Option<TransportMode> {
    match failed {
        TransportMode::WsH3 => Some(TransportMode::WsH2),
        TransportMode::Quic => Some(TransportMode::WsH2),
        TransportMode::XhttpH3 => Some(TransportMode::XhttpH2),
        TransportMode::XhttpH2 => Some(TransportMode::XhttpH1),
        TransportMode::WsH1 | TransportMode::WsH2 | TransportMode::XhttpH1 => None,
    }
}
