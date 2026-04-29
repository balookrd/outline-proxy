//! Single source of truth for the "advanced WS mode → H2" downgrade window.
//!
//! Originally only H3 → H2 (hence the field name `mode_downgrade_until`); now
//! also covers raw QUIC → H2 for both Ws and Vless transports.  Four
//! independent events can (re)set [`PerTransportStatus::mode_downgrade_until`]:
//! runtime traffic failure, probe transport failure, probe connect failure,
//! and a recovery re-probe that failed to confirm recovery.  All of them go
//! through [`UplinkManager::extend_mode_downgrade`] so the guard conditions
//! (Ws/Vless transport, H3-or-Quic dial mode), the "set or extend — never
//! shorten" rule, and the "log once per window start" rule live in exactly
//! one place.
//!
//! [`PerTransportStatus::mode_downgrade_until`]: crate::types::PerTransportStatus::mode_downgrade_until

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
        let ws_mode = match transport {
            TransportKind::Tcp => uplink.tcp_dial_mode(),
            TransportKind::Udp => uplink.udp_dial_mode(),
        };
        if !matches!(ws_mode, TransportMode::WsH3 | TransportMode::Quic) {
            return;
        }

        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let new_until = now + duration;

        let prev = self.inner.read_status(index).of(transport).mode_downgrade_until;
        let newly_started = prev.is_none_or(|t| t < now);
        let advances_deadline = prev.is_none_or(|t| t < new_until);

        if advances_deadline {
            self.inner.with_status_mut(index, |status| {
                let per = match transport {
                    TransportKind::Tcp => &mut status.tcp,
                    TransportKind::Udp => &mut status.udp,
                };
                per.mode_downgrade_until = Some(new_until);
            });
        }

        let downgrade_secs = duration.as_secs();
        if newly_started {
            match (&trigger, transport) {
                (ModeDowngradeTrigger::RuntimeFailure(err), TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 TCP runtime error detected, downgrading TCP transport to H2"
                ),
                (ModeDowngradeTrigger::RuntimeFailure(err), TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 UDP runtime error detected, downgrading UDP transport to H2"
                ),
                (ModeDowngradeTrigger::ProbeTransportFailure, TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    downgrade_secs,
                    "H3 TCP probe failed, downgrading to H2 for next probe cycle"
                ),
                (ModeDowngradeTrigger::ProbeTransportFailure, TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    downgrade_secs,
                    "H3 UDP probe failed, downgrading to H2 for next probe cycle"
                ),
                (ModeDowngradeTrigger::ProbeConnectFailure(err), TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 probe connection failed, downgrading TCP to H2"
                ),
                (ModeDowngradeTrigger::ProbeConnectFailure(err), TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 probe connection failed, downgrading UDP to H2"
                ),
                (ModeDowngradeTrigger::RecoveryReprobeFail, _) => debug!(
                    uplink = %uplink.name,
                    kind = ?transport,
                    downgrade_secs,
                    "H3 still unreachable, starting downgrade window after recovery probe"
                ),
                (ModeDowngradeTrigger::SilentTransportFallback(requested), TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    requested_mode = %requested,
                    downgrade_secs,
                    "TCP dial silently fell back from {requested} via ws_mode_cache, syncing per-uplink downgrade window"
                ),
                (ModeDowngradeTrigger::SilentTransportFallback(requested), TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    requested_mode = %requested,
                    downgrade_secs,
                    "UDP dial silently fell back from {requested} via ws_mode_cache, syncing per-uplink downgrade window"
                ),
            }
        } else if matches!(trigger, ModeDowngradeTrigger::RecoveryReprobeFail) && advances_deadline {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                downgrade_secs,
                "H3 still unreachable after recovery probe, extending downgrade window"
            );
        }
    }

    /// Public entry-point for dial-time fallback: a synchronous QUIC (or H3)
    /// dial just failed, so mark the downgrade window the same way a runtime
    /// failure would.  The next call to `effective_*_ws_mode` will return H2
    /// for the rest of the window.
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

    /// Clear the H3 downgrade window for `(index, transport)`.  Called when
    /// an explicit H3 recovery re-probe confirms that H3 is back.
    pub(crate) fn clear_mode_downgrade(&self, index: usize, transport: TransportKind) {
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => status.tcp.mode_downgrade_until = None,
            TransportKind::Udp => status.udp.mode_downgrade_until = None,
        });
    }
}
