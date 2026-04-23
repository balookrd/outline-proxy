//! Single source of truth for the H3→H2 downgrade window.
//!
//! Four independent events can (re)set [`PerTransportStatus::h3_downgrade_until`]:
//! runtime traffic failure, probe transport failure, probe connect failure,
//! and an H3 recovery re-probe that failed to confirm recovery.  All of them
//! go through [`UplinkManager::extend_h3_downgrade`] so the guard conditions
//! (WS transport, H3 mode), the "set or extend — never shorten" rule, and the
//! "log once per window start" rule live in exactly one place.
//!
//! [`PerTransportStatus::h3_downgrade_until`]: crate::types::PerTransportStatus::h3_downgrade_until

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{UplinkTransport, WsTransportMode};

use super::super::types::{TransportKind, UplinkManager};

/// Why a downgrade window is being set or extended.  Controls the log
/// message and level emitted when the call starts a *new* window (silent
/// when it extends one that is already active).
pub(crate) enum H3DowngradeTrigger<'a> {
    /// Real traffic observed a transport-level failure on an H3 session.
    RuntimeFailure(&'a anyhow::Error),
    /// Probe task completed but the per-transport check failed
    /// (e.g. `tcp_ok=false` in `ProbeOutcome`).
    ProbeTransportFailure,
    /// Probe task itself errored out (ws connect failure, timeout).
    ProbeConnectFailure(&'a anyhow::Error),
    /// Explicit H3 recovery re-probe failed to confirm H3 liveness.
    RecoveryReprobeFail,
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
    /// window are silent, except [`H3DowngradeTrigger::RecoveryReprobeFail`]
    /// which still emits a debug breadcrumb when it actually advances the
    /// deadline (preserves the pre-refactor recovery log).
    pub(crate) fn extend_h3_downgrade(
        &self,
        index: usize,
        transport: TransportKind,
        trigger: H3DowngradeTrigger<'_>,
    ) {
        let uplink = &self.inner.uplinks[index];
        if uplink.transport != UplinkTransport::Ws {
            return;
        }
        let ws_mode = match transport {
            TransportKind::Tcp => uplink.tcp_ws_mode,
            TransportKind::Udp => uplink.udp_ws_mode,
        };
        if ws_mode != WsTransportMode::H3 {
            return;
        }

        let now = Instant::now();
        let duration = self.inner.load_balancing.h3_downgrade_duration;
        let new_until = now + duration;

        let prev = self.inner.read_status(index).of(transport).h3_downgrade_until;
        let newly_started = prev.is_none_or(|t| t < now);
        let advances_deadline = prev.is_none_or(|t| t < new_until);

        if advances_deadline {
            self.inner.with_status_mut(index, |status| {
                let per = match transport {
                    TransportKind::Tcp => &mut status.tcp,
                    TransportKind::Udp => &mut status.udp,
                };
                per.h3_downgrade_until = Some(new_until);
            });
        }

        let downgrade_secs = duration.as_secs();
        if newly_started {
            match (&trigger, transport) {
                (H3DowngradeTrigger::RuntimeFailure(err), TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 TCP runtime error detected, downgrading TCP transport to H2"
                ),
                (H3DowngradeTrigger::RuntimeFailure(err), TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 UDP runtime error detected, downgrading UDP transport to H2"
                ),
                (H3DowngradeTrigger::ProbeTransportFailure, TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    downgrade_secs,
                    "H3 TCP probe failed, downgrading to H2 for next probe cycle"
                ),
                (H3DowngradeTrigger::ProbeTransportFailure, TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    downgrade_secs,
                    "H3 UDP probe failed, downgrading to H2 for next probe cycle"
                ),
                (H3DowngradeTrigger::ProbeConnectFailure(err), TransportKind::Tcp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 probe connection failed, downgrading TCP to H2"
                ),
                (H3DowngradeTrigger::ProbeConnectFailure(err), TransportKind::Udp) => warn!(
                    uplink = %uplink.name,
                    error = %format!("{err:#}"),
                    downgrade_secs,
                    "H3 probe connection failed, downgrading UDP to H2"
                ),
                (H3DowngradeTrigger::RecoveryReprobeFail, _) => debug!(
                    uplink = %uplink.name,
                    kind = ?transport,
                    downgrade_secs,
                    "H3 still unreachable, starting downgrade window after recovery probe"
                ),
            }
        } else if matches!(trigger, H3DowngradeTrigger::RecoveryReprobeFail) && advances_deadline {
            debug!(
                uplink = %uplink.name,
                kind = ?transport,
                downgrade_secs,
                "H3 still unreachable after recovery probe, extending downgrade window"
            );
        }
    }

    /// Clear the H3 downgrade window for `(index, transport)`.  Called when
    /// an explicit H3 recovery re-probe confirms that H3 is back.
    pub(crate) fn clear_h3_downgrade(&self, index: usize, transport: TransportKind) {
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => status.tcp.h3_downgrade_until = None,
            TransportKind::Udp => status.udp.h3_downgrade_until = None,
        });
    }
}
