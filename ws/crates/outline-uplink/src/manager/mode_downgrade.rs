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
    /// (e.g. `tcp_ok=false` in `ProbeOutcome`). Carries the **effective**
    /// mode the probe actually attempted — when a downgrade window is
    /// active the probe runs against the capped carrier (e.g. `xhttp_h2`
    /// after a previous `xhttp_h3 → xhttp_h2` cap), not the configured
    /// one. Threading the actually-failed carrier through here lets the
    /// monotonic downward cap continue (`xhttp_h2 → xhttp_h1`) instead
    /// of stalling at the first downgrade step forever.
    ProbeTransportFailure(TransportMode),
    /// Probe task itself errored out (ws connect failure, timeout).
    /// Carries the effective mode that was attempted — same reasoning as
    /// [`Self::ProbeTransportFailure`].
    ProbeConnectFailure(&'a anyhow::Error, TransportMode),
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
            ModeDowngradeTrigger::ProbeTransportFailure(attempted)
            | ModeDowngradeTrigger::ProbeConnectFailure(_, attempted) => *attempted,
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
        //
        // Comparing against `configured_mode` (rather than `failed_mode`)
        // here is important: under multi-step downgrades the failed mode
        // may already be a previous cap (`xhttp_h2`), and the new cap
        // (`xhttp_h1`) ranks below configured (`xhttp_h3`) — so the
        // multi-step `xhttp_h3 → h2 → h1` walk is admitted, while a
        // mis-wired cross-family or above-configured trigger is still
        // rejected.
        if family(new_cap) != family(configured_mode) || rank(new_cap) >= rank(configured_mode) {
            return;
        }

        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let new_until = now + duration;

        let (prev_until, prev_cap, consecutive_failures) = {
            let per = self.inner.read_status(index);
            let snapshot = per.of(transport);
            (
                snapshot.mode_downgrade_until,
                snapshot.mode_downgrade_capped_to,
                snapshot.consecutive_failures,
            )
        };
        let window_active = prev_until.is_some_and(|t| t > now);
        let newly_started = prev_until.is_none_or(|t| t < now);
        let advances_deadline = prev_until.is_none_or(|t| t < new_until);

        // Min-failures gate for further descent: when a probe trigger
        // arrives in an already-capped window and the failed mode is
        // the same as (or below) the current cap — i.e. the probe
        // tested the capped carrier and failed — we hold the cap in
        // place until `consecutive_failures` reaches the operator's
        // `probe.min_failures` threshold. Without this gate a single
        // flaky probe at the capped rank pushes the cap one step
        // deeper for a full TTL even when the capped carrier is
        // mostly healthy, producing the observed "video stalls every
        // ~probe_interval" pattern on intermittent H2 paths.
        //
        // `RuntimeFailure` and `SilentTransportFallback` skip this
        // gate intentionally: real-traffic failures are a stronger
        // signal than probe failures and warrant immediate descent.
        let probe_trigger = matches!(
            trigger,
            ModeDowngradeTrigger::ProbeTransportFailure(_)
                | ModeDowngradeTrigger::ProbeConnectFailure(_, _)
        );
        let probe_min_failures = self.inner.probe.min_failures.max(1) as u32;
        let descent_gated = probe_trigger
            && window_active
            && match prev_cap {
                Some(prev) => {
                    family(prev) == family(failed_mode) && rank(failed_mode) <= rank(prev)
                },
                None => false,
            }
            && consecutive_failures < probe_min_failures;

        // Cap update rule: monotonically downward inside an active
        // window. If the previous cap is in the same family and already
        // ranks lower than `new_cap`, keep it — a `XhttpH3 → XhttpH2`
        // re-trigger after a previous `XhttpH2 → XhttpH1` step must not
        // raise the ceiling back to `XhttpH2`. Outside an active window
        // the previous cap is stale, so always overwrite. The descent
        // gate above can also pin the cap in place when probe failures
        // on the capped carrier haven't yet stacked to `min_failures`.
        let updated_cap = match prev_cap {
            Some(prev) if descent_gated => prev,
            Some(prev) if window_active && family(prev) == family(new_cap)
                && rank(prev) < rank(new_cap) =>
            {
                prev
            },
            _ => new_cap,
        };

        let cap_changed = prev_cap != Some(updated_cap);
        if advances_deadline || cap_changed {
            self.inner.with_status_mut(index, |status| {
                let per = match transport {
                    TransportKind::Tcp => &mut status.tcp,
                    TransportKind::Udp => &mut status.udp,
                };
                if advances_deadline {
                    per.mode_downgrade_until = Some(new_until);
                }
                per.mode_downgrade_capped_to = Some(updated_cap);
                if cap_changed {
                    // The capped carrier just moved (first entry into the
                    // window or step further down) — `walk_up_mode_downgrade`
                    // must observe a fresh `min_failures`-long streak of
                    // successes against the **new** rank before lifting it
                    // again. Without resetting here, a probe-success stretch
                    // accumulated against the old (higher) rank could
                    // immediately walk back up the cap that
                    // `SilentTransportFallback` / `RuntimeFailure` just set.
                    per.consecutive_successes = 0;
                }
            });
            // The cached probe transport (if any) was dialled with the
            // old effective mode; the next probe will request the new
            // capped carrier, so a stale cached transport would either
            // mismatch and be discarded anyway or — worse — keep the
            // probe pinned to the failing carrier. Clear it now so the
            // refresh is unambiguous.
            match transport {
                TransportKind::Udp => {
                    super::probe::warm_udp::clear(self.inner.warm_udp_probe_slot(index));
                },
                TransportKind::Tcp => {
                    super::probe::warm_tcp::clear(self.inner.warm_tcp_probe_slot(index));
                },
            }
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
                ModeDowngradeTrigger::ProbeTransportFailure(_) => warn!(
                    uplink = %uplink.name,
                    failed_mode = %failed_mode,
                    capped_to = %updated_cap,
                    downgrade_secs,
                    "{kind_label} probe failed on {failed_mode}, capping carrier to {updated_cap} for next probe cycle"
                ),
                ModeDowngradeTrigger::ProbeConnectFailure(err, _) => warn!(
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

    /// Wire-aware variant of [`Self::note_silent_transport_fallback`]: when
    /// `wire_index == 0`, identical to the primary entry-point; when
    /// `wire_index >= 1`, the downgrade observation is stored against
    /// `fallback_mode_downgrades[wire_index - 1]` instead of primary's
    /// slot. Used by fallback-wire dial paths so a fallback that observes
    /// (e.g.) `XhttpH3 → XhttpH2` doesn't mis-park the primary's mode
    /// while still letting subsequent dials of the same fallback wire
    /// honour the cap.
    ///
    /// Reuses the same family/rank logic as the primary path: the cap
    /// must be in the same family as the wire's configured mode and rank
    /// strictly below it (cross-family or upward triggers are dropped).
    pub fn note_silent_transport_fallback_for_wire(
        &self,
        index: usize,
        transport: TransportKind,
        wire_index: u8,
        requested: TransportMode,
    ) {
        if wire_index == 0 {
            self.note_silent_transport_fallback(index, transport, requested);
            return;
        }
        let slot_idx = (wire_index - 1) as usize;
        let uplink = &self.inner.uplinks[index];
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return;
        };
        let configured_mode = match transport {
            TransportKind::Tcp => fallback.tcp_dial_mode(),
            TransportKind::Udp => fallback.udp_dial_mode(),
        };
        let new_cap = match one_step_down(requested) {
            Some(cap) => cap,
            None => return,
        };
        if family(new_cap) != family(configured_mode) || rank(new_cap) >= rank(configured_mode) {
            return;
        }
        let now = Instant::now();
        let duration = self.inner.load_balancing.mode_downgrade_duration;
        let new_until = now + duration;
        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            // Lazy-extend the per-wire vec; entries default to (None, None).
            while per.fallback_mode_downgrades.len() <= slot_idx {
                per.fallback_mode_downgrades
                    .push(super::status::ModeDowngradeSlot::default());
            }
            let slot = &mut per.fallback_mode_downgrades[slot_idx];
            let window_active = slot.until.is_some_and(|t| t > now);
            // Monotonically-downward cap update mirroring primary's rule:
            // an in-window re-trigger must not raise the ceiling.
            let updated_cap = match slot.capped_to {
                Some(prev)
                    if window_active
                        && family(prev) == family(new_cap)
                        && rank(prev) < rank(new_cap) =>
                {
                    prev
                },
                _ => new_cap,
            };
            slot.until = Some(new_until);
            slot.capped_to = Some(updated_cap);
        });
        debug!(
            uplink = %uplink.name,
            transport = ?transport,
            wire_index,
            requested = %requested,
            capped_to = %new_cap,
            duration_secs = duration.as_secs(),
            "fallback wire mode-downgrade window opened"
        );
    }

    /// Read the effective TCP / UDP mode for a specific wire on this uplink:
    /// configured mode for that wire, capped by any active downgrade window
    /// in the wire's slot. Wire 0 reuses the existing primary path; wire >= 1
    /// reads `fallback_mode_downgrades[wire_index - 1]`. Out-of-range wires
    /// return their configured mode unchanged (no slot, no downgrade).
    pub async fn effective_tcp_mode_for_wire(
        &self,
        index: usize,
        wire_index: u8,
    ) -> crate::config::TransportMode {
        if wire_index == 0 {
            return self.effective_tcp_mode(index).await;
        }
        let uplink = &self.inner.uplinks[index];
        let slot_idx = (wire_index - 1) as usize;
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return uplink.tcp_dial_mode();
        };
        let configured = fallback.tcp_dial_mode();
        if !matches!(fallback.transport, UplinkTransport::Ws | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        wire_capped_or_configured(&status.tcp, slot_idx, configured)
    }

    /// UDP counterpart to [`Self::effective_tcp_mode_for_wire`].
    pub async fn effective_udp_mode_for_wire(
        &self,
        index: usize,
        wire_index: u8,
    ) -> crate::config::TransportMode {
        if wire_index == 0 {
            return self.effective_udp_mode(index).await;
        }
        let uplink = &self.inner.uplinks[index];
        let slot_idx = (wire_index - 1) as usize;
        let Some(fallback) = uplink.fallbacks.get(slot_idx) else {
            return uplink.udp_dial_mode();
        };
        let configured = fallback.udp_dial_mode();
        if !matches!(fallback.transport, UplinkTransport::Ws | UplinkTransport::Vless) {
            return configured;
        }
        let status = self.inner.read_status(index);
        wire_capped_or_configured(&status.udp, slot_idx, configured)
    }

    /// Walk the active mode-downgrade cap up by one carrier rank when
    /// the regular probe has succeeded against the capped (effective)
    /// carrier `min_failures` times in a row. Used as the
    /// reactive-recovery counterpart to the H3 recovery probe: while
    /// `run_h3_recovery_probes` tests the **configured** carrier
    /// directly, this path lets the system claw back rank-by-rank when
    /// only the capped carrier has been confirmed healthy by the
    /// ordinary probe loop.
    ///
    /// Behaviour:
    /// * No active window or no cap set → no-op.
    /// * Counter `consecutive_successes < min_failures` → no-op (the
    ///   regular probe success increments the counter, so this builds
    ///   up over `min_failures` cycles before each step).
    /// * Otherwise the cap moves one rank up via [`one_step_up`]. If
    ///   the new rank reaches the configured carrier the cap is
    ///   cleared entirely. The success counter is reset to zero so the
    ///   next step requires a fresh `min_failures` streak.
    ///
    /// Without this path the cap could only fall through TTL expiry,
    /// which in combination with `extend_mode_downgrade` re-firing on
    /// every cycle's H2 probe failure traps real traffic on the
    /// deepest fallback for `mode_downgrade_duration` at a stretch
    /// even when the capped carrier itself is healthy.
    pub(crate) fn walk_up_mode_downgrade(&self, index: usize, transport: TransportKind) {
        let uplink = &self.inner.uplinks[index];
        if !matches!(uplink.transport, UplinkTransport::Ws | UplinkTransport::Vless) {
            return;
        }
        let configured_mode = match transport {
            TransportKind::Tcp => uplink.tcp_dial_mode(),
            TransportKind::Udp => uplink.udp_dial_mode(),
        };
        let min_successes = self.inner.probe.min_failures.max(1) as u32;
        let now = Instant::now();

        // Outcome captured inside the critical section so the log can
        // run after the lock is released — `tracing` macros allocate
        // and we'd rather not hold the status lock across that.
        enum Outcome {
            NoOp,
            Cleared { from: TransportMode },
            StepUp { from: TransportMode, to: TransportMode },
        }
        let mut outcome = Outcome::NoOp;

        self.inner.with_status_mut(index, |status| {
            let per = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            let Some(prev_cap) = per.mode_downgrade_capped_to else { return };
            if per.mode_downgrade_until.is_none_or(|t| t <= now) {
                return;
            }
            if per.consecutive_successes < min_successes {
                return;
            }
            // Defensive: a cross-family cap shouldn't exist alongside the
            // current configured family (the descent path enforces same-
            // family writes), but if it does we'd rather clear it than
            // mis-walk into the wrong chain.
            if family(prev_cap) != family(configured_mode) {
                per.mode_downgrade_until = None;
                per.mode_downgrade_capped_to = None;
                per.consecutive_successes = 0;
                outcome = Outcome::Cleared { from: prev_cap };
                return;
            }
            match one_step_up(prev_cap) {
                None => {
                    // Already at the family's top — nothing higher to
                    // walk to. Drop the cap; configured carrier is the
                    // ceiling.
                    per.mode_downgrade_until = None;
                    per.mode_downgrade_capped_to = None;
                    per.consecutive_successes = 0;
                    outcome = Outcome::Cleared { from: prev_cap };
                },
                Some(next) if rank(next) >= rank(configured_mode) => {
                    // Walking up one rank reaches (or matches) the
                    // configured carrier — recovery complete, clear
                    // the window outright.
                    per.mode_downgrade_until = None;
                    per.mode_downgrade_capped_to = None;
                    per.consecutive_successes = 0;
                    outcome = Outcome::Cleared { from: prev_cap };
                },
                Some(next) => {
                    per.mode_downgrade_capped_to = Some(next);
                    // Refresh the deadline so the new rank gets a full
                    // window's worth of probe cycles to prove itself
                    // before the natural TTL fires.
                    per.mode_downgrade_until =
                        Some(now + self.inner.load_balancing.mode_downgrade_duration);
                    per.consecutive_successes = 0;
                    outcome = Outcome::StepUp { from: prev_cap, to: next };
                },
            }
            // The cached probe transport (if any) was dialled at the
            // old cap; clear it so the next probe refreshes against
            // the walked-up carrier.
            match transport {
                TransportKind::Udp => {
                    super::probe::warm_udp::clear(self.inner.warm_udp_probe_slot(index));
                },
                TransportKind::Tcp => {
                    super::probe::warm_tcp::clear(self.inner.warm_tcp_probe_slot(index));
                },
            }
        });

        let kind_label = match transport {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
        };
        match outcome {
            Outcome::NoOp => {},
            Outcome::Cleared { from } => debug!(
                uplink = %uplink.name,
                kind = ?transport,
                from = %from,
                configured = %configured_mode,
                "{kind_label} mode-downgrade cap cleared by walk-up — capped carrier confirmed healthy"
            ),
            Outcome::StepUp { from, to } => debug!(
                uplink = %uplink.name,
                kind = ?transport,
                from = %from,
                to = %to,
                "{kind_label} mode-downgrade cap walked up after consecutive successes on capped carrier"
            ),
        }
    }

    /// Clear the downgrade window for `(index, transport)`. Resets both
    /// the deadline and the cap so the next dial returns to the
    /// configured mode. Called when an explicit recovery re-probe
    /// confirms that the configured carrier is back, or when the
    /// reactive walk-up path lifts the cap all the way to configured.
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

/// Mirror of `capped_or_configured` (in standby/mod.rs) but for a
/// fallback wire's per-wire slot in `fallback_mode_downgrades`.
/// Returns the cap when the per-wire window is active and the cap is
/// set; falls back to the configured mode in any other case (no slot,
/// expired window, missing cap — defensive).
fn wire_capped_or_configured(
    status: &super::status::PerTransportStatus,
    slot_idx: usize,
    configured: TransportMode,
) -> TransportMode {
    let now = Instant::now();
    let Some(slot) = status.fallback_mode_downgrades.get(slot_idx) else {
        return configured;
    };
    match (slot.until, slot.capped_to) {
        (Some(until), Some(cap)) if until > now => cap,
        _ => configured,
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

/// Inverse of [`one_step_down`]: map a capped carrier to the next
/// higher rank in its own family. Drives the walk-up path that lifts
/// a probe-confirmed cap one rank at a time toward the configured
/// carrier when the capped carrier itself proves healthy. Returns
/// `None` for the deepest fallbacks (`WsH3`, `XhttpH3`, raw `Quic`)
/// — they have nothing higher to walk to.
///
/// `WsH2 → WsH3` matches the WS family's natural top; the WS chain
/// never walks up to `Quic` (raw-QUIC is operator-configured-only —
/// recovery returns to the configured carrier, never above it).
fn one_step_up(capped: TransportMode) -> Option<TransportMode> {
    match capped {
        TransportMode::WsH1 => Some(TransportMode::WsH2),
        TransportMode::WsH2 => Some(TransportMode::WsH3),
        TransportMode::XhttpH1 => Some(TransportMode::XhttpH2),
        TransportMode::XhttpH2 => Some(TransportMode::XhttpH3),
        TransportMode::WsH3 | TransportMode::XhttpH3 | TransportMode::Quic => None,
    }
}
