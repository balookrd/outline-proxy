//! Per-uplink, per-transport "active wire" state machine.
//!
//! For an uplink declared with `[[outline.uplinks.fallbacks]]`, the active
//! wire is the index into `[primary, fallbacks[0], fallbacks[1], ...]` of the
//! wire that subsequent **new sessions** should start with. The dial loop
//! still tries every wire in a single session (so a freshly-broken active
//! wire still recovers via fallback inside that session), but the per-session
//! starting point is sticky across sessions until either the active wire
//! has accumulated `probe.min_failures` consecutive dial failures or the
//! auto-failback timer fires.
//!
//! Auto-failback uses the existing `LoadBalancingConfig::mode_downgrade_duration`
//! knob — one timer for both per-wire mode downgrades and per-uplink
//! active-wire pinning. When the pin expires, the active wire snaps back to
//! the primary (index 0) so the next session retries the operator's
//! configured first-choice wire.
//!
//! State is per-transport (TCP and UDP advance independently) — TCP failures
//! must not flip a UDP wire that may still be working, and vice versa.
//! Probe rerouting onto the active wire and snapshot/dashboard exposure of
//! this state are wired in subsequent commits.
//!
//! For uplinks **without** any fallbacks, every method here is a no-op or
//! returns the trivial answer (`active_wire = 0`, dial order = `[0]`).

use tokio::time::Instant;
use tracing::{debug, info};

use crate::types::{TransportKind, UplinkManager};

impl UplinkManager {
    /// Read the currently-active wire index for `uplink_index` on `transport`.
    /// Performs an inline auto-failback check: if the pin has expired, the
    /// active wire is snapped back to `0` (primary) before the value is
    /// returned. Caller-visible side effect: subsequent calls observe the
    /// snap-back without needing a separate `tick`.
    ///
    /// Always `0` for uplinks declared without `[[outline.uplinks.fallbacks]]`.
    pub fn active_wire(&self, uplink_index: usize, transport: TransportKind) -> u8 {
        let now = Instant::now();
        self.inner.with_status_mut(uplink_index, |status| {
            let st = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            if let Some(until) = st.active_wire_pinned_until {
                if until <= now {
                    if st.active_wire != 0 {
                        info!(
                            uplink_index,
                            transport = ?transport,
                            previous_wire = st.active_wire,
                            "auto-failback timer expired, snapping active wire back to primary",
                        );
                    }
                    st.active_wire = 0;
                    st.active_wire_pinned_until = None;
                    st.active_wire_streak = 0;
                }
            }
            st.active_wire
        })
    }

    /// Build the per-session dial order over the wire chain
    /// `[primary, fallbacks[0], ..., fallbacks[total_wires-1]]`. Returns
    /// indices in the order they should be tried this session: starting at
    /// the currently-active wire, then continuing through the chain wrapping
    /// at the end so primary still gets tried as a last resort even when
    /// active is pinned to a fallback.
    ///
    /// `total_wires` is `1 + uplink.fallbacks.len()`. Caller passes it
    /// explicitly to keep this module independent of the uplink config slice.
    pub fn wire_dial_order(
        &self,
        uplink_index: usize,
        transport: TransportKind,
        total_wires: usize,
    ) -> Vec<u8> {
        if total_wires <= 1 {
            return vec![0];
        }
        let active = self.active_wire(uplink_index, transport) as usize;
        let active = active.min(total_wires - 1); // defensive cap
        let total = total_wires as u8;
        let mut order = Vec::with_capacity(total_wires);
        for offset in 0..total_wires {
            let idx = ((active + offset) % total_wires) as u8;
            order.push(idx);
        }
        debug_assert_eq!(order.len(), total_wires);
        debug_assert!(order.iter().all(|&i| i < total));
        order
    }

    /// Record the outcome of a single wire dial attempt. Drives the active-
    /// wire transitions:
    ///
    /// - **Success** on `attempted_wire`: clears `active_wire_streak`. The
    ///   active wire is *not* changed by a success — sticky behaviour is
    ///   driven entirely by failures and the auto-failback timer.
    /// - **Failure** on `attempted_wire`: increments `active_wire_streak`
    ///   when the failed wire matches the current active wire (failures on
    ///   non-active wires inside the same session are session-local fallback
    ///   churn and don't influence the sticky state machine). When the
    ///   streak reaches `min_failures` and at least one alternative wire
    ///   exists (`total_wires > 1`), `active_wire` advances to the next wire
    ///   in the chain (wrapping at `total_wires`), the streak resets, and
    ///   `active_wire_pinned_until` is set to `now + mode_downgrade_duration`
    ///   to keep the new active sticky for that window.
    ///
    /// `min_failures` comes from the per-group `ProbeConfig`, mirroring the
    /// existing health-flip threshold so operators don't have to learn a new
    /// knob.
    pub fn record_wire_outcome(
        &self,
        uplink_index: usize,
        transport: TransportKind,
        attempted_wire: u8,
        success: bool,
        total_wires: usize,
    ) {
        if total_wires <= 1 {
            return;
        }
        let min_failures = self.inner.probe.min_failures.max(1) as u32;
        let pin_window = self.inner.load_balancing.mode_downgrade_duration;
        let now = Instant::now();
        let group_name = self.inner.group_name.clone();
        let uplink_name = self.inner.uplinks[uplink_index].name.clone();
        let total = total_wires as u8;

        self.inner.with_status_mut(uplink_index, |status| {
            let st = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            if success {
                if attempted_wire == st.active_wire {
                    st.active_wire_streak = 0;
                }
                return;
            }
            // Failure on a non-active wire is session-local churn — the
            // active wire's sticky state machine is driven only by failures
            // on the wire that *new sessions* land on.
            if attempted_wire != st.active_wire {
                return;
            }
            st.active_wire_streak = st.active_wire_streak.saturating_add(1);
            if st.active_wire_streak < min_failures {
                return;
            }
            // Streak threshold reached — advance the active wire.
            let previous = st.active_wire;
            let next = (previous + 1) % total;
            st.active_wire = next;
            st.active_wire_streak = 0;
            // Pin the new active wire only when we moved away from primary;
            // wrapping back to primary clears the pin so the next session is
            // a clean retry from the operator's first-choice wire.
            st.active_wire_pinned_until = if next == 0 { None } else { Some(now + pin_window) };
            info!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?transport,
                previous_wire = previous,
                new_wire = next,
                pin_window_secs = pin_window.as_secs(),
                "active wire advanced after consecutive dial failures",
            );
            outline_metrics::record_failover(
                match transport {
                    TransportKind::Tcp => "tcp_active_wire",
                    TransportKind::Udp => "udp_active_wire",
                },
                &group_name,
                &previous.to_string(),
                &next.to_string(),
            );
            debug!(
                uplink = %uplink_name,
                transport = ?transport,
                "active_wire_streak reset; pin = {:?}",
                st.active_wire_pinned_until,
            );
        });
    }
}
