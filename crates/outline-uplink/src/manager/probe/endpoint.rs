//! Manager side of the endpoint-reachability short-circuit.
//!
//! [`crate::probe::endpoint`] answers "did any endpoint of this uplink accept
//! a bare TCP connect"; this module decides what that answer does to
//! [`UplinkStatus`].
//!
//! The rule is deliberately narrow. A *reachable* endpoint changes nothing —
//! it only clears the streak, and the regular probe decides health as always.
//! An *unreachable* one, repeated `probe.min_failures` cycles in a row,
//! condemns the uplink directly:
//!
//! * `healthy = Some(false)` on both planes (UDP only when some wire could
//!   carry UDP at all), plus the usual failure penalty and cooldown, so the
//!   candidate filter drops the uplink immediately;
//! * `last_any_wire_success` is aged out of the runtime-failure window — the
//!   liveness override behind `health_effective` would otherwise keep painting
//!   the uplink "Ready" for up to a full window after the host went away,
//!   which is the exact confusion this check exists to remove;
//! * `wires_failed_in_round` is reset, because the `shuffle_wires` round is
//!   moot once the whole host is gone.
//!
//! What it pointedly does **not** touch is the carrier-descent state. Dropping
//! `h3 → h2` cannot help when nothing is listening, and a cap installed here
//! would outlive the outage and force recovered traffic onto a slower carrier
//! for the rest of the downgrade window.

use tokio::time::Instant;
use tracing::warn;

use crate::config::LoadBalancingConfig;
use crate::manager::status::{PerTransportStatus, UplinkStatus};
use crate::penalty::add_penalty;
use crate::types::{Uplink, UplinkManager};

/// Apply one plane's share of an "all endpoints unreachable" verdict.
fn condemn_plane(
    plane: &mut PerTransportStatus,
    now: Instant,
    load_balancing: &LoadBalancingConfig,
) {
    plane.healthy = Some(false);
    plane.consecutive_successes = 0;
    plane.consecutive_failures = plane.consecutive_failures.saturating_add(1);
    plane.cooldown_until = Some(now + load_balancing.failure_cooldown);
    // A dead host is not a wire-rotation problem; drop the round so a later
    // recovery starts from a clean chain instead of one step from exhaustion.
    plane.wires_failed_in_round = 0;
    add_penalty(&mut plane.penalty, now, load_balancing);
    // Age the any-wire liveness stamp out of the window rather than clearing
    // it: `None` means "no wire ever worked", which `fallback_bootstrap_allowed`
    // reads as permission to keep dialling. We know the opposite — wires used
    // to work and the host is gone — so the stamp stays present but stale.
    if let Some(last) = plane.last_any_wire_success
        && now.saturating_duration_since(last) < load_balancing.runtime_failure_window
    {
        plane.last_any_wire_success = now.checked_sub(load_balancing.runtime_failure_window);
    }
}

impl UplinkManager {
    /// Record that at least one endpoint of `index` answered a bare connect.
    /// Only resets the streak — health stays the regular probe's business.
    pub(crate) fn note_endpoint_reachable(&self, index: usize) {
        self.inner.with_status_mut(index, |status| {
            status.endpoint_unreachable_streak = 0;
        });
    }

    /// Record a cycle in which every endpoint of `index` failed the bare-TCP
    /// check. Returns `true` once the streak has reached `probe.min_failures`
    /// and the uplink has been condemned, so the caller can skip the (now
    /// pointless) expensive probe stages for this cycle.
    pub(crate) fn note_endpoint_unreachable(
        &self,
        index: usize,
        uplink: &Uplink,
        endpoints: &str,
    ) -> bool {
        let now = Instant::now();
        let min_failures = (self.inner.probe.min_failures as u32).max(1);
        let load_balancing = self.inner.load_balancing.clone();
        let supports_udp = uplink.supports_udp_any();
        let (streak, condemned) = self.inner.with_status_mut(index, |status: &mut UplinkStatus| {
            status.last_checked = Some(now);
            status.endpoint_unreachable_streak =
                status.endpoint_unreachable_streak.saturating_add(1);
            let condemned = status.endpoint_unreachable_streak >= min_failures;
            if condemned {
                condemn_plane(&mut status.tcp, now, &load_balancing);
                if supports_udp {
                    condemn_plane(&mut status.udp, now, &load_balancing);
                }
                status.last_error = Some(format!("endpoint unreachable: {endpoints}"));
            }
            (status.endpoint_unreachable_streak, condemned)
        });
        if condemned {
            warn!(
                uplink = %uplink.name,
                endpoints,
                streak,
                "every uplink endpoint refused a bare TCP connect — marking uplink down",
            );
        }
        condemned
    }
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
