//! Weighted-random forced re-selection of the strict active uplink.
//!
//! Scheduled (`reselect_at` / `reselect_interval`) or manual
//! (`POST /control/reselect`) rotation of the active_passive slot: the current
//! active is excluded, the winner is drawn with probability proportional to
//! `penalty_weight × configured weight` among healthy, enabled, non-cooldown
//! candidates. The commit mirrors the carrier-degraded automatic soft switch
//! (`manager/candidates.rs`): move the slot(s), reseed the sticky route, keep
//! all accumulated health/EWMA/penalty state (NO `reset_all_uplink_statuses`).
//!
//! `RoutingScope::Global` has one active slot, so there is one draw. `RoutingScope::PerUplink`
//! has independent TCP and UDP active slots — gated on their own transport's
//! health/cooldown/penalty and excluding only that transport's own current
//! active — so the two draws can legitimately land on different uplinks. See
//! [`UplinkManager::reselect_per_uplink`] for how a two-slot move is reported
//! through the single `ReselectOutcome::Switched { from, to, .. }` pair.

use std::time::Duration;

use rand::{Rng, SeedableRng};
use tokio::time::{Instant, sleep};
use tracing::info;

use crate::config::{LoadBalancingMode, RoutingScope};
use crate::manager::sync_order::current_slot_key;
use crate::penalty::{penalty_weight, weighted_pick_with_rng};
use crate::routing_key::strict_route_key;
use crate::selection::{
    cooldown_active, selection_health, strict_gate_transport, supports_transport_for_scope,
};
use crate::types::{TransportKind, UplinkManager};

/// Result of one [`UplinkManager::reselect_active_uplink`] call.
#[derive(Debug, Clone)]
pub enum ReselectOutcome {
    /// The active slot moved from `from` (`None` if it was previously unset)
    /// to the uplink named `to`. `soft` reports the *effective* soft bit
    /// (clamped to `false` off a `shared_resume` cluster).
    ///
    /// For `RoutingScope::PerUplink`, TCP and UDP are drawn independently and
    /// may land on different uplinks; `from`/`to` report the TCP slot's move
    /// when TCP moved, else the UDP slot's move. The `tracing::info!` emitted
    /// for each transport that actually moved is the only place both moves
    /// are visible when they disagree — see
    /// [`UplinkManager::reselect_per_uplink`].
    Switched {
        from: Option<String>,
        to: String,
        soft: bool,
    },
    /// The group is in `active_passive` mode but no eligible candidate
    /// remains once the current active(s) and disabled/unhealthy/cooldown
    /// uplinks are excluded (e.g. a single-uplink group, or — for
    /// `PerUplink` — neither transport has an eligible candidate).
    NoCandidate,
    /// The group is not in `active_passive` mode, or its routing scope has no
    /// single strict active slot to rotate — there is nothing to reselect.
    Skipped { reason: &'static str },
}

impl ReselectOutcome {
    /// Low-cardinality label for `outline_metrics::record_uplink_reselect`.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Switched { .. } => "switched",
            Self::NoCandidate => "no_candidate",
            Self::Skipped { .. } => "skipped",
        }
    }
}

/// How far past a `reselect_at` slot the wall-clock loop may observe it and
/// still fire. The loop ticks every [`WALL_CLOCK_TICK`], so anything
/// comfortably above the tick period works; beyond the tolerance a slot
/// missed (e.g. the host was suspended through it) is skipped rather than
/// fired retroactively.
pub(crate) const RESELECT_SLOT_TOLERANCE_SECS: u32 = 90;
/// Poll period for the wall-clock re-selection loop. Deliberately short
/// relative to [`RESELECT_SLOT_TOLERANCE_SECS`] so a slot cannot be missed
/// between ticks, and short enough to notice a `shutdown` signal promptly.
const WALL_CLOCK_TICK: Duration = Duration::from_secs(30);

/// Pure slot arbiter for the wall-clock loop: returns the index of a slot in
/// `slots` that is due *now* (`secs_of_day` is at or up to
/// [`RESELECT_SLOT_TOLERANCE_SECS`] past the slot's time) and has not already
/// fired today. `last_fired` is `(day_key, slot_index)` of the most recent
/// firing; the same `(day_key, slot_index)` pair is refused, but the day
/// advancing (or a *different* slot index on the same day) is allowed. Slots
/// are checked in configured order and the first due slot wins — callers
/// build `slots` sorted/deduped, so this only matters when two slots are
/// within tolerance of each other and both are due, which the loader's
/// dedup makes rare in practice.
///
/// Known limitation, deliberately not handled: a slot within
/// [`RESELECT_SLOT_TOLERANCE_SECS`] of local midnight (e.g. `23:59`) has its
/// effective window truncated at the day rollover — `day_key` advances and
/// `secs_of_day` resets to `0` while `slot_secs` stays large (e.g. 86340), so
/// the `secs_of_day >= slot_secs` check fails for the rest of the tolerance
/// window on the new day. In practice such a slot gets roughly the tolerance
/// window's worth of seconds *before* midnight rather than the full window,
/// never wrapping into the next day. No wrap-around arithmetic is
/// implemented for this; if it matters, avoid configuring `reselect_at`
/// slots within `RESELECT_SLOT_TOLERANCE_SECS` of midnight.
pub(crate) fn due_slot(
    day_key: i64,
    secs_of_day: u32,
    slots: &[(u8, u8)],
    last_fired: Option<(i64, usize)>,
) -> Option<usize> {
    slots.iter().enumerate().find_map(|(i, &(h, m))| {
        let slot_secs = u32::from(h) * 3600 + u32::from(m) * 60;
        let due =
            secs_of_day >= slot_secs && secs_of_day - slot_secs <= RESELECT_SLOT_TOLERANCE_SECS;
        (due && last_fired != Some((day_key, i))).then_some(i)
    })
}

/// Seeds the wall-clock loop's `last_fired` guard at spawn time (initial
/// process start, or respawn on `/control/apply` hot-apply). If a slot is
/// currently inside its tolerance window, this treats it as already fired
/// today — the loop's first tick will then observe it via [`due_slot`] and
/// correctly refuse to fire it again. This mirrors the existing "a slot
/// missed during sleep/suspend is skipped rather than fired retroactively"
/// semantics: a loop that (re)starts mid-window skips that occurrence
/// instead of risking a duplicate switch (e.g. a hot-apply landing seconds
/// after a slot fired must not have the freshly spawned task fire it again).
/// Returns `None` when no slot is currently due — the ordinary case, where
/// the loop starts with nothing to suppress.
pub(crate) fn initial_last_fired(
    day_key: i64,
    secs_of_day: u32,
    slots: &[(u8, u8)],
) -> Option<(i64, usize)> {
    due_slot(day_key, secs_of_day, slots, None).map(|slot| (day_key, slot))
}

/// Local calendar day key + seconds since local midnight, read from the
/// system clock via `libc::localtime_r`. The workspace has no chrono/`time`
/// dependency and this crate only targets unix, so this is the direct libc
/// call rather than a pulled-in dependency. Returns `None` if the current
/// time cannot be converted (`localtime_r` failure, or the system clock
/// reading before the Unix epoch) — callers treat that as "skip this tick".
fn local_day_and_secs() -> Option<(i64, u32)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let t = now.as_secs() as libc::time_t;
    // SAFETY: `libc::tm` is a `repr(C)` struct; every integer field's
    // all-zero bit pattern is a valid value, and its one non-integer field
    // (`tm_zone: *const c_char` on glibc/musl) is likewise valid when null —
    // a null pointer is never dereferenced, only ever passed through by
    // `localtime_r`. `localtime_r` below fully overwrites every field on
    // success before we read any of them (checked via the null-pointer
    // return first), so the zeroed value is never actually observed.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `&t` and `&mut tm` are valid, non-aliasing, appropriately
    // aligned pointers to stack locals that outlive this call. `localtime_r`
    // is the thread-safe variant (unlike `localtime`, it does not write
    // through a shared static buffer) and does not retain either pointer
    // past its return, so there is no aliasing or lifetime hazard here.
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return None;
    }
    let secs = tm.tm_hour as u32 * 3600 + tm.tm_min as u32 * 60 + tm.tm_sec as u32;
    // `tm_year` is years since 1900, `tm_yday` is 0..=365 — the combination
    // is unique per local calendar day, which is all `due_slot` needs (it
    // never interprets `day_key` as an actual date, only compares equality
    // and ordering with the previous tick's key).
    Some((i64::from(tm.tm_year) * 366 + i64::from(tm.tm_yday), secs))
}

impl UplinkManager {
    /// Spawn the scheduled re-selection loop for this group, if
    /// `load_balancing.reselect_at` or `.reselect_interval` is configured.
    /// Interval mode is a plain monotonic sleep loop; wall-clock mode ticks
    /// every [`WALL_CLOCK_TICK`] and compares local time against the
    /// configured slots via [`due_slot`] — this survives NTP jumps, DST
    /// shifts and suspend (a slot slept through is simply skipped, never
    /// fired retroactively). `reselect_at` and `reselect_interval` are
    /// mutually exclusive by config-loader validation, and both require
    /// `active_passive` mode (checked again below as defence in depth); but
    /// nothing stops both branches running if that were ever violated —
    /// each is independent and `reselect_active_uplink` itself is a no-op
    /// outside `active_passive`.
    ///
    /// Honours this manager's group-scoped shutdown channel — same as
    /// [`Self::spawn_shuffle_timer_loops`] — so the loop(s) die on hot-apply
    /// and must be respawned by the caller for the replacement managers (see
    /// `UplinkRegistry::apply_new_groups`).
    pub fn spawn_reselect_timer_loops(&self) {
        let lb = &self.inner.load_balancing;
        // The config loader only allows `reselect_at`/`reselect_interval` under
        // `active_passive`, so this is unreachable through validated config —
        // but `UplinkManager::new_for_test` and any future entry point can
        // bypass that validation, so guard here too (defence in depth;
        // `reselect_active_uplink` itself would also just no-op with
        // `Skipped`, this only avoids spawning idle tasks for it).
        if lb.mode != LoadBalancingMode::ActivePassive {
            return;
        }
        if let Some(interval) = lb.reselect_interval {
            let manager = self.clone();
            let mut shutdown = self.shutdown_rx();
            info!(
                group = %self.inner.group_name,
                interval_secs = interval.as_secs(),
                "scheduled uplink re-selection loop spawned (interval mode)",
            );
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(interval) => {}
                    }
                    manager.reselect_active_uplink("scheduled_reselect", true).await;
                }
            });
        }
        if !lb.reselect_at.is_empty() {
            let slots = lb.reselect_at.clone();
            let manager = self.clone();
            let mut shutdown = self.shutdown_rx();
            info!(
                group = %self.inner.group_name,
                slots = ?slots,
                "scheduled uplink re-selection loop spawned (wall-clock mode)",
            );
            tokio::spawn(async move {
                // Seed the guard from the clock read at spawn time rather
                // than starting from `None`: a `/control/apply` hot-apply (or
                // process start) landing inside a slot's tolerance window
                // must not let the freshly spawned task fire that slot a
                // second time on the same day. See `initial_last_fired`'s
                // doc comment for why this is a "skip on restart", not a
                // wrap-around/persistence mechanism.
                let mut last_fired: Option<(i64, usize)> = local_day_and_secs()
                    .and_then(|(day_key, secs)| initial_last_fired(day_key, secs, &slots));
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(WALL_CLOCK_TICK) => {}
                    }
                    let Some((day_key, secs)) = local_day_and_secs() else { continue };
                    if let Some(slot) = due_slot(day_key, secs, &slots, last_fired) {
                        last_fired = Some((day_key, slot));
                        manager.reselect_active_uplink("scheduled_reselect", true).await;
                    }
                }
            });
        }
    }

    /// Forced weighted-random rotation of the strict active uplink, always
    /// excluding the current active. `reason` is recorded on the active-uplink
    /// selection state (surfaced on the dashboard) exactly like a failover
    /// reason. `soft` requests a soft (resume-preserving) switch; it is
    /// clamped to `false` off a `shared_resume` cluster, mirroring
    /// [`Self::set_active_uplink_by_name`].
    ///
    /// Records `outline_ws_uplink_reselect_total{group,outcome}`. Use
    /// [`Self::reselect_active_uplink_with_rng`] directly in tests that need
    /// a seeded RNG — that seam does not record the metric.
    ///
    /// Uses an OS-seeded [`rand::rngs::StdRng`] rather than the thread-local
    /// [`rand::rng()`]: the scheduled loops in this module call this method
    /// from a `tokio::spawn`ed task, which requires the returned future to be
    /// `Send`, and `ThreadRng` (backed by an `Rc`) is not. `StdRng` is a
    /// plain value with no thread-affinity, so it stays `Send` across the
    /// `.await` points inside `reselect_active_uplink_with_rng`.
    pub async fn reselect_active_uplink(&self, reason: &str, soft: bool) -> ReselectOutcome {
        let mut rng = rand::rngs::StdRng::from_os_rng();
        let outcome = self.reselect_active_uplink_with_rng(reason, soft, &mut rng).await;
        outline_metrics::record_uplink_reselect(self.group_name(), outcome.metric_label());
        outcome
    }

    pub(crate) async fn reselect_active_uplink_with_rng<R: Rng + ?Sized>(
        &self,
        reason: &str,
        soft: bool,
        rng: &mut R,
    ) -> ReselectOutcome {
        if self.inner.load_balancing.mode != LoadBalancingMode::ActivePassive {
            return ReselectOutcome::Skipped { reason: "not active_passive" };
        }
        let applied_soft = soft && self.inner.load_balancing.shared_resume;
        if self.strict_global_active_uplink() {
            return self.reselect_global(reason, applied_soft, rng).await;
        }
        if self.strict_per_uplink_active_uplink() {
            return self.reselect_per_uplink(reason, applied_soft, rng).await;
        }
        // `active_passive` mode is only strict under `Global` / `PerUplink`
        // routing scope (see `strict_global_active_uplink` /
        // `strict_per_uplink_active_uplink`); other scopes have no single
        // active slot to rotate. Mirrors the same bail in
        // `initialize_strict_active_selection`.
        ReselectOutcome::Skipped {
            reason: "active_passive but not global/per_uplink scope",
        }
    }

    /// One weighted draw among uplinks eligible for `gate`'s health/cooldown/
    /// penalty, excluding `exclude` (that transport's own current active
    /// index — the forced-rotation exclusion), every administratively
    /// disabled uplink, and every uplink that cannot carry `gate` at all
    /// under `scope` (mirrors the `supports_transport_for_scope` filter every
    /// other candidate builder applies — see `build_candidate_states` /
    /// `has_any_healthy` in `manager/candidates.rs`). Without this, a
    /// UDP-incapable uplink whose status happens to read UDP-healthy could
    /// win the strict UDP active slot. Returns `None` when no eligible
    /// candidate remains.
    fn draw_reselect_candidate<R: Rng + ?Sized>(
        &self,
        gate: TransportKind,
        scope: RoutingScope,
        exclude: Option<usize>,
        rng: &mut R,
    ) -> Option<usize> {
        let now = Instant::now();
        let floor = self.inner.load_balancing.health_weight_floor;
        let mut candidates: Vec<usize> = Vec::new();
        let mut weights: Vec<f64> = Vec::new();
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            if exclude == Some(index)
                || !self.inner.admin_enabled(index)
                || !supports_transport_for_scope(uplink, gate, scope)
            {
                continue;
            }
            let weight = self.inner.with_status(index, |status| {
                let eligible =
                    selection_health(status, uplink, gate, now, scope, &self.inner.load_balancing)
                        && !cooldown_active(status, gate, now);
                eligible.then(|| {
                    let ts = status.of(gate);
                    penalty_weight(&ts.penalty, now, &self.inner.load_balancing, floor)
                        * uplink.weight.max(0.0)
                })
            });
            if let Some(weight) = weight {
                candidates.push(index);
                weights.push(weight);
            }
        }
        weighted_pick_with_rng(&weights, rng).map(|pos| candidates[pos])
    }

    /// This slot's decision for `gate` under `reselect_sync`: `None` when the
    /// clock is unreadable, when no slots are configured (the config loader
    /// refuses that combination) or when nothing is currently eligible.
    fn sync_target(&self, gate: TransportKind, scope: RoutingScope) -> Option<usize> {
        let (day_key, secs) = local_day_and_secs()?;
        let key = current_slot_key(day_key, secs, &self.inner.load_balancing.reselect_at)?;
        self.sync_pick(key, gate, scope, Instant::now())
    }

    /// `RoutingScope::Global`: one active slot, one draw.
    async fn reselect_global<R: Rng + ?Sized>(
        &self,
        reason: &str,
        soft: bool,
        rng: &mut R,
    ) -> ReselectOutcome {
        // A reselect is operator-configured, not machine-driven: `soft` is the
        // operator's choice (already clamped to the group's `shared_resume` by
        // the caller), so a hard one means the same drain an explicit hard
        // switch does.
        let intent = crate::types::SwitchIntent::from_operator_soft(soft);
        let scope = self.inner.load_balancing.routing_scope;
        let gate = strict_gate_transport(scope, TransportKind::Tcp);
        let current = self.inner.active_uplinks.read().await.global;
        let sync = self.inner.load_balancing.reselect_sync;
        let target = if sync {
            let Some(target) = self.sync_target(gate, scope) else {
                return ReselectOutcome::NoCandidate;
            };
            // Re-applying a decision this node already follows must not move
            // the slot to itself. The unsynchronized path cannot reach this
            // case (it excludes the current active by construction); the
            // synchronized one hits it whenever the node is already correct.
            if current == Some(target) {
                return ReselectOutcome::Skipped { reason: "already on the slot's uplink" };
            }
            target
        } else {
            let Some(target) = self.draw_reselect_candidate(gate, scope, current, rng) else {
                return ReselectOutcome::NoCandidate;
            };
            target
        };
        let from = current.map(|i| self.inner.uplinks[i].name.clone());
        let to = self.inner.uplinks[target].name.clone();
        // Same commit shape as the carrier-degraded soft failover: slot +
        // sticky reseed, health/EWMA/penalty state left untouched (NOT the
        // clean-slate reset a manual operator switch performs).
        self.set_active_uplink_index_for_transport(TransportKind::Tcp, target, reason, intent)
            .await;
        let key = strict_route_key(TransportKind::Tcp, scope);
        self.store_sticky_route(&key, target).await;
        info!(
            group = %self.inner.group_name,
            from = ?from,
            to = %to,
            soft,
            reason,
            sync,
            "weighted re-selection moved the strict active uplink (global)",
        );
        ReselectOutcome::Switched { from, to, soft }
    }

    /// `RoutingScope::PerUplink`: TCP and UDP each have their own active
    /// slot, so each gets its own independent weighted draw — gated on that
    /// transport's own health/cooldown/penalty and excluding only that
    /// transport's own current active. The two draws may land on different
    /// uplinks; that is the intended behaviour of this scope (the carrier-
    /// degraded automatic failover this mirrors also gates each transport
    /// independently — see `manager/candidates.rs`).
    ///
    /// Reports `NoCandidate` only when *neither* transport has an eligible
    /// candidate. Otherwise reports `Switched`, with `from`/`to` describing
    /// the TCP slot's move if TCP moved, else the UDP slot's move — the only
    /// place both moves are visible when they disagree is the per-transport
    /// `tracing::info!` emitted below for each slot that actually moved.
    async fn reselect_per_uplink<R: Rng + ?Sized>(
        &self,
        reason: &str,
        soft: bool,
        rng: &mut R,
    ) -> ReselectOutcome {
        // See `reselect_global`: operator intent, already clamped.
        let intent = crate::types::SwitchIntent::from_operator_soft(soft);
        let scope = self.inner.load_balancing.routing_scope;
        let (cur_tcp, cur_udp) = {
            let active = self.inner.active_uplinks.read().await;
            (active.tcp, active.udp)
        };
        let tcp_gate = strict_gate_transport(scope, TransportKind::Tcp);
        let udp_gate = strict_gate_transport(scope, TransportKind::Udp);
        // Under `reselect_sync` "already correct" and "nothing eligible" both
        // collapse to `None` here, so a fully-converged per-uplink group
        // reports `NoCandidate` where the global scope reports `Skipped`. Both
        // are no-ops, and the fleet shape this flag targets is global scope.
        let sync = self.inner.load_balancing.reselect_sync;
        let tcp_target = if sync {
            self.sync_target(tcp_gate, scope).filter(|&t| cur_tcp != Some(t))
        } else {
            self.draw_reselect_candidate(tcp_gate, scope, cur_tcp, rng)
        };
        let udp_target = if sync {
            self.sync_target(udp_gate, scope).filter(|&t| cur_udp != Some(t))
        } else {
            self.draw_reselect_candidate(udp_gate, scope, cur_udp, rng)
        };

        if tcp_target.is_none() && udp_target.is_none() {
            return ReselectOutcome::NoCandidate;
        }

        let mut reported_from: Option<String> = None;
        let mut reported_to: Option<String> = None;

        if let Some(target) = tcp_target {
            let from = cur_tcp.map(|i| self.inner.uplinks[i].name.clone());
            let to = self.inner.uplinks[target].name.clone();
            self.set_active_uplink_index_for_transport(TransportKind::Tcp, target, reason, intent)
                .await;
            let key = strict_route_key(TransportKind::Tcp, scope);
            self.store_sticky_route(&key, target).await;
            info!(
                group = %self.inner.group_name,
                transport = "tcp",
                from = ?from,
                to = %to,
                soft,
                reason,
                "weighted re-selection moved the strict active uplink (per-uplink, tcp)",
            );
            reported_from = from;
            reported_to = Some(to);
        }

        if let Some(target) = udp_target {
            let from = cur_udp.map(|i| self.inner.uplinks[i].name.clone());
            let to = self.inner.uplinks[target].name.clone();
            self.set_active_uplink_index_for_transport(TransportKind::Udp, target, reason, intent)
                .await;
            let key = strict_route_key(TransportKind::Udp, scope);
            self.store_sticky_route(&key, target).await;
            info!(
                group = %self.inner.group_name,
                transport = "udp",
                from = ?from,
                to = %to,
                soft,
                reason,
                "weighted re-selection moved the strict active uplink (per-uplink, udp)",
            );
            if reported_to.is_none() {
                reported_from = from;
                reported_to = Some(to);
            }
        }

        ReselectOutcome::Switched {
            from: reported_from,
            to: reported_to.expect("at least one transport moved: checked above"),
            soft,
        }
    }
}

#[cfg(test)]
#[path = "tests/reselect.rs"]
mod tests;
