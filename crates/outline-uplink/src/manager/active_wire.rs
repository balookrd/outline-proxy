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

use rand::Rng;
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

use super::standby::resume_cache_key;
use crate::penalty::{add_penalty, weighted_permutation_with_rng, weighted_pick_with_rng};
use crate::types::{TransportKind, UplinkManager};

impl UplinkManager {
    /// Drain the warm-standby deque for `(uplink_index, transport)`.
    ///
    /// The pool holds sockets dialed against whichever wire it was prewarming
    /// (`StandbyCtx::wire`, which follows `active_wire` once `tun_wire_dial`
    /// is on). When the active wire moves, those sockets belong to the wire
    /// that was just abandoned for failing. Holding them until the next probe
    /// cycle's `validate` peek would either dispatch a stale socket to a
    /// session that lands back on the old wire or keep an FD alive
    /// needlessly. Drain on transition is the cleanup.
    ///
    /// It is not the only line of defence, and deliberately so: the pool
    /// carries its wire structurally, so `try_take_alive` refuses (and drains)
    /// a pool filled on a wire it no longer serves even if this call never
    /// ran. This one just makes the FDs go away at the moment of the
    /// transition rather than at the next take.
    pub async fn drain_standby_pool(&self, uplink_index: usize, transport: TransportKind) {
        let pool = match self.inner.standby_pools.get(uplink_index) {
            Some(p) => p,
            None => return,
        };
        let drained = pool.wire_pool(transport).lock().await.clear();
        if drained == 0 {
            return;
        }
        debug!(
            uplink_index,
            transport = ?transport,
            drained,
            "drained warm-standby pool on active-wire transition",
        );
    }
}

impl UplinkManager {
    /// Public-facing handle for the cross-transport resume-cache key used by
    /// the dial paths to look up / store an `X-Outline-Resume` token. The
    /// key is identity-level (parent uplink name + transport label, no wire
    /// disambiguation) so primary and fallback dials of the same uplink
    /// share the same upstream session token — enabling handover-via-resume
    /// when the dial loop switches wires mid-flight.
    ///
    /// `transport_label` must be one of `"tcp"` / `"udp"`.
    pub fn resume_cache_key_for(&self, uplink_name: &str, transport_label: &str) -> String {
        resume_cache_key(self.resume_scope(uplink_name), transport_label)
    }

    /// The resume-cache scope for `uplink_name`: the group name when this group
    /// shares one resume id across its uplinks (`shared_resume`, set when the
    /// uplinks are edges of one server-side mesh `[cluster]`), else the uplink's
    /// own name (the standalone per-uplink default). Sharing the scope makes the
    /// client present the same `X-Outline-Resume` id to whichever edge it dials,
    /// so the session survives an edge switch via the mesh relay.
    ///
    /// Scope is **transport-independent**: both TCP and UDP share the group scope
    /// under `shared_resume`. A group-shared resume id carries a fixed home shard,
    /// so when the rotating UDP wire lands on a non-home edge the server relays
    /// the datagram carrier to the home over the mesh — the intended cross-node
    /// path. The per-session NAT scope on the home (each resumable SS-UDP session
    /// keys its own NAT entry, carried across park/resume) keeps two concurrent
    /// carriers from sharing one response slot, so the relay leg is healthy for
    /// migration. The `#tcp` / `#udp` suffix in the cache key still separates the
    /// two transports' Session IDs within one scope (see `resume_cache_key`).
    pub(crate) fn resume_scope<'a>(&'a self, uplink_name: &'a str) -> &'a str {
        if self.inner.load_balancing.shared_resume {
            &self.inner.group_name
        } else {
            uplink_name
        }
    }

    /// Owned form of [`resume_scope`](Self::resume_scope) for out-of-crate
    /// callers. The VLESS-UDP mux keys its durable per-target resume ids by
    /// `<scope>#<target>`, so it needs the bare scope (no transport suffix)
    /// captured as an owned string that outlives the manager borrow.
    pub fn resume_scope_owned(&self, uplink_name: &str) -> String {
        self.resume_scope(uplink_name).to_string()
    }

    /// Read the currently-active wire index for `uplink_index` on `transport`.
    /// Performs an inline pin-expiry check: if the auto-failback pin has
    /// expired, the pin is cleared so the state machine is free to advance
    /// again on the next failure — but the active wire itself is **not**
    /// forced back to primary. Auto-failback to primary is probe-driven
    /// (the early-failback block in `record_transport_success` snaps active
    /// back to 0 once `min_failures` consecutive primary probes succeed),
    /// not timer-driven, so an active fallback wire that is actually
    /// delivering traffic stays in place until probe confirms primary
    /// recovery. The previous timer-driven snap forced a periodic `0 → 1
    /// → 2 → 0` cycle through known-broken wires whenever primary
    /// remained dead, walking real user-flows back through every failed
    /// wire each pin window — fixed here.
    ///
    /// Always `0` for uplinks declared without `[[outline.uplinks.fallbacks]]`.
    pub fn active_wire(&self, uplink_index: usize, transport: TransportKind) -> u8 {
        let now = Instant::now();
        self.inner.with_status_mut(uplink_index, |status| {
            let st = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            if let Some(until) = st.active_wire_pinned_until
                && until <= now
            {
                st.active_wire_pinned_until = None;
                st.active_wire_streak = 0;
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
        if self.inner.load_balancing.health_weighted_selection {
            // Weighted dial order: rank wires by liveness weight (healthier
            // wires statistically first) while still returning a *complete*
            // permutation, so the fallback cascade still reaches every wire in
            // the same session. Liveness weighting orders the tail; the head
            // is pinned to `active_wire` below, unless that wire is itself
            // the one being weighted down.
            let floor = self.inner.load_balancing.health_weight_floor;
            let now = Instant::now();
            let weights: Vec<f64> = self.inner.with_status_mut(uplink_index, |status| {
                let st = match transport {
                    TransportKind::Tcp => &status.tcp,
                    TransportKind::Udp => &status.udp,
                };
                (0..total_wires as u8)
                    .map(|w| st.wire_weight(w, now, &self.inner.load_balancing, floor))
                    .collect()
            });
            let mut rng = rand::rng();
            let mut order: Vec<u8> = weighted_permutation_with_rng(&weights, &mut rng)
                .into_iter()
                .map(|i| i as u8)
                .collect();
            // The warm pool is prewarmed on the active wire (see
            // `standby_ctx`), so dialing anything else first throws that
            // prewarm away and pays a fresh dial per flow. Liveness weighting
            // still orders the rest of the chain — this only pins the head,
            // which is what makes `active_wire` mean "the wire new sessions
            // land on" rather than a number nothing consults.
            //
            // The pin yields when the active wire itself carries a liveness
            // penalty: `wire_weight` (read from the same `weights` computed
            // above, so no second pass over the penalty state) is `1.0`
            // exactly only when the wire has no *currently effective*
            // penalty — `penalty_weight`'s `1.0 / (1.0 + penalty / scale)`
            // is strictly less than `1.0` for any positive penalty, and its
            // ceiling is `1.0`. A penalised active wire is precisely the
            // case liveness weighting exists to keep new sessions off of, so
            // forcing it to the front unconditionally would defeat that —
            // leave the weighted order's own placement stand instead.
            let active = self.active_wire(uplink_index, transport);
            let active_unpenalised = weights.get(active as usize).is_some_and(|&w| w >= 1.0);
            if active_unpenalised && let Some(pos) = order.iter().position(|&w| w == active) {
                order[..=pos].rotate_right(1);
            }
            // A `position` miss (active wire not found in `order`) covers a
            // stale active wire past the end of the chain (e.g. a config
            // reload that shrank the fallback count) — same defensive
            // posture as the non-weighted branch's cap below: leave the
            // weighted order untouched rather than panic or drop a wire.
            debug_assert_eq!(order.len(), total_wires);
            debug_assert!(order.iter().all(|&i| (i as usize) < total_wires));
            return order;
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
        let failure_cooldown = self.inner.load_balancing.failure_cooldown;
        // Cloned for the per-wire liveness penalty fed below (the closure cannot
        // borrow `self.inner` while it holds the status lock). Mirrors the same
        // clone in `report_runtime_failure_inner`.
        let load_balancing = self.inner.load_balancing.clone();
        let now = Instant::now();
        let group_name = self.inner.group_name.clone();
        let uplink_name = self.inner.uplinks[uplink_index].name.clone();
        let total = total_wires as u8;
        let total_u32 = total_wires as u32;
        // Only the shuffle_wires mode interprets a full round-trip of
        // active_wire advancements as "every wire is dead" and surrenders
        // to uplink-failover. Legacy chains keep wrapping forever; the
        // operator-ordered primary is special-cased on wrap-back-to-zero
        // by the existing pin reset above and unrelated to this counter.
        let shuffle_wires = self.inner.uplinks[uplink_index].shuffle_wires;

        // We collect the transition signal inside the sync `with_status_mut`
        // closure and act on it (spawn the async pool drain) after the
        // status lock is released — async work can't happen inside the
        // sync closure.
        let mut transition_away_from_primary = false;
        let mut chain_exhausted = false;

        self.inner.with_status_mut(uplink_index, |status| {
            let st = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            #[cfg(any(test, feature = "test-helpers"))]
            {
                *st.wire_outcome_calls.entry(attempted_wire).or_insert(0) += 1;
            }
            if success {
                // A successful *dial* only proves the transport handshake
                // completed — NOT that data is flowing. A degraded server can
                // accept the WS upgrade and immediately close the data path
                // (e.g. `Close 1013`), so treating a bare handshake as liveness
                // lets a handshake-alive / data-dead uplink reset the round
                // counter and re-stamp liveness on every reconnect and thus keep
                // the strict-global active slot forever (no health flip ever
                // fires). A dial success therefore only advances the
                // wire-rotation streak (the wire did dial); the any-wire
                // liveness stamp and the shuffle round-counter reset are
                // reserved for *proven* delivery — a fallback-wire probe that
                // reached its target, or real traffic — via
                // [`Self::mark_wire_data_proven`] / `report_active_traffic`.
                if attempted_wire == st.active_wire {
                    st.active_wire_streak = 0;
                }
                return;
            }
            // Liveness penalty for weighted wire selection: a failed dial on
            // *any* wire lowers that wire's selection weight. Recorded for
            // non-active wires too — unlike the `active_wire_streak` below,
            // which only tracks the active wire — so the weighted
            // `wire_dial_order` / `rotate_active_wire` see the health of every
            // wire, not just the one new sessions currently land on. The
            // penalty decays via the shared half-life, so a wire that stops
            // failing recovers its weight on its own. No-op effect when
            // `health_weighted_selection` is off (the weight is never read).
            add_penalty(st.wire_penalty_slot_mut(attempted_wire), now, &load_balancing);
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
            // shuffle_wires "vertical carrier cascade" gate: hold off
            // the wire-rotation step while the active wire still has
            // unused ranks in its carrier-downgrade stack (xhttp_h3 →
            // xhttp_h2 → xhttp_h1, ws_h3 → ws_h2 → ws_h1). The
            // failure that brought us here was already routed through
            // `extend_mode_downgrade` upstream, which caps one rank
            // lower; surfacing the wire-advance now would skip the
            // intermediate ranks and jump straight to the next wire.
            // Once the wire's effective mode reaches the floor of its
            // family (h1) — or the family has no descent stack at
            // all, e.g. Shadowsocks direct — the gate releases and
            // the rotation step fires like the legacy chain.
            //
            // Streak is reset here too: the next batch of failures on
            // the new (capped) carrier starts a fresh per-wire budget
            // before being held up against the gate again.
            if shuffle_wires
                && !super::mode_downgrade::wire_is_at_carrier_floor(
                    &self.inner.uplinks[uplink_index],
                    st,
                    transport,
                    attempted_wire,
                )
            {
                st.active_wire_streak = 0;
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
            transition_away_from_primary = previous == 0 && next != 0;
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
            // shuffle_wires accounting: fresh wire = fresh failure budget
            // for downstream gates (probe-driven healthy flip in
            // `record_transport_failure`, runtime-driven flip in
            // `report_runtime_failure_inner`). Resetting these here keeps
            // the per-wire semantics consistent with the probe-driven
            // advance in `advance_active_wire_on_probe_failure`.
            if shuffle_wires {
                st.consecutive_failures = 0;
                st.consecutive_runtime_failures = 0;
                st.wires_failed_in_round = st.wires_failed_in_round.saturating_add(1);
                if st.wires_failed_in_round >= total_u32 {
                    // Chain exhausted: every wire has been the active wire
                    // of a failed round since the last success. Force the
                    // uplink-level health flip and cooldown right here so
                    // the load balancer drops us from candidates on its
                    // next pass — no recursive `report_runtime_failure`
                    // hop required.
                    chain_exhausted = true;
                    st.wires_failed_in_round = 0;
                    st.healthy = Some(false);
                    st.cooldown_until = Some(now + failure_cooldown);
                }
            }
        });

        // Drain the warm-standby pool when active just moved off primary —
        // see `drain_standby_pool` for the rationale. Spawned because we
        // cannot `.await` inside the sync `with_status_mut` closure above;
        // ordering with subsequent dials is fine because a stale socket
        // arriving before the drain completes still gets liveness-peeked
        // by the standby validate path before being handed out.
        if transition_away_from_primary && tokio::runtime::Handle::try_current().is_ok() {
            // `try_current` guards the unit-test path: those tests call
            // `record_wire_outcome` synchronously from a `#[test]` (no
            // tokio runtime), and `tokio::spawn` would panic. The drain
            // is best-effort cleanup anyway — production callers always
            // run inside the tokio runtime, so the guard short-circuits
            // only in tests.
            let manager = self.clone();
            tokio::spawn(async move {
                manager.drain_standby_pool(uplink_index, transport).await;
            });
        }

        // Round exhausted: every wire of the chain has been advanced
        // through without an intervening success on this transport.
        // The healthy flip + cooldown are applied inside the lock above,
        // so out here we only emit the operator-facing log + metric. A
        // later wire success or probe success resets the round counter
        // via `record_wire_outcome(success=true)` /
        // `record_transport_success`; probe recovery clears the cooldown
        // and re-flips `healthy = Some(true)` through the existing
        // health-recovery paths.
        if chain_exhausted {
            warn!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?transport,
                total_wires,
                "shuffle_wires round exhausted: every wire failed since last success, surrendering to uplink-failover",
            );
            let kind = match transport {
                TransportKind::Tcp => "tcp_shuffle_round_exhausted",
                TransportKind::Udp => "udp_shuffle_round_exhausted",
            };
            outline_metrics::record_failover(kind, &group_name, &uplink_name, &uplink_name);
        }
    }

    /// Record that data was *actually delivered* over `uplink_index` on
    /// `transport` — a fallback-wire probe that reached its external target, or
    /// real client traffic. Unlike a bare dial handshake
    /// ([`Self::record_wire_outcome`] with `success = true`), this is genuine
    /// end-to-end proof the uplink is alive, so it stamps the any-wire liveness
    /// timestamp consulted by `selection_health` /
    /// `should_skip_primary_probe_escalation` and resets the `shuffle_wires`
    /// round counter (traffic has stabilised). Keeping the liveness signal
    /// distinct from the handshake signal is what stops a handshake-alive /
    /// data-dead server (one that completes the WS upgrade then closes with
    /// 1013) from holding the strict-global active slot forever.
    pub fn mark_wire_data_proven(&self, uplink_index: usize, transport: TransportKind) {
        let now = Instant::now();
        self.inner.with_status_mut(uplink_index, |status| {
            let st = match transport {
                TransportKind::Tcp => &mut status.tcp,
                TransportKind::Udp => &mut status.udp,
            };
            st.last_any_wire_success = Some(now);
            st.active_wire_streak = 0;
            st.wires_failed_in_round = 0;
            // Proven end-to-end delivery clears the active wire's liveness
            // penalty outright (not just decay): real traffic is stronger
            // evidence of health than a bare dial handshake, so the wire
            // immediately regains full selection weight for the weighted
            // `wire_dial_order` / `rotate_active_wire`.
            let active = st.active_wire;
            let slot = st.wire_penalty_slot_mut(active);
            slot.value_secs = 0.0;
            slot.updated_at = None;
        });
    }

    /// Reroll the active wire on both transports for `uplink_index`,
    /// independently. Powers the `shuffle_timer` scheduler: a periodic task
    /// fires this on each tick so an uplink that has been serving traffic on
    /// the same wire for hours pivots to a different carrier shape on
    /// schedule (defence against time-based DPI heuristics).
    ///
    /// **The draw always excludes the wire currently active** on that
    /// transport — fleet observation showed a naive draw over every wire
    /// (including the active one) frequently "rerolled" onto the same wire
    /// it started on, defeating the whole point of the rotation. Candidates
    /// are every *other* wire whose [`super::status::PerTransportStatus::wire_weight`]
    /// is strictly above `health_weight_floor`, i.e. has not been pushed all
    /// the way down by an accumulated liveness penalty — see
    /// [`draw_reroll_wire`], which mirrors `draw_reselect_candidate`'s
    /// exclude + eligibility-filter shape one level down (wires within one
    /// uplink's chain, rather than uplinks within a group). This exclude +
    /// floor filter is identical whether `health_weighted_selection` is on
    /// (the draw among candidates is then biased toward the healthier ones)
    /// or off (the draw among candidates is uniform, restoring the legacy
    /// flat distribution) — whether "a reroll changes the wire" must not
    /// depend on that flag.
    ///
    /// **When a transport has no live alternative** (every non-active wire
    /// is at the floor), that transport's active wire is left **completely
    /// untouched**: no pin refresh, no failure-accounting reset — `apply`
    /// below simply does not run for that transport. TCP and UDP draw
    /// independently, so one plane having no live alternative never blocks
    /// the other from rerolling.
    ///
    /// When a reroll *does* land on a new wire, whether the per-wire failure
    /// budgets (`active_wire_streak`, `wires_failed_in_round`,
    /// `consecutive_failures`, `consecutive_runtime_failures`) reset to give
    /// it a clean budget depends on `recently_proven` below — see that
    /// comment for why a fully dead `shuffle_wires` uplink must keep its
    /// accounting instead. The mode-downgrade cap (if any) is cleared on the
    /// same condition, because the new wire's carrier stack is independent
    /// of the old wire's; a stale cap installed for a previous wire would
    /// otherwise persist across the pivot and skew the dial-time mode for
    /// the freshly-chosen wire.
    ///
    /// No-op for uplinks without any fallbacks (the chain is a
    /// singleton; nothing to reroll to).
    ///
    /// Per transport, the weight computation, the draw, and (when it finds a
    /// live alternative) the apply all happen under one acquisition of the
    /// status lock — see the comment at the call site — so "a reroll always
    /// changes the wire, or leaves it provably untouched" holds even against
    /// a concurrent probe/dial success advancing `active_wire` mid-call.
    ///
    /// The operator-facing WARN for "no live alternative" fires only on the
    /// tick that newly finds the condition; it stays at DEBUG for as long as
    /// the condition persists (see [`super::status::PerTransportStatus::reroll_no_live_alt`]).
    ///
    /// Returns the `(tcp_wire, udp_wire)` pair the uplink ends this call
    /// on — the freshly-rolled wire for a transport that had a live
    /// alternative, or the unchanged previous wire for one that did not —
    /// or `None` for the no-fallback case.
    pub fn rotate_active_wire(&self, uplink_index: usize) -> Option<(u8, u8)> {
        let uplink = &self.inner.uplinks[uplink_index];
        let total_wires = 1 + uplink.fallbacks.len();
        if total_wires <= 1 {
            return None;
        }
        let total = total_wires as u8;
        let floor = self.inner.load_balancing.health_weight_floor;
        let now = Instant::now();
        let weighted = self.inner.load_balancing.health_weighted_selection;
        let pin_window = self.inner.load_balancing.mode_downgrade_duration;
        let runtime_failure_window = self.inner.load_balancing.runtime_failure_window;
        let mut rng = rand::rng();

        // Draw *and* apply happen inside one lock acquisition (one call to
        // `with_status_mut`) rather than the previous read-lock-draw /
        // release / re-lock-apply shape. `draw_reroll_wire` is synchronous
        // and cheap (weight computation + one RNG draw over at most a
        // handful of wires), so there is no reason to release the lock
        // between the draw and the apply — and doing so opened a window: a
        // concurrent probe or dial success advancing `status.tcp.active_wire`
        // (or `.udp`) between the two acquisitions would let this call apply
        // the wire that had *just* become active, silently breaking "a
        // reroll always changes the wire" for that tick. Computing weights,
        // drawing, and applying under a single guard removes the window
        // (and the extra lock round-trip).
        let (
            (tcp_active, tcp_pick, tcp_became_stuck, tcp_still_stuck),
            (udp_active, udp_pick, udp_became_stuck, udp_still_stuck),
        ) = self.inner.with_status_mut(uplink_index, |status| {
            let apply = |st: &mut super::status::PerTransportStatus, new_wire: u8| {
                // The anti-DPI reroll always changes which wire new sessions
                // start on. Whether it ALSO clears the failure-accounting
                // depends on whether the uplink is currently proving delivery.
                //
                // Recently-proven (some wire delivered within
                // `runtime_failure_window`): the uplink is alive and we are
                // merely rotating its active wire, so give the freshly-rolled
                // wire a clean failure budget — the rotation itself must not be
                // counted against it.
                //
                // NOT proven (no wire delivered within the window — a dying or
                // dead uplink): KEEP the accumulated failure-accounting.
                // Zeroing it on every shuffle_timer tick is what let a
                // fully-dead `shuffle_wires` uplink dodge chain-exhaustion
                // forever: `wires_failed_in_round` reset to 0 before the
                // carrier cascade could exhaust it, so `healthy` never flipped
                // to `Some(false)`, no cooldown engaged, and the uplink stayed
                // a green "Ready" row on the dashboard AND an eligible failover
                // candidate (`fallback_bootstrap_allowed`). Preserving the
                // counters lets the cascade reach chain-exhaustion across
                // reroll ticks and finally flip the uplink unhealthy. The
                // active-wire change (the actual anti-DPI effect) still happens.
                let recently_proven = !runtime_failure_window.is_zero()
                    && st
                        .last_any_wire_success
                        .is_some_and(|t| now.saturating_duration_since(t) < runtime_failure_window);
                st.active_wire = new_wire;
                if recently_proven {
                    st.active_wire_streak = 0;
                    st.wires_failed_in_round = 0;
                    st.consecutive_failures = 0;
                    st.consecutive_runtime_failures = 0;
                    st.chunk0_consecutive_failures = 0;
                    // Wipe any in-flight mode-downgrade cap left over from the
                    // previous wire — a healthy uplink's new wire starts its
                    // carrier stack fresh at the configured rank. Both slot
                    // kinds are cleared: primary's descent and every fallback
                    // wire's own slot. Leaving the latter behind would let a
                    // cap earned by a wire we are rotating *away* from decide
                    // the dial mode of the wire we are rotating *onto* the
                    // next time the reroll lands there — and, because walk-up
                    // and the recovery probe are primary-only, that stale cap
                    // could otherwise outlive the condition that installed it.
                    st.descent.reset_window_for_wire_change();
                    st.fallback_mode_downgrades.clear();
                }
                // Pin the freshly-rolled wire for the standard mode-downgrade
                // duration window, except when we happen to roll back to
                // primary — primary is never pinned (matches the dial-path /
                // probe-path advance semantics).
                st.active_wire_pinned_until =
                    if new_wire == 0 { None } else { Some(now + pin_window) };
            };
            // Compute weights, draw, and (if the draw found a live
            // alternative) apply — all under the same `st` borrow, for one
            // transport. Also updates `st.reroll_no_live_alt` and reports
            // the `false -> true` / `true -> true` edges so the caller can
            // throttle the operator-facing log to "once per new occurrence"
            // instead of once per tick.
            let mut roll =
                |st: &mut super::status::PerTransportStatus| -> (u8, Option<u8>, bool, bool) {
                    let weights: Vec<f64> = (0..total)
                        .map(|w| st.wire_weight(w, now, &self.inner.load_balancing, floor))
                        .collect();
                    let active = st.active_wire;
                    let pick = draw_reroll_wire(&weights, active, floor, weighted, &mut rng);
                    let was_stuck = st.reroll_no_live_alt;
                    let stuck_now = pick.is_none();
                    st.reroll_no_live_alt = stuck_now;
                    if let Some(new_wire) = pick {
                        apply(st, new_wire);
                    }
                    (active, pick, stuck_now && !was_stuck, stuck_now && was_stuck)
                };
            (roll(&mut status.tcp), roll(&mut status.udp))
        });

        let group_name = self.inner.group_name.clone();
        let uplink_name = uplink.name.clone();
        // Report the wire each transport actually ends this call on: the
        // freshly-rolled one when the draw found a live alternative, else
        // the unchanged previous active wire. `*_changed` keeps the log
        // truthful about which case happened — a plain `tcp_wire` field
        // alone cannot distinguish "rerolled back onto the wire it started
        // at" (impossible now, since the draw excludes it) from "left
        // untouched because nothing else qualified".
        let tcp_wire = tcp_pick.unwrap_or(tcp_active);
        let udp_wire = udp_pick.unwrap_or(udp_active);
        info!(
            group = %group_name,
            uplink = %uplink_name,
            tcp_wire,
            tcp_changed = tcp_pick.is_some(),
            udp_wire,
            udp_changed = udp_pick.is_some(),
            total_wires,
            "shuffle_timer reroll: active wire randomized per transport where a live alternative existed",
        );
        // WARN only on the tick that *newly* finds no live alternative — a
        // two-wire uplink whose only alternative sits at the floor would
        // otherwise repeat this outcome every tick (at `shuffle_timer =
        // "30s"`, ~5800 lines/day/uplink for a condition that by definition
        // keeps recurring until something changes). Once the condition is
        // already flagged, later ticks that are still stuck log at DEBUG
        // instead — the state is fully captured by `reroll_no_live_alt` on
        // the dashboard / snapshot for anyone who wants "is it stuck right
        // now" without the WARN noise.
        if tcp_became_stuck {
            warn!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?TransportKind::Tcp,
                active_wire = tcp_active,
                total_wires,
                "shuffle_timer reroll: no live TCP alternative (every other wire at health_weight_floor) — active wire left unchanged",
            );
        } else if tcp_still_stuck {
            debug!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?TransportKind::Tcp,
                active_wire = tcp_active,
                total_wires,
                "shuffle_timer reroll: still no live TCP alternative — active wire left unchanged",
            );
        }
        if udp_became_stuck {
            warn!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?TransportKind::Udp,
                active_wire = udp_active,
                total_wires,
                "shuffle_timer reroll: no live UDP alternative (every other wire at health_weight_floor) — active wire left unchanged",
            );
        } else if udp_still_stuck {
            debug!(
                group = %group_name,
                uplink = %uplink_name,
                transport = ?TransportKind::Udp,
                active_wire = udp_active,
                total_wires,
                "shuffle_timer reroll: still no live UDP alternative — active wire left unchanged",
            );
        }
        if tcp_pick.is_some() {
            outline_metrics::record_failover(
                "tcp_shuffle_timer",
                &group_name,
                &uplink_name,
                &uplink_name,
            );
        }
        if udp_pick.is_some() {
            outline_metrics::record_failover(
                "udp_shuffle_timer",
                &group_name,
                &uplink_name,
                &uplink_name,
            );
        }
        Some((tcp_wire, udp_wire))
    }

    /// Spawn one background tokio task per uplink that has
    /// `shuffle_timer = Some(_)` configured. Each task wakes up every
    /// `shuffle_timer` interval and calls [`Self::rotate_active_wire`].
    /// Uplinks without a configured interval, or with no fallbacks
    /// (where rotation is a no-op anyway), are skipped — no idle
    /// task is created for them.
    ///
    /// The tasks honour the manager's shutdown channel and exit
    /// promptly on graceful shutdown.
    pub fn spawn_shuffle_timer_loops(&self) {
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            let Some(interval) = uplink.shuffle_timer else { continue };
            if uplink.fallbacks.is_empty() {
                debug!(
                    uplink = %uplink.name,
                    "shuffle_timer set but uplink has no fallbacks — no rotation task spawned"
                );
                continue;
            }
            let manager = self.clone();
            let mut shutdown = self.shutdown_rx();
            let uplink_name = uplink.name.clone();
            let group_name = self.inner.group_name.clone();
            info!(
                group = %group_name,
                uplink = %uplink_name,
                interval_secs = interval.as_secs(),
                "shuffle_timer rotation loop spawned",
            );
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        _ = sleep(interval) => {}
                    }
                    manager.rotate_active_wire(index);
                }
            });
        }
    }
}

/// Draw one wire index for [`UplinkManager::rotate_active_wire`]'s anti-DPI
/// reroll on a single transport.
///
/// Candidates are every index in `weights` **except `active`** whose weight
/// is strictly above `floor` — a wire whose accumulated liveness penalty has
/// pushed it down to the floor (see
/// [`super::status::PerTransportStatus::wire_weight`]) is not a "live
/// alternative" and is excluded exactly like the active wire itself. Mirrors
/// `draw_reselect_candidate`'s (`manager/reselect.rs`) exclude +
/// eligibility-filter shape one level down: wires within a single uplink's
/// fallback chain, rather than uplinks within a group.
///
/// `weighted = true` draws proportionally to each candidate's own weight
/// (the `health_weighted_selection` bias toward the healthier wires);
/// `weighted = false` draws uniformly among the same candidate set (the
/// legacy flat distribution, restored by `health_weighted_selection =
/// false`). The exclude-current + floor filter is identical either way, so
/// whether a reroll changes the wire never depends on that flag.
///
/// Returns `None` when no wire qualifies: the caller must leave that
/// transport's active wire completely untouched rather than re-apply the
/// wire it already had.
///
/// `floor >= 1.0` is a degenerate but validator-accepted edge of the
/// configured range: `penalty_weight`'s `.max(floor)` clamps *every* wire's
/// weight to exactly `1.0` in that case, so the plain `w > floor` test below
/// could never be true for any wire — every tick would find zero candidates
/// and the reroll would go permanently silent, with no config error to
/// explain why. Since the floor carries no discriminating information at
/// `1.0` anyway (every wire looks equally healthy to it), treat that case as
/// "every non-active wire is a candidate" instead, so the anti-DPI rotation
/// keeps working — merely without the liveness bias `health_weight_floor`
/// would otherwise have provided.
fn draw_reroll_wire<R: Rng + ?Sized>(
    weights: &[f64],
    active: u8,
    floor: f64,
    weighted: bool,
    rng: &mut R,
) -> Option<u8> {
    let floor_discriminates = floor < 1.0;
    let candidates: Vec<u8> = weights
        .iter()
        .enumerate()
        .filter(|&(idx, &w)| idx as u8 != active && (!floor_discriminates || w > floor))
        .map(|(idx, _)| idx as u8)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if weighted {
        let candidate_weights: Vec<f64> = candidates.iter().map(|&w| weights[w as usize]).collect();
        weighted_pick_with_rng(&candidate_weights, rng).map(|pos| candidates[pos])
    } else {
        Some(candidates[rng.random_range(0..candidates.len())])
    }
}

#[cfg(test)]
#[path = "tests/active_wire.rs"]
mod tests;
