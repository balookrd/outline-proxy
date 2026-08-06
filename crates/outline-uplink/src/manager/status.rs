//! Per-uplink, per-transport runtime status: probe health, RTT, cooldowns,
//! penalty, mode-downgrade window, and runtime-failure counters.

use std::time::Duration;

use tokio::time::Instant;

use crate::selection::{StatusView, TransportStatusView};
use crate::types::TransportKind;

use super::carrier_descent_state::CarrierDescentState;

#[cfg(test)]
#[path = "tests/status.rs"]
mod tests;

/// All per-transport runtime state for a single uplink.
///
/// [`UplinkStatus`] holds one instance for TCP and one for UDP, eliminating
/// the previous flat `tcp_*/udp_*` field pairs and the accompanying
/// `match transport { Tcp => self.tcp_x, Udp => self.udp_x }` repetition.
/// Use [`UplinkStatus::of`] to select the right half by a [`TransportKind`] variable.
#[derive(Clone, Debug, Default)]
pub(crate) struct PerTransportStatus {
    pub(crate) healthy: Option<bool>,
    pub(crate) latency: Option<Duration>,
    pub(crate) rtt_ewma: Option<Duration>,
    pub(crate) penalty: PenaltyState,
    pub(crate) cooldown_until: Option<Instant>,
    pub(crate) consecutive_failures: u32,
    pub(crate) consecutive_successes: u32,
    /// Consecutive data-plane (runtime) failures observed by the dispatch
    /// path on this transport. Separate from `consecutive_failures`, which
    /// counts probe outcomes — runtime failures are noisier and should not
    /// share a counter with the authoritative probe signal. Used in strict
    /// global + probe-enabled mode to flip `healthy = Some(false)` after
    /// `probe.min_failures` consecutive runtime failures, without waiting
    /// for the next probe cycle.
    pub(crate) consecutive_runtime_failures: u32,
    /// Timestamp of the previous runtime failure on this transport.
    /// Used to time-decay [`Self::consecutive_runtime_failures`]: when a new
    /// runtime failure arrives more than
    /// [`LoadBalancingConfig::runtime_failure_window`] after this timestamp,
    /// the counter is reset to 1 (start of a fresh streak) instead of
    /// incrementing. Without decay, sparse transient errors on a low-traffic
    /// uplink stack indefinitely (the counter only resets on a successful
    /// data transfer or a successful probe), causing eventual spurious
    /// `healthy = Some(false)` flips and active-uplink flapping.
    pub(crate) last_runtime_failure_at: Option<Instant>,
    /// Consecutive chunk-0 timeouts observed by the dispatch path on this
    /// transport. Tracked separately from [`Self::consecutive_runtime_failures`]
    /// because chunk-0 timeouts are a strong upstream-down signal — the
    /// connection handshake succeeded but the upstream produced zero
    /// response bytes within the deadline, which uniquely indicates a
    /// silent server / network condition that the probe (handshake-only)
    /// cannot see. The streak is decayed by
    /// [`LoadBalancingConfig::chunk0_failure_window`], typically much wider
    /// than `runtime_failure_window`, so chunk-0 timeouts that are too
    /// sparse to escalate via the generic counter still accumulate here
    /// and trigger an active-uplink switch via
    /// `runtime_health_escalation` after `probe.min_failures` of them.
    pub(crate) chunk0_consecutive_failures: u32,
    /// Timestamp of the previous chunk-0 timeout on this transport.
    /// Used to decay [`Self::chunk0_consecutive_failures`]: a new chunk-0
    /// timeout arriving more than
    /// [`LoadBalancingConfig::chunk0_failure_window`] after this timestamp
    /// resets the streak to 1 instead of incrementing.
    pub(crate) last_chunk0_failure_at: Option<Instant>,
    /// The carrier-descent slot for the primary wire: the downgrade
    /// window (deadline + family-aware cap), the recovery-probe
    /// cooldown, the post-recovery grace budget and the recovery
    /// success streak, with every transition encapsulated as a method.
    /// See [`CarrierDescentState`] for the per-field semantics and
    /// [`super::mode_downgrade`] for the driver that feeds it.
    pub(crate) descent: CarrierDescentState,
    /// Per-fallback-wire mode-downgrade slots. Indexed by `wire_index - 1`
    /// (i.e. `[0]` corresponds to `fallbacks[0]`); the primary wire's
    /// downgrade lives in the existing `mode_downgrade_until` /
    /// `mode_downgrade_capped_to` fields above. Lazily extended on first
    /// write — empty for uplinks without fallbacks. Reads of an out-of-
    /// range slot return `(None, None)` (no active downgrade).
    ///
    /// Without these slots, every observation of a downgrade on a fallback
    /// wire (XHTTP-H3 → H2, raw-QUIC → WS, etc.) had to be discarded at the
    /// proxy / transport layer to avoid mis-parking the primary's mode —
    /// which kept fallback-only paths from learning their own downgrade
    /// chain. Now each wire gets its own window, and fallback dials can
    /// honour the cap they earned without polluting primary's slot.
    pub(crate) fallback_mode_downgrades: Vec<ModeDowngradeSlot>,
    /// Per-fallback-wire RTT EWMA slots. Indexed by `wire_index - 1`
    /// (`[0]` corresponds to `fallbacks[0]`); the primary wire's EWMA
    /// lives in [`Self::rtt_ewma`] above. Lazily extended on first
    /// write — empty for uplinks without fallbacks; reads of an
    /// out-of-range slot return `None`.
    ///
    /// Without these slots, the EWMA on `PerTransportStatus` reflects
    /// the **primary** wire's latency forever, even after the dial
    /// loop / probe walk has moved `active_wire` to a fallback. The
    /// scoring layer would then keep ranking this uplink against
    /// peers using a stale primary RTT, potentially preferring it (or
    /// avoiding it) for reasons unrelated to the wire actually
    /// carrying traffic. Each fallback wire now has its own slot, fed
    /// by the per-wire probe walk in
    /// [`crate::manager::probe::wire`], so scoring of an uplink whose
    /// `active_wire` is non-zero uses that wire's measured RTT.
    pub(crate) fallback_rtt_ewma: Vec<Option<Duration>>,
    /// Smoothed carrier loss for the primary wire. The live probes it is
    /// derived from live in the manager's registry, not here: they own
    /// duplicated descriptors, and `UplinkStatus` is cloned on every snapshot.
    pub(crate) carrier_loss: crate::loss::LossEwma,
    /// Per-fallback-wire loss slots, indexed by `wire_index - 1` exactly like
    /// [`Self::fallback_rtt_ewma`]. Lazily extended on first write.
    pub(crate) fallback_carrier_loss: Vec<crate::loss::LossEwma>,
    /// Start of this transport's current continuous loss-elevated episode:
    /// the active-wire loss ratio ([`Self::active_wire_loss`]) has been
    /// above `LoadBalancingConfig::loss_failover_ratio` on every sampling
    /// tick since this timestamp, with no clean tick in between. Maintained
    /// by `UplinkManager::sample_carrier_loss_once` via
    /// [`Self::update_loss_elevated_since`] — set on the first tick whose
    /// ratio exceeds the threshold, cleared the instant a tick comes back at
    /// or below it (or the ratio is unmeasured). Same continuous-episode
    /// discipline as [`CarrierDescentState::window_started_at`]: a stream of
    /// re-triggers reads as one episode, but an interrupted one restarts the
    /// clock, so an uplink flapping around the threshold never accumulates
    /// its way into a failover. Read by
    /// `UplinkManager::loss_failover_switch_target` through the
    /// [`TransportSelectionView`] projection below.
    pub(crate) loss_elevated_since: Option<Instant>,
    /// `(wire, when)` of the most recent sampling tick that recorded a
    /// *qualifying* carrier-loss window (met `loss_sample_min_packets`) for
    /// whichever wire was active at that moment. Distinct from "the ratio is
    /// still above the threshold": [`Self::active_wire_loss`]'s ratio is a
    /// frozen EWMA that a sub-volume-threshold window leaves completely
    /// untouched (see [`crate::loss::LossEwma::record_window`]), and carrier
    /// eviction only fires after three consecutive ticks with *zero* traffic
    /// — so a wire idling on light-but-nonzero traffic below the volume
    /// floor (sparse keepalives, an overnight lull) can go a long time
    /// without ever re-measuring. Without this stamp,
    /// [`Self::update_loss_elevated_since`] would keep reading that stale,
    /// no-longer-current ratio as if it were fresh evidence indefinitely,
    /// letting a loss-driven failover fire hours after the measurement that
    /// justified it stopped being observed — and letting a warm-standby
    /// uplink's episode from a previous stint as active survive, unconfirmed,
    /// until it becomes active again.
    ///
    /// The wire is part of the stamp, not just the timestamp, because
    /// [`Self::active_wire`] can change between ticks: without it, a fresh
    /// measurement of the wire the dial loop just moved *off* of would
    /// validate the *new* active wire's completely unrelated (and possibly
    /// still-lossy) ratio for up to `max_staleness` after the flip.
    /// [`Self::update_loss_elevated_since`] only trusts this stamp when its
    /// wire still matches [`Self::active_wire`].
    ///
    /// Maintained by `UplinkManager::sample_carrier_loss_once`; a verdict
    /// older than `3 × loss_sample_interval` (mirroring
    /// [`crate::loss::MAX_IDLE_TICKS`], the same bound the registry itself
    /// uses before evicting an idle carrier probe) is treated as unmeasured.
    pub(crate) loss_last_qualifying_at: Option<(u8, Instant)>,
    /// Per-wire liveness penalty for weighted wire selection, decaying via the
    /// shared `0.5^(t/halflife)` curve (see [`crate::penalty::penalty_weight`]).
    /// Indexed by **wire index directly**: `[0]` is the primary wire, `[i]` is
    /// `fallbacks[i-1]`. Unlike [`Self::fallback_rtt_ewma`] /
    /// [`Self::fallback_mode_downgrades`], which exclude primary, the primary is
    /// included here — otherwise a primary that disconnects often would keep the
    /// top selection weight forever and never yield to a healthier fallback.
    /// Lazily extended on first write; reads of an out-of-range slot are treated
    /// as a default (zero penalty → full weight). Fed by dial / probe failures
    /// in [`super::UplinkManager::record_wire_outcome`] and cleared on proven
    /// delivery in [`super::UplinkManager::mark_wire_data_proven`]; consumed by
    /// the weighted `wire_dial_order` / `rotate_active_wire` when
    /// `health_weighted_selection` is enabled.
    pub(crate) wire_penalty: Vec<PenaltyState>,
    /// Timestamp of the most recent real data transfer on this transport.
    /// Used to skip probe cycles when the uplink is actively carrying traffic.
    pub(crate) last_active: Option<Instant>,
    /// Timestamp of the most recent early probe wakeup caused by a runtime
    /// failure. Rate-limits wakeups to one per `PROBE_WAKEUP_MIN_INTERVAL`.
    pub(crate) last_probe_wakeup: Option<Instant>,
    /// Index into the uplink's `[primary, fallbacks[0], fallbacks[1], ...]`
    /// list of the currently active wire. `0` is primary; `1..=N` selects
    /// `fallbacks[i-1]`. Defaults to `0` for uplinks with no fallbacks
    /// configured (the value is read but never advances). When fallbacks are
    /// declared, the dial loop reads this to start the per-session attempt
    /// chain at the active wire instead of always retrying primary first.
    pub(crate) active_wire: u8,
    /// Auto-failback deadline. When set and in the future, the active wire
    /// stays pinned (a session whose dial fails on the active wire still
    /// advances inside the wire chain, but new sessions keep starting at
    /// `active_wire`). When the deadline passes, [`Self::active_wire`] is
    /// reset to 0 and this field is cleared so the next session retries the
    /// primary wire. Sized to share the existing
    /// `LoadBalancingConfig::mode_downgrade_duration` knob — one timer for
    /// both per-wire mode downgrades and per-uplink active-wire pinning.
    pub(crate) active_wire_pinned_until: Option<Instant>,
    /// Consecutive dial failures on [`Self::active_wire`]. Reset on a
    /// successful dial of the same wire; reset when the active-wire pin
    /// expires. Once this reaches `probe.min_failures` (or the runtime-
    /// failure threshold equivalent), the dial-loop bumps `active_wire` to
    /// the next configured wire and starts a fresh streak there.
    pub(crate) active_wire_streak: u32,
    /// Timestamp of the most recent **any-wire** successful dial on this
    /// transport (primary or any fallback). Used by `selection_health` as a
    /// liveness override: if the probe has marked the parent uplink
    /// unhealthy because the *primary* wire is broken but a fallback wire
    /// has dialed successfully within the runtime-failure window, the
    /// uplink stays in the candidate set so the active-wire dial loop can
    /// keep using the working fallback. Without this, probe health on the
    /// primary would gate the whole uplink out of selection and the
    /// fallback wire never gets a chance.
    ///
    /// Only set on successful dials of an uplink that has at least one
    /// fallback configured — for single-wire uplinks the existing health
    /// gating is unchanged.
    pub(crate) last_any_wire_success: Option<Instant>,
    /// Number of `active_wire` advancements observed since the last
    /// successful wire dial on this transport, used **only** when the
    /// parent uplink has `shuffle_wires = true`. Once the counter
    /// reaches `total_wires`, the active wire has been moved through
    /// every wire of the chain without a single successful dial in
    /// between — the round is exhausted and the caller treats the next
    /// failure as a uplink-level runtime failure so the load balancer
    /// fails over to another uplink. Any successful wire dial (primary
    /// or fallback) resets the counter to `0` so the next failure
    /// starts a fresh round forward from the wire that is currently
    /// working. Stays at `0` for uplinks without `shuffle_wires`.
    pub(crate) wires_failed_in_round: u32,
    /// Cumulative count of server-initiated downstream-throttle signals received
    /// on this transport over the manager's lifetime (a padded carrier's server
    /// asked the client to switch uplinks because the path toward it was being
    /// throttled). Surfaced on the dashboard so an operator can see which uplink
    /// was nudged off by throttling and how often. Monotonic — never decayed.
    pub(crate) downstream_throttle_count: u64,
    /// Timestamp of the most recent downstream-throttle signal on this
    /// transport, used to render a "recently throttled" badge on the dashboard.
    pub(crate) last_downstream_throttle_at: Option<Instant>,
    /// Whether the most recent `shuffle_timer` tick on this transport found
    /// no live alternative (every other wire at `health_weight_floor`) and
    /// left `active_wire` untouched. Exists purely to throttle the
    /// operator-facing log for that condition in
    /// [`super::UplinkManager::rotate_active_wire`]: a two-wire uplink whose
    /// only alternative is floored repeats this outcome on every tick, so a
    /// bare per-tick `warn!` becomes ~5800 lines/day/uplink at a 30s
    /// `shuffle_timer`. `warn!` fires only on the `false -> true` edge (a
    /// fresh "stuck" condition); it keeps logging at `debug!` while the
    /// condition persists, and the flag resets on the tick that finds a live
    /// alternative again.
    pub(crate) reroll_no_live_alt: bool,
    /// Test-only: number of times [`super::UplinkManager::record_wire_outcome`]
    /// has been invoked for each wire, regardless of success or failure.
    /// Exists solely so `dial_over_wires` tests can observe the negative —
    /// that a `WireAttempt::NotApplicable` wire never reaches
    /// `record_wire_outcome` at all — which no other field in this struct
    /// distinguishes from "reached it and happened to leave every field
    /// unchanged". Never read outside tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) wire_outcome_calls: std::collections::HashMap<u8, u32>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UplinkStatus {
    pub(crate) tcp: PerTransportStatus,
    pub(crate) udp: PerTransportStatus,
    pub(crate) last_error: Option<String>,
    /// `notAfter` of the soonest-expiring TLS certificate among this uplink's
    /// endpoints (primary + fallback wires that dial `wss`/`https`), as Unix
    /// milliseconds. Populated by the periodic cert-check loop
    /// (`manager::cert_check`); `None` until the first check completes, when
    /// the uplink has no TLS endpoint (e.g. a plaintext `ws://` uplink), or when the
    /// `cert-check` feature is disabled. A transient check failure leaves the
    /// last known value in place rather than clearing it.
    pub(crate) cert_not_after_unix_ms: Option<u64>,
    pub(crate) last_checked: Option<Instant>,
    /// Consecutive probe cycles in which *every* endpoint of this uplink
    /// failed the bare-TCP reachability check (`[probe] endpoint_check`).
    /// Zeroed the moment any endpoint answers again.
    ///
    /// Uplink-level rather than per-transport on purpose: the check dials a
    /// socket, not a carrier, so its verdict is about the host both planes
    /// share. Once the streak reaches `probe.min_failures` the manager
    /// condemns the uplink outright instead of letting the per-wire descent
    /// rediscover the same fact one timeout at a time — see
    /// [`crate::manager::probe::endpoint`].
    pub(crate) endpoint_unreachable_streak: u32,
    /// Wall-clock timestamp of the most recent probe cycle that actually
    /// ran on this uplink (i.e. NOT a cycle that exited via the
    /// activity-based skip). Used by the liveness-probe override in
    /// `should_skip_probe_cycle_for_recent_activity`: when
    /// `liveness_interval` is set and this stamp is older than the
    /// interval, the cycle runs unconditionally — guarantees a periodic
    /// "pulse" of probe metrics on uplinks that otherwise stay in skip
    /// mode forever because they keep carrying traffic. Distinct from
    /// `last_checked`, which is updated by `process_probe_ok` /
    /// `process_probe_err` *after* the probe completes — by the time a
    /// skipped cycle decides whether to skip, the writer has not run
    /// yet, so we need a separate "last not-skipped" stamp.
    pub(crate) last_full_probe_at: Option<Instant>,
}

impl UplinkStatus {
    /// Borrow the per-transport status for the given transport kind.
    pub(crate) fn of(&self, kind: TransportKind) -> &PerTransportStatus {
        match kind {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }

    /// `Copy` projection of the fields the selection path reads *after* it has
    /// released the status lock — see [`SelectionView`]. `config` supplies the
    /// carrier-loss latency-penalty knobs that fold into `base_latency`, and
    /// `now` is what [`TransportSelectionView::loss_ratio_fresh`] is
    /// evaluated against.
    pub(crate) fn selection_view(
        &self,
        config: &crate::config::LoadBalancingConfig,
        now: Instant,
    ) -> SelectionView {
        SelectionView {
            tcp: self.tcp.selection_view(config, now),
            udp: self.udp.selection_view(config, now),
        }
    }
}

/// The per-transport slice of [`SelectionView`].
///
/// `base_latency` is resolved eagerly (while the status lock is held) because
/// it is a pure function of the status — active-wire EWMA, then primary's EWMA,
/// then the last probe sample — and resolving it here is what lets the view drop
/// the per-wire `Vec`s.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TransportSelectionView {
    pub(crate) healthy: Option<bool>,
    pub(crate) cooldown_until: Option<Instant>,
    pub(crate) consecutive_successes: u32,
    pub(crate) penalty: PenaltyState,
    pub(crate) descent_window_until: Option<Instant>,
    pub(crate) descent_window_started_at: Option<Instant>,
    pub(crate) base_latency: Option<Duration>,
    /// Copy of [`PerTransportStatus::loss_elevated_since`], for the
    /// loss-driven strict-mode failover check
    /// (`UplinkManager::loss_failover_switch_target`).
    pub(crate) loss_elevated_since: Option<Instant>,
    /// This transport's active-wire loss ratio
    /// ([`PerTransportStatus::active_wire_loss`]), copied out so the
    /// loss-driven failover check can read a *candidate's* own loss without
    /// re-locking its status. `None` means "not measured" — never "no
    /// loss" — see [`crate::loss::LossEwma::ratio`].
    pub(crate) loss_ratio: Option<f64>,
    /// Whether [`Self::loss_ratio`] is still fresh —
    /// [`PerTransportStatus::loss_is_fresh`], evaluated at the same instant
    /// `loss_ratio` was read. Meaningless when `loss_ratio` is `None` (an
    /// unmeasured candidate has nothing to be fresh or stale *about*, and
    /// stays clean by the separate absence rule); when `loss_ratio` is
    /// `Some`, `UplinkManager::loss_failover_switch_target` must not trust
    /// that number as proof of a currently-clean candidate unless this is
    /// `true` — a frozen reading from a warm-standby wire idling below the
    /// sampling volume floor is not evidence either way, and treating its
    /// stale ratio as clean is exactly the defect this field closes.
    pub(crate) loss_ratio_fresh: bool,
}

/// Everything the scoring / gating layer reads off an [`UplinkStatus`], as a
/// flat `Copy` struct.
///
/// Candidate building runs per connection and per uplink, so it used to clone a
/// whole [`UplinkStatus`] — a `String` (`last_error`, most often `Some(..)`
/// exactly on the flapping uplinks) plus three per-wire `Vec`s — for every
/// candidate, none of which the selection ever reads. This view carries only the
/// scalars selection actually consults, so the hot path copies bytes instead of
/// allocating.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SelectionView {
    pub(crate) tcp: TransportSelectionView,
    pub(crate) udp: TransportSelectionView,
}

impl SelectionView {
    pub(crate) fn of(&self, kind: TransportKind) -> &TransportSelectionView {
        match kind {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }
}

impl TransportStatusView for TransportSelectionView {
    fn healthy(&self) -> Option<bool> {
        self.healthy
    }

    fn cooldown_until(&self) -> Option<Instant> {
        self.cooldown_until
    }

    fn penalty(&self) -> PenaltyState {
        self.penalty
    }

    fn descent_window_until(&self) -> Option<Instant> {
        self.descent_window_until
    }

    fn descent_window_started_at(&self) -> Option<Instant> {
        self.descent_window_started_at
    }

    fn base_latency(&self) -> Option<Duration> {
        self.base_latency
    }
}

impl StatusView for SelectionView {
    type Transport = TransportSelectionView;

    fn transport(&self, kind: TransportKind) -> &Self::Transport {
        self.of(kind)
    }
}

impl TransportStatusView for PerTransportStatus {
    fn healthy(&self) -> Option<bool> {
        self.healthy
    }

    fn cooldown_until(&self) -> Option<Instant> {
        self.cooldown_until
    }

    fn penalty(&self) -> PenaltyState {
        self.penalty
    }

    fn descent_window_until(&self) -> Option<Instant> {
        self.descent.until()
    }

    fn descent_window_started_at(&self) -> Option<Instant> {
        self.descent.window_started_at()
    }

    fn base_latency(&self) -> Option<Duration> {
        // This is the trait's config-free contract: the raw latency, with no
        // carrier-loss penalty applied. Actual scoring goes through
        // [`PerTransportStatus::base_latency_with`], which needs the config
        // to fold loss in and is unavailable here. Both share one fallback
        // chain — see [`PerTransportStatus::base_latency_and_wire_loss`].
        self.base_latency_and_wire_loss().map(|(base, _loss)| base)
    }
}

impl StatusView for UplinkStatus {
    type Transport = PerTransportStatus;

    fn transport(&self, kind: TransportKind) -> &Self::Transport {
        self.of(kind)
    }
}

impl PerTransportStatus {
    /// `Copy` projection of this transport's selection-relevant fields.
    /// `config` resolves `base_latency` through [`Self::base_latency_with`]
    /// so the projection carries the loss-inflated value, not the raw one;
    /// `now`, paired with `config`'s [`crate::config::LoadBalancingConfig::loss_max_staleness`],
    /// resolves `loss_ratio_fresh`.
    pub(crate) fn selection_view(
        &self,
        config: &crate::config::LoadBalancingConfig,
        now: Instant,
    ) -> TransportSelectionView {
        TransportSelectionView {
            healthy: self.healthy,
            cooldown_until: self.cooldown_until,
            consecutive_successes: self.consecutive_successes,
            penalty: self.penalty,
            descent_window_until: self.descent.until(),
            descent_window_started_at: self.descent.window_started_at(),
            base_latency: self.base_latency_with(config),
            loss_elevated_since: self.loss_elevated_since,
            loss_ratio: self.active_wire_loss().ratio(),
            loss_ratio_fresh: self.loss_is_fresh(config.loss_max_staleness(), now),
        }
    }

    /// RTT EWMA for the wire that `new sessions currently land on`
    /// (i.e. [`Self::active_wire`]). Returns the primary's
    /// [`Self::rtt_ewma`] when `active_wire == 0` and the corresponding
    /// per-fallback-wire slot otherwise. Returns `None` when the active
    /// wire has no measured RTT yet — caller-side fallback behaviour
    /// (e.g. primary's stale value vs. None) is the caller's choice.
    ///
    /// Used by the scoring layer so the load-balancer compares uplinks by
    /// the latency of the wire that is **actually carrying traffic**
    /// rather than primary's measurement, which may belong to a wire
    /// that the dial loop has long since moved off.
    pub(crate) fn active_wire_rtt_ewma(&self) -> Option<Duration> {
        if self.active_wire == 0 {
            return self.rtt_ewma;
        }
        let slot_idx = (self.active_wire - 1) as usize;
        self.fallback_rtt_ewma.get(slot_idx).copied().flatten()
    }

    /// Fold a fresh latency sample into the per-fallback-wire EWMA slot
    /// for `wire_index`. No-op for `wire_index == 0` (the primary path
    /// updates [`Self::rtt_ewma`] directly through `update_rtt_ewma` in
    /// the probe outcome handler). Lazily extends
    /// [`Self::fallback_rtt_ewma`] so wires that have never been probed
    /// stay represented as `None` rather than a stale zero.
    ///
    /// Called from the per-wire probe walk
    /// ([`crate::manager::probe::wire`]) on a successful fallback-wire
    /// probe, so scoring picks up the fallback's measured RTT instead of
    /// inheriting primary's (possibly stale, possibly broken) value.
    pub(crate) fn record_fallback_wire_latency(
        &mut self,
        wire_index: u8,
        sample: Option<Duration>,
        alpha: f64,
    ) {
        if wire_index == 0 {
            return;
        }
        let slot_idx = (wire_index - 1) as usize;
        while self.fallback_rtt_ewma.len() <= slot_idx {
            self.fallback_rtt_ewma.push(None);
        }
        let mut current = self.fallback_rtt_ewma[slot_idx];
        crate::penalty::update_rtt_ewma(&mut current, sample, alpha);
        self.fallback_rtt_ewma[slot_idx] = current;
    }

    /// Loss for the wire new sessions currently land on. Same active-wire rule
    /// as [`Self::active_wire_rtt_ewma`], so scoring never mixes one wire's
    /// latency with another's loss.
    pub(crate) fn active_wire_loss(&self) -> crate::loss::LossEwma {
        if self.active_wire == 0 {
            return self.carrier_loss;
        }
        let slot_idx = (self.active_wire - 1) as usize;
        self.fallback_carrier_loss.get(slot_idx).copied().unwrap_or_default()
    }

    /// Advance [`Self::loss_elevated_since`] by one sampling tick. Called
    /// from `UplinkManager::sample_carrier_loss_once` on every tick, for
    /// every uplink/transport, regardless of whether that tick produced a
    /// fresh loss window — an uplink already over the threshold whose only
    /// carrier just went idle must not silently freeze its episode instead
    /// of continuing to age it, and a tick that measured nothing new must
    /// still be able to *clear* a stale episode once the wire's carrier is
    /// gone (its ratio resets to "not measured" via [`Self::reset_wire_loss`]
    /// first).
    ///
    /// `threshold <= 0.0` is `LoadBalancingConfig::loss_failover_ratio`'s
    /// documented off switch: the episode is always cleared, so the check
    /// ships inert exactly like the sibling `carrier_degraded_failover`
    /// knob when unset.
    ///
    /// Otherwise the ratio is trusted only when it is *fresh*:
    /// [`Self::loss_last_qualifying_at`] must both name the wire currently
    /// active ([`Self::active_wire`] — see that stamp's doc for why a wire
    /// flip must not let one wire's freshness vouch for another's ratio) and
    /// be within `max_staleness` of `now` (see the same doc for why a frozen
    /// EWMA cannot be trusted indefinitely just because nothing has
    /// re-measured it). A fresh ratio strictly above `threshold` starts the
    /// episode on the first such tick and leaves an already-running
    /// episode's anchor untouched — a re-trigger must not reset a genuinely
    /// long episode back to "just started". A fresh ratio at or below
    /// `threshold`, a stale (or wire-mismatched, or absent) verdict, or no
    /// ratio at all (not measured is never evidence of loss) all clear the
    /// episode: a single clean tick restarts the clock instead of letting an
    /// uplink that merely flaps around the threshold accumulate its way
    /// into a failover, and a verdict nobody has reconfirmed — for this
    /// wire, recently — stops counting as "still happening".
    pub(crate) fn update_loss_elevated_since(
        &mut self,
        threshold: f64,
        now: Instant,
        max_staleness: Duration,
    ) {
        if threshold <= 0.0 {
            self.loss_elevated_since = None;
            return;
        }
        let elevated = self.loss_is_fresh(max_staleness, now)
            && self.active_wire_loss().ratio().is_some_and(|ratio| ratio > threshold);
        self.loss_elevated_since = if elevated {
            self.loss_elevated_since.or(Some(now))
        } else {
            None
        };
    }

    /// Whether [`Self::loss_last_qualifying_at`] still vouches for
    /// [`Self::active_wire_loss`]'s ratio: the stamp must name the wire
    /// currently active (a wire flip must not let a stale measurement of a
    /// *different* wire validate the new active wire's ratio) and be within
    /// `max_staleness` of `now` (a qualifying window this old is no longer
    /// trustworthy evidence of the *current* state — see
    /// [`Self::loss_last_qualifying_at`]'s doc for the warm-standby scenario
    /// this exists to catch).
    ///
    /// Shared by two callers that both need this same yes/no, for opposite
    /// reasons: [`Self::update_loss_elevated_since`] uses it to decide
    /// whether the *active* uplink's own ratio may still be trusted as
    /// evidence of ongoing loss (a stale reading must not keep an episode
    /// running, nor start a new one); `UplinkManager::loss_failover_switch_target`
    /// (via [`Self::selection_view`]) uses it to decide whether a
    /// *candidate's* ratio may be trusted as evidence the candidate is
    /// currently clean (a stale reading — however low the frozen number —
    /// must not wave a not-recently-confirmed candidate onto the leg; only
    /// a genuinely unmeasured candidate, which carries no number to
    /// mistrust, keeps the separate "absence is not evidence of loss" rule).
    pub(crate) fn loss_is_fresh(&self, max_staleness: Duration, now: Instant) -> bool {
        let active_wire = self.active_wire;
        self.loss_last_qualifying_at.is_some_and(|(wire, t)| {
            wire == active_wire && now.saturating_duration_since(t) <= max_staleness
        })
    }

    /// The latency this transport is ranked by, paired with the loss slot
    /// **attributed to the same wire it came from** — the single fallback
    /// chain shared by [`TransportStatusView::base_latency`] (raw value) and
    /// [`Self::base_latency_with`] (loss-inflated value), so the two can
    /// never drift apart.
    ///
    /// - The active wire's own RTT EWMA is preferred, so cross-uplink scoring
    ///   compares the latency of the wire that is **actually carrying
    ///   traffic**; paired with that same wire's own loss slot
    ///   ([`Self::active_wire_loss`]).
    /// - Falling back to primary's `rtt_ewma` (the active wire has no
    ///   per-wire sample yet — cold start right after a wire flip, primary's
    ///   `rtt_ewma` may otherwise belong to a completely different,
    ///   now-broken wire) is paired with primary's own loss slot
    ///   (`carrier_loss`, wire `0`), not the active wire's — mixing the two
    ///   would score a latency sample against a loss verdict from an
    ///   unrelated wire.
    /// - Falling back further to the last probe `latency` sample carries no
    ///   wire attribution at all, so it is paired with a default (no-loss)
    ///   verdict: an unattributed base value cannot correctly carry an
    ///   attributed loss penalty.
    fn base_latency_and_wire_loss(&self) -> Option<(Duration, crate::loss::LossEwma)> {
        if let Some(active) = self.active_wire_rtt_ewma() {
            return Some((active, self.active_wire_loss()));
        }
        if let Some(primary) = self.rtt_ewma {
            return Some((primary, self.carrier_loss));
        }
        Some((self.latency?, crate::loss::LossEwma::default()))
    }

    /// Penalty-free latency this transport is ranked by, with carrier loss on
    /// the same wire the latency came from folded in — see
    /// [`Self::base_latency_and_wire_loss`] for which wire's loss slot
    /// applies to which fallback branch.
    ///
    /// Loss is applied as a multiplier on latency rather than as a separate
    /// term because that is what it physically is: every retransmit costs the
    /// affected bytes another round trip, so a lossy path delivers later at
    /// the same RTT. Applying it here — the shared input of every routing
    /// scope — is also what makes it visible to Global scope under
    /// `auto_failback`, which discards `penalty` entirely and would otherwise
    /// stay blind exactly where the field incident happened. This is only
    /// true because the candidate-building call site scores from the
    /// [`TransportSelectionView`] this method feeds (via [`Self::selection_view`]),
    /// not from the raw, uninflated [`TransportStatusView::base_latency`] —
    /// see `UplinkManager::build_candidate_states` in `manager/candidates.rs`.
    ///
    /// Loss never synthesises a latency: with no RTT sample the result stays
    /// `None`, because an uplink that has never been measured must not be
    /// ranked on a fabricated number.
    ///
    /// This is the scoring entry point; [`TransportStatusView::base_latency`]
    /// on this type stays the config-free raw value (no loss applied) for
    /// callers that rank a single status against itself without a config in
    /// hand.
    ///
    /// Deliberately **not** gated on [`Self::loss_is_fresh`], unlike
    /// [`Self::selection_view`]'s `loss_ratio_fresh` (consumed by
    /// `UplinkManager::loss_failover_switch_target`) and
    /// [`Self::update_loss_elevated_since`]. Both of those decide whether a
    /// *stale* reading may be trusted as **good** news — evidence an active
    /// or candidate uplink is not currently lossy — and staleness must not
    /// vouch for that; the risk is a warm-standby wire's ratio going stale
    /// and being silently read as "confirmed clean" the moment nobody has
    /// re-measured it, which is exactly backwards from what a freshness gate
    /// is for. Ranking has the opposite risk profile: gating this multiplier
    /// on freshness would make a stale ratio "expire" back to `1.0` (no
    /// penalty), which is trusting staleness as good news in the *other*
    /// place it must not be trusted — a lossy uplink deselected minutes ago
    /// would have its rank penalty silently vanish once its warm-standby
    /// traffic falls quiet, before anything has re-confirmed it improved.
    /// Leaving the multiplier on a frozen ratio keeps ranking conservative in
    /// the same direction the candidate filter is conservative in: neither
    /// treats "nobody has re-checked recently" as proof of recovery.
    pub(crate) fn base_latency_with(
        &self,
        config: &crate::config::LoadBalancingConfig,
    ) -> Option<Duration> {
        let (base, loss) = self.base_latency_and_wire_loss()?;
        let multiplier =
            loss.inflation(config.loss_latency_penalty_k, config.loss_latency_inflation_max);
        if multiplier <= 1.0 {
            return Some(base);
        }
        // `try_from_secs_f64` rather than the panicking `from_secs_f64`: the
        // config loader bounds `loss_latency_inflation_max` to `[1, 100]`
        // (`bins/outline-ws-rust/src/config/load/balancing.rs`), but this
        // stays as defence in depth against this function's own
        // multiplication overflowing regardless of that bound, saturating to
        // `Duration::MAX` (effectively "worst possible") here rather than
        // panicking.
        //
        // Saturating here does not, on its own, guarantee no caller ever
        // panics on the result: `crate::selection::weighted_latency_score`
        // divides this value by the uplink's `weight` (unbounded above —
        // only `> 0.0` is enforced at load time, see
        // `bins/outline-ws-rust/src/config/load/uplinks/mod.rs`) and calls
        // the panicking `Duration::from_secs_f64` again, so a genuine
        // `Duration::MAX` here divided by a `weight < 1.0` would overflow
        // past `Duration::MAX` and panic there instead. What actually makes
        // this unreachable is that the `[1, 100]` bound on
        // `loss_latency_inflation_max` keeps `base * multiplier` from ever
        // *reaching* `Duration::MAX` for any base latency a real RTT sample
        // could produce — the saturating branch below is defence against an
        // input that is not itself reachable, so there is nothing for
        // `weighted_latency_score`'s division to overflow. It stays this
        // function's job to keep its own output sane; it is not what
        // protects the caller from an unrelated unbounded `weight`.
        Some(Duration::try_from_secs_f64(base.as_secs_f64() * multiplier).unwrap_or(Duration::MAX))
    }

    /// Fold one sampling window into the slot for `wire`. Returns whether
    /// the window actually qualified (met `min_packets`) and moved the
    /// ratio — see [`crate::loss::LossEwma::record_window`]. Callers that
    /// need to know whether *this tick* produced fresh evidence for the
    /// active wire (as opposed to a sub-threshold window the ratio silently
    /// ignored) use the return value; see [`Self::loss_last_qualifying_at`].
    pub(crate) fn record_wire_loss_window(
        &mut self,
        wire: u8,
        sent: u64,
        lost: u64,
        min_packets: u64,
        alpha: f64,
    ) -> bool {
        if wire == 0 {
            return self.carrier_loss.record_window(sent, lost, min_packets, alpha);
        }
        let slot_idx = (wire - 1) as usize;
        while self.fallback_carrier_loss.len() <= slot_idx {
            self.fallback_carrier_loss.push(crate::loss::LossEwma::default());
        }
        self.fallback_carrier_loss[slot_idx].record_window(sent, lost, min_packets, alpha)
    }

    /// Clear `wire`'s loss verdict back to "not measured". Called by the
    /// sampling loop when a (transport, wire) loses its last registered
    /// carrier ([`crate::loss::CarrierLossRegistry::collect_windows`]'s
    /// `emptied_wires`), so a ratio measured while the wire carried traffic
    /// does not survive as a stale penalty once nothing is left to measure —
    /// see [`crate::loss::LossEwma::reset`].
    ///
    /// A no-op for a fallback slot that was never extended (`wire` past the
    /// end of [`Self::fallback_carrier_loss`]): an unmeasured slot is already
    /// the reset state, so there is nothing to clear.
    pub(crate) fn reset_wire_loss(&mut self, wire: u8) {
        if wire == 0 {
            self.carrier_loss.reset();
            return;
        }
        let slot_idx = (wire - 1) as usize;
        if let Some(slot) = self.fallback_carrier_loss.get_mut(slot_idx) {
            slot.reset();
        }
    }

    /// Mutable per-wire penalty slot for `wire` (`0` = primary, `i` = fallback
    /// `i-1`), lazily extending [`Self::wire_penalty`] so a wire that has never
    /// failed is materialised as a default (zero-penalty) slot.
    pub(crate) fn wire_penalty_slot_mut(&mut self, wire: u8) -> &mut PenaltyState {
        let idx = wire as usize;
        if self.wire_penalty.len() <= idx {
            self.wire_penalty.resize(idx + 1, PenaltyState::default());
        }
        &mut self.wire_penalty[idx]
    }

    /// Selection weight in `(0, 1]` for `wire`, derived from its decaying
    /// penalty (see [`crate::penalty::penalty_weight`]). A wire with no recorded
    /// penalty — including any wire past the end of [`Self::wire_penalty`] —
    /// scores the full `1.0`.
    pub(crate) fn wire_weight(
        &self,
        wire: u8,
        now: Instant,
        config: &crate::config::LoadBalancingConfig,
        floor: f64,
    ) -> f64 {
        match self.wire_penalty.get(wire as usize) {
            Some(state) => crate::penalty::penalty_weight(state, now, config, floor),
            None => 1.0,
        }
    }
}

/// One non-primary wire's carrier-descent slot: the same
/// [`CarrierDescentState`] the primary wire uses, plus this wire's own
/// probe streaks.
///
/// The streaks cannot be shared with [`PerTransportStatus::consecutive_failures`]
/// / [`PerTransportStatus::consecutive_successes`]: those count the *primary*
/// probe's outcomes (the default probe path always targets primary — see
/// [`crate::manager::probe::wire`]), so feeding them to this wire's descent
/// gate would let primary's failures push a fallback's carrier down, which is
/// the whole class of bug the per-wire slots exist to prevent. The
/// fallback-wire probe keeps its own counters here.
#[derive(Clone, Debug, Default)]
pub(crate) struct ModeDowngradeSlot {
    /// Window, cap, grace budget and recovery streak for this wire —
    /// identical bookkeeping to the primary's slot.
    pub(crate) descent: CarrierDescentState,
    /// Consecutive fallback-wire probe failures on this wire. Feeds the
    /// at-cap descent gate so a single flaky probe at the capped rank
    /// cannot step the cap deeper.
    pub(crate) probe_failures: u32,
    /// Consecutive fallback-wire probe successes on this wire. Feeds the
    /// walk-up that claws intermediate ranks back.
    pub(crate) probe_successes: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PenaltyState {
    pub(crate) value_secs: f64,
    pub(crate) updated_at: Option<Instant>,
}
