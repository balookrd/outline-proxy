//! Per-uplink, per-transport runtime status: probe health, RTT, cooldowns,
//! penalty, mode-downgrade window, and runtime-failure counters.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::TransportMode;
use crate::types::TransportKind;

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
    /// When set, connections must use a lower-rank carrier than the
    /// configured one until this instant because the configured one
    /// (H3, raw QUIC, XHTTP-H3, XHTTP-H2) produced repeated transport
    /// errors. Cleared by a successful explicit H3 re-probe (WS path)
    /// or by natural TTL expiry (XHTTP path — no recovery probe).
    /// Always paired with [`Self::mode_downgrade_capped_to`]: either
    /// both are `Some` or both are `None`.
    pub(crate) mode_downgrade_until: Option<Instant>,
    /// Family-aware ceiling for the downgrade window — what
    /// `effective_*_mode` returns while [`Self::mode_downgrade_until`]
    /// is in the future. Set alongside the deadline so the
    /// reader does not need to know which family the configured mode
    /// belongs to (`WsH3` → `WsH2`, `XhttpH3` → `XhttpH2`,
    /// `XhttpH2` → `XhttpH1`, `Quic` → `WsH2`). Updates monotonically
    /// downward inside an active window: a second failure on the
    /// already-capped carrier (e.g. `XhttpH2` after a previous
    /// `XhttpH3` → `XhttpH2` cap) lowers the ceiling but never
    /// raises it, so multi-step downgrades preserve the deepest
    /// failure observed during the window.
    pub(crate) mode_downgrade_capped_to: Option<TransportMode>,
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
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UplinkStatus {
    pub(crate) tcp: PerTransportStatus,
    pub(crate) udp: PerTransportStatus,
    pub(crate) last_error: Option<String>,
    pub(crate) last_checked: Option<Instant>,
}

impl UplinkStatus {
    /// Borrow the per-transport status for the given transport kind.
    pub(crate) fn of(&self, kind: TransportKind) -> &PerTransportStatus {
        match kind {
            TransportKind::Tcp => &self.tcp,
            TransportKind::Udp => &self.udp,
        }
    }
}

impl PerTransportStatus {
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
}

/// One mode-downgrade window slot. Mirrors the
/// `(mode_downgrade_until, mode_downgrade_capped_to)` pair on
/// [`PerTransportStatus`] but for a non-primary wire. `until == None`
/// means no active window (defaults dial to the wire's configured mode);
/// `capped_to == None` is the same.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ModeDowngradeSlot {
    pub(crate) until: Option<Instant>,
    pub(crate) capped_to: Option<TransportMode>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PenaltyState {
    pub(crate) value_secs: f64,
    pub(crate) updated_at: Option<Instant>,
}
