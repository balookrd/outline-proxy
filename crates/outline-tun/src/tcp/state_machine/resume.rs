//! Per-flow resume accounting for TUN TCP flows.
//!
//! A TUN TCP flow rides a *shared* carrier (one H3/H2/H1 connection multiplexes
//! many flows). When that carrier dies, every flow on it dies with it — even
//! though the server still holds each flow's upstream socket parked under the
//! Session ID it minted for that flow (see
//! `bins/outline-ss-rust/docs/SESSION-RESUMPTION.md`). Re-attaching the parked
//! upstream on a fresh carrier is byte-exact only if the client can answer two
//! questions at redial time:
//!
//!   1. *Which* parked upstream is mine? → the flow's own [`SessionId`].
//!   2. Which uplink bytes must be replayed, and from which offset? → the
//!      [`ClientUpstreamRingBuffer`] (uplink tail) plus `client_acked_offset`
//!      (the v2 `X-Outline-Resume-Down-Acked` value the server needs to compute
//!      its downlink replay slice).
//!
//! This module holds exactly that state, plus the bookkeeping that keeps the
//! two tasks touching a carrier — the upstream reader (which drives the
//! migration) and the upstream pump (which must not fight it) — in step. The
//! migration itself lives in `engine/tasks/upstream/migrate.rs`. Mirrors the
//! accounting the SOCKS5 pinned relay already does inline
//! (`bins/outline-ws-rust/src/proxy/tcp/connect/pinned_relay.rs`).

use std::time::{Duration, Instant};

use outline_transport::SessionId;
use outline_transport::uplink_replay::{ClientUpstreamRingBuffer, PushError, ReplayError};

/// Byte cap of one flow's uplink replay ring.
///
/// This is a **ceiling, not a preallocation**: [`ClientUpstreamRingBuffer::new`]
/// allocates nothing, and the ring only ever grows with the bytes the flow
/// actually sends upstream (FIFO-evicting once it reaches the cap). A flow that
/// never sends — an idle flow, or a pure download — holds zero bytes here.
///
/// Memory budget (AGENTS.md bounded-resources guardrail): worst case is
/// `max_flows × TUN_UPLINK_REPLAY_RING_BYTES`, reached only if *every* flow in
/// the table is simultaneously mid-upload; the steady state is far below that.
/// 64 KiB per flow also comfortably exceeds the largest single chunk the uplink
/// pump can hand us (one client segment, ≤ 65535 B of IP payload), so the
/// oversized-chunk path below is a guardrail rather than an expected event.
pub(in crate::tcp) const TUN_UPLINK_REPLAY_RING_BYTES: usize = 64 * 1024;

/// How many carrier migrations one flow may attempt over its whole lifetime.
///
/// A migration only pays off when the carrier died under a flow that is
/// otherwise healthy; a flow whose carriers keep dying is being told something,
/// and retrying forever would just keep re-dialling a broken uplink while the
/// application waits. Two attempts cover the case this exists for — a shared H3
/// carrier collapsing, and the replacement being unlucky — after which the flow
/// tears down as it did before.
pub(in crate::tcp) const TUN_TCP_MIGRATION_MAX_ATTEMPTS: u8 = 2;

/// How long after the *first* migration attempt a flow may still start another.
///
/// The server parks an orphaned upstream for 30 s
/// (`bins/outline-ss-rust/docs/SESSION-RESUMPTION.md`), so an attempt starting
/// later than this can only ever miss — and a miss costs a wasted dial plus the
/// wait for a control frame that will never come, while the application sits
/// there. Give up and tear down honestly instead.
pub(in crate::tcp) const TUN_TCP_MIGRATION_DEADLINE: Duration = Duration::from_secs(20);

/// Where a flow is in the carrier-migration handshake. Read by the upstream pump
/// to decide whether a failed send means "the flow is dead" (as it always did)
/// or "wait, the reader is re-attaching this flow to a live carrier".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tcp) enum MigrationPhase {
    /// No migration in progress. The flow's carrier is whatever the last commit
    /// installed (or the original one).
    Idle,
    /// The reader is dialling / confirming / replaying. The pump must not push
    /// anything new into the replay ring while this is set — a chunk pushed
    /// after the migration snapshotted the ring would be replayed by nobody and
    /// dropped by the pump's epoch check.
    InFlight,
    /// This flow will never migrate again: it missed, it could not replay
    /// byte-exact, or it spent its budget. The pump falls back to the original
    /// teardown on the next failed send.
    Abandoned,
}

/// What a carrier migration needs to re-attach this flow's parked upstream on a
/// new carrier without losing or duplicating a byte.
///
/// A flow is *resumable* while it holds a replay ring. It stops being resumable
/// the moment the ring can no longer reconstruct the uplink byte stream
/// exactly — see [`Self::record_uplink_chunk`]. That is a downgrade of a future
/// capability, never a reason to disturb the live flow.
pub(in crate::tcp) struct FlowResume {
    /// The Session ID the server minted for **this flow** on its carrier
    /// (`None` on a direct flow, or against a server without resumption).
    ///
    /// It is the flow's own id and must never be presented by another flow: on
    /// a resume hit the server ignores the handshake target and re-attaches
    /// whatever upstream is parked under the id, so a shared id would splice one
    /// flow onto another flow's destination.
    ///
    /// Refreshed on every committed migration: the server mints a *new* id on
    /// the resume hit, and the next migration must present that one.
    ///
    /// `None` also carries a decision: a server with resumption disabled never
    /// mints an id, so such a flow is never eligible to migrate and never pays
    /// for a dial that could only miss.
    pub(in crate::tcp) session_id: Option<SessionId>,
    /// Bounded tail of the bytes this flow sent upstream, addressed by absolute
    /// offset. `None` once the flow is no longer replayable (never armed, or
    /// downgraded by an oversized chunk).
    replay: Option<ClientUpstreamRingBuffer>,
    /// Cumulative downstream *payload* bytes this flow has accepted from the
    /// server — the v2 `X-Outline-Resume-Down-Acked` value.
    ///
    /// A plain `u64` rather than the SOCKS relay's `Arc<AtomicU64>`: there the
    /// counter is shared by two independently-spawned relay closures and must
    /// survive them, whereas here both writers (the uplink pump and the downlink
    /// reader) already hold the flow mutex when they touch it, and the state
    /// outlives every per-flow task. An `Arc` would buy nothing but an
    /// allocation per flow.
    client_acked_offset: u64,
    /// Bumped once per *committed* carrier migration, in the same critical
    /// section that snapshots the replay ring. The pump reads it when it pops a
    /// batch and compares it against the epoch stamped on the carrier it is
    /// about to write to: a mismatch means a migration replaced the carrier
    /// after the batch went into the ring, so the replay already re-emitted
    /// those bytes and sending them again would duplicate them. See
    /// `engine/tasks/upstream/migrate.rs` for the full ordering argument.
    carrier_epoch: u64,
    phase: MigrationPhase,
    /// Migrations started (not necessarily committed). Capped by
    /// [`TUN_TCP_MIGRATION_MAX_ATTEMPTS`].
    attempts: u8,
    /// When the first attempt began — the clock the
    /// [`TUN_TCP_MIGRATION_DEADLINE`] runs against, so a flow cannot keep
    /// re-dialling past the server's park TTL.
    first_attempt_at: Option<Instant>,
}

impl FlowResume {
    /// State for a flow that cannot be resumed: no id, no ring. This is what a
    /// flow is born with (no carrier yet) and what a direct flow keeps for life
    /// (a direct socket has no carrier to migrate off).
    pub(in crate::tcp) const fn disarmed() -> Self {
        Self {
            session_id: None,
            replay: None,
            client_acked_offset: 0,
            carrier_epoch: 0,
            phase: MigrationPhase::Idle,
            attempts: 0,
            first_attempt_at: None,
        }
    }

    /// State for a freshly-connected tunneled flow: records `session_id` and
    /// arms a [`TUN_UPLINK_REPLAY_RING_BYTES`] replay ring.
    pub(in crate::tcp) fn armed(session_id: Option<SessionId>) -> Self {
        Self::armed_with_capacity(session_id, TUN_UPLINK_REPLAY_RING_BYTES)
    }

    /// [`Self::armed`] with an explicit ring cap. Production always takes the
    /// default; the cap is a parameter so tests can drive the overflow path
    /// without pushing 64 KiB through a flow.
    pub(in crate::tcp) fn armed_with_capacity(
        session_id: Option<SessionId>,
        capacity_bytes: usize,
    ) -> Self {
        Self {
            session_id,
            replay: Some(ClientUpstreamRingBuffer::new(capacity_bytes)),
            client_acked_offset: 0,
            carrier_epoch: 0,
            phase: MigrationPhase::Idle,
            attempts: 0,
            first_attempt_at: None,
        }
    }

    /// Whether a byte-exact replay of this flow's uplink is still possible.
    pub(in crate::tcp) fn is_resumable(&self) -> bool {
        self.replay.is_some()
    }

    /// The replay ring itself, for tests that assert on its offsets
    /// (`total_sent`, `oldest_offset`) or its contents. Production reads the
    /// tail through [`Self::replay_from`], which is the only shape a migration
    /// ever needs.
    #[cfg(test)]
    pub(in crate::tcp) fn replay(&self) -> Option<&ClientUpstreamRingBuffer> {
        self.replay.as_ref()
    }

    /// The uplink bytes the server has *not* confirmed forwarding, per its own
    /// `up_acked` report on a resume hit — exactly what the migration must
    /// re-send on the new carrier, and nothing else.
    ///
    /// The errors are the two ways the server's claim and our ring disagree, and
    /// both are fatal to the migration (never to correctness): `OffsetEvicted`
    /// means the bytes it wants are older than anything we still hold, and
    /// `OffsetAhead` means it claims to have forwarded bytes we never sent. In
    /// either case we cannot reproduce the stream, so the flow must tear down
    /// rather than continue with a hole in it.
    pub(in crate::tcp) fn replay_from(&self, up_acked: u64) -> Result<Vec<u8>, ReplayError> {
        match self.replay.as_ref() {
            Some(ring) => ring.replay_from(up_acked),
            // Unreachable via the migration path (`can_attempt_migration` gates
            // on the ring), but a torn stream is the worst thing this code can
            // produce — so answer with the error that tears down, not `Ok`.
            None => Err(ReplayError::OffsetEvicted {
                requested: up_acked,
                oldest_available: u64::MAX,
            }),
        }
    }

    /// Cumulative downstream payload bytes accepted from the server — the
    /// `X-Outline-Resume-Down-Acked` value the migration redial presents so the
    /// server can compute the exact downstream slice we never saw.
    pub(in crate::tcp) fn client_acked_offset(&self) -> u64 {
        self.client_acked_offset
    }

    /// Epoch of the carrier this flow's ring is currently accounted against. See
    /// [`Self::carrier_epoch`] (the field) for what the pump does with it.
    pub(in crate::tcp) fn carrier_epoch(&self) -> u64 {
        self.carrier_epoch
    }

    /// Whether a migration is dialling / confirming / replaying right now.
    pub(in crate::tcp) fn migration_in_flight(&self) -> bool {
        self.phase == MigrationPhase::InFlight
    }

    /// Whether this flow may still *start* a migration.
    ///
    /// Every clause is a way the migration could not be proven byte-exact, and
    /// so a way it must not be attempted at all:
    ///
    /// * `enabled` — the operator turned it off (`[tun.tcp] carrier_migration`).
    /// * no Session ID — the server never issued one (resumption disabled, or a
    ///   direct flow), so there is nothing parked to re-attach and a dial could
    ///   only ever produce a *fresh* upstream spliced onto a live stream.
    /// * no ring — an oversized chunk already cost this flow its uplink replay
    ///   (see [`Self::record_uplink_chunk`]); we could re-attach but not
    ///   reproduce the tail.
    /// * abandoned / budget / deadline — see [`MigrationPhase::Abandoned`],
    ///   [`TUN_TCP_MIGRATION_MAX_ATTEMPTS`], [`TUN_TCP_MIGRATION_DEADLINE`].
    pub(in crate::tcp) fn can_attempt_migration(&self, enabled: bool, now: Instant) -> bool {
        enabled
            && self.phase != MigrationPhase::Abandoned
            && self.session_id.is_some()
            && self.replay.is_some()
            && self.attempts < TUN_TCP_MIGRATION_MAX_ATTEMPTS
            && self
                .first_attempt_at
                .is_none_or(|started| now.duration_since(started) < TUN_TCP_MIGRATION_DEADLINE)
    }

    /// Claims one attempt from the budget and marks the flow as migrating. Call
    /// only after [`Self::can_attempt_migration`] returned `true`, under the
    /// same flow lock, so two tasks cannot both claim the last attempt.
    pub(in crate::tcp) fn begin_migration(&mut self, now: Instant) {
        self.phase = MigrationPhase::InFlight;
        self.attempts = self.attempts.saturating_add(1);
        self.first_attempt_at.get_or_insert(now);
    }

    /// Commits a migration whose resume hit is confirmed: adopts the id the
    /// server minted on the hit (the retired one is dead the moment it is
    /// re-used) and bumps the carrier epoch.
    ///
    /// MUST be called in the same flow-lock critical section that snapshots the
    /// replay tail — the epoch is what tells the pump whether the batch in its
    /// hand is inside that snapshot or after it.
    pub(in crate::tcp) fn commit_migration(&mut self, session_id: Option<SessionId>) {
        self.session_id = session_id;
        self.carrier_epoch = self.carrier_epoch.wrapping_add(1);
        self.phase = MigrationPhase::Idle;
    }

    /// Gives up on migrating this flow, for good. The caller then falls through
    /// to the unchanged teardown.
    pub(in crate::tcp) fn abandon_migration(&mut self) {
        self.phase = MigrationPhase::Abandoned;
    }

    /// Records a payload chunk handed to the upstream writer. Called with
    /// exactly the bytes, in exactly the order, that go out on the wire, so the
    /// ring's `total_sent()` tracks the server's view of this flow's uplink.
    ///
    /// A chunk larger than the ring cap cannot be held whole, and a ring that
    /// cannot hold it whole can never replay it — so the flow is downgraded to
    /// non-resumable (the ring is dropped, freeing what it held) and the error
    /// is handed back for the caller to log/count. **The chunk is still sent**:
    /// losing the ability to replay a future carrier death says nothing about
    /// the flow that is working right now, and turning this into a FIN/RST would
    /// break a live connection to protect a hypothetical one.
    pub(in crate::tcp) fn record_uplink_chunk(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        let Some(ring) = self.replay.as_mut() else {
            return Ok(());
        };
        match ring.push(chunk) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.replay = None;
                Err(error)
            },
        }
    }

    /// Records downstream payload bytes accepted from the server.
    ///
    /// "Accepted" is the moment the bytes land in this flow's downlink buffer,
    /// not the moment the TUN client ACKs them: from that point our own TCP
    /// state machine owns their delivery (and retransmission), so a resume must
    /// not ask the server to replay them a second time.
    ///
    /// Kept up to date even after the flow stops being resumable, so the counter
    /// stays a truthful "bytes taken from the server" for the whole flow.
    pub(in crate::tcp) fn record_downlink_payload(&mut self, len: usize) {
        self.client_acked_offset = self.client_acked_offset.saturating_add(len as u64);
    }
}

#[cfg(test)]
#[path = "tests/resume.rs"]
mod tests;
