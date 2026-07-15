//! Carrier migration: keeping a TUN TCP flow alive across the death of the
//! carrier it rides.
//!
//! A tunnelled flow shares its carrier (one H3/H2/H1 connection) with every
//! other flow on the uplink. When that carrier collapses, all of them lose their
//! transport at once — but the *upstream sockets* are not gone: the server parks
//! each one in its orphan registry under the Session ID it minted for that flow
//! and holds it for 30 s
//! (`bins/outline-ss-rust/docs/SESSION-RESUMPTION.md`). This module re-dials a
//! fresh carrier, presents the flow's own id, has the parked upstream
//! re-attached, closes the byte gap in both directions, and lets the read loop
//! carry on — so the application never sees the disconnect.
//!
//! # The one rule
//!
//! **Migrate only on a confirmed hit.** A redial that presents an id can miss:
//! the park expired, the server has resumption off (it does by default), or it
//! is simply a different server. On a miss the server mints a new id and opens a
//! **fresh** upstream to the destination, starting the byte stream from zero —
//! so continuing the flow would splice a brand-new stream onto a half-finished
//! one and hand the application a corrupt result *that looks like success*. That
//! is strictly worse than the disconnect we are trying to avoid.
//!
//! The proof of a hit is the v1 `ORSM` control frame: the server emits it only
//! after the orphan-take succeeded. It is not the capability echo on the upgrade
//! response — the server echoes that whenever it *understands* the protocol,
//! hit or miss. So the test is `consume_ack_prefix_with_timeout` returning
//! `Ok(Some(up_acked))`, and nothing else. Everything that is not that —
//! `Ok(None)` (server never engaged the protocol), a timeout, a parse failure, a
//! ring that cannot reproduce the tail, a `REPLAY_TRUNCATED` v2 frame — takes
//! the flow down exactly the way it went down before this module existed.
//!
//! # Who touches what
//!
//! Two tasks share the carrier: the reader (which runs the migration) and the
//! pump (the sole writer). They coordinate through the flow state, and the
//! ordering that makes the byte stream come out exact is:
//!
//! 1. The reader marks the flow `InFlight` under the flow lock. From here the
//!    pump stops taking new batches out of the flow's buffer, so nothing new
//!    enters the replay ring until the migration is done. Anything already in
//!    the pump's hand was mirrored into the ring *before* this point.
//! 2. The reader dials and confirms the hit — holding no locks, because it is
//!    slow.
//! 3. The reader takes the **writer** lock, and the flow lock inside it (the
//!    pump only ever holds one at a time, so this order cannot deadlock). Under
//!    both, it snapshots the ring tail from `up_acked` and bumps the carrier
//!    epoch: the snapshot and the epoch are one atomic fact — "these bytes are
//!    the replay, and any batch stamped with the old epoch is inside it".
//! 4. Still holding the writer lock, it installs the new carrier and pushes the
//!    replay through it. Any pump send that piled up on that mutex therefore
//!    lands *after* the replay, in order — and, seeing the epoch has moved,
//!    drops the batch the replay already covered instead of sending it twice.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow, bail};
use socks5_proto::TargetAddr;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

use outline_metrics as metrics;
use outline_transport::downlink_replay::DownlinkReplayOutcome;
use outline_transport::{SessionId, TcpReader, TcpWriter};
use outline_uplink::{UplinkCandidate, UplinkManager};

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, UpstreamCarrier, UpstreamWriter, flush_server_output,
};
use super::super::super::TunTcpEngine;
use super::super::super::connect::redial_tcp_uplink_for_migration;

/// What the reader does next.
pub(super) enum MigrationOutcome {
    /// The flow rides a fresh carrier and its byte stream is intact: `reader`
    /// replaces the dead one and the read loop continues. The application saw
    /// nothing.
    Migrated(Box<TcpReader>),
    /// No migration (not eligible, missed, or could not be made byte-exact).
    /// The caller falls through to the teardown it always did.
    NotMigrated,
}

/// Everything the migration needs, snapshotted under the flow lock so the slow
/// part (dial + handshake) runs without holding it.
struct MigrationPlan {
    manager: UplinkManager,
    uplink_index: usize,
    target: TargetAddr,
    /// **This flow's** id. Presenting another flow's id would re-attach us to
    /// that flow's upstream — the server takes the parked target as
    /// authoritative on a hit.
    session_id: SessionId,
    client_acked_offset: u64,
    carrier: Arc<Mutex<UpstreamCarrier>>,
    group_name: Arc<str>,
    uplink_name: Arc<str>,
}

impl TunTcpEngine {
    /// Try to carry `flow` over to a live carrier after its own died.
    ///
    /// Returns [`MigrationOutcome::Migrated`] only when the server confirmed it
    /// re-attached this flow's parked upstream **and** both byte gaps were
    /// closed. Every other path returns [`MigrationOutcome::NotMigrated`] with
    /// the flow untouched, for the caller to tear down as before.
    pub(super) async fn try_migrate_carrier(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
    ) -> MigrationOutcome {
        let Some(plan) = self.plan_migration(flow).await else {
            return MigrationOutcome::NotMigrated;
        };

        let result = self.migrate_to_fresh_carrier(key, flow, &plan).await;
        let notify = {
            let state = flow.lock().await;
            state.signals.carrier_migration.clone()
        };
        match result {
            Ok(reader) => {
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migrated",
                );
                // Release the pump onto the carrier the commit installed.
                notify.notify_one();
                MigrationOutcome::Migrated(Box::new(reader))
            },
            Err(error) => {
                {
                    let mut state = flow.lock().await;
                    state.resume.abandon_migration();
                }
                // Release the pump onto the teardown path: without this it would
                // sit parked on a flow the reader is about to FIN.
                notify.notify_one();
                debug!(
                    uplink = %plan.uplink_name,
                    error = %format!("{error:#}"),
                    "TUN TCP carrier migration abandoned; tearing the flow down as before"
                );
                MigrationOutcome::NotMigrated
            },
        }
    }

    /// Claim one migration attempt and snapshot what it needs, or `None` when
    /// this flow must not migrate at all. Claiming under the flow lock is what
    /// keeps the budget honest and puts the flow into `InFlight` — the state the
    /// pump reads to know it must not feed the replay ring for now.
    async fn plan_migration(&self, flow: &Arc<Mutex<TcpFlowState>>) -> Option<MigrationPlan> {
        let now = Instant::now();
        let mut state = flow.lock().await;
        if matches!(state.status, TcpFlowStatus::Closed)
            || !state
                .resume
                .can_attempt_migration(self.inner.tcp.carrier_migration, now)
        {
            return None;
        }
        let (Some(session_id), Some(carrier)) =
            (state.resume.session_id, state.routing.upstream_carrier.clone())
        else {
            // `can_attempt_migration` already proved the id is there; a flow with
            // no carrier has nothing to replace.
            return None;
        };
        state.resume.begin_migration(now);
        Some(MigrationPlan {
            manager: state.routing.manager.clone(),
            uplink_index: state.routing.uplink_index,
            target: state.routing.target.clone(),
            session_id,
            client_acked_offset: state.resume.client_acked_offset(),
            carrier,
            group_name: state.routing.group_name.clone(),
            uplink_name: state.routing.uplink_name.clone(),
        })
    }

    /// Dial, confirm the hit, replay both directions, install the carrier.
    ///
    /// Any `Err` leaves the flow exactly as it was found (bar the spent attempt):
    /// the old carrier is still installed, the ring untouched, and the freshly
    /// dialled stream closed before we return, so a missed resume does not leak
    /// the upstream the server opened for it.
    async fn migrate_to_fresh_carrier(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
        plan: &MigrationPlan,
    ) -> Result<TcpReader> {
        let candidate = migration_candidate(&plan.manager, plan.uplink_index)?;
        let lb = plan.manager.load_balancing();
        let symmetric_replay = lb.tcp_symmetric_replay_enabled;
        let consume_timeout = lb.tcp_mid_session_retry_consume_timeout;
        let symmetric_replay_max_bytes = lb.tcp_symmetric_replay_max_bytes;

        // Re-dial the uplink this flow already lives on, not a re-selected one: a
        // different uplink is a different server, where the parked upstream is
        // not — the resume could only miss (a mesh cluster shares one resume
        // scope, but its edges also share the shard encoded in the id, so the
        // same dial reaches the same home). The dial deliberately bypasses the
        // candidate filter for the same reason: the carrier death we are
        // recovering from has just been reported as a runtime failure, which may
        // have put this very uplink in cooldown, and dialling elsewhere would
        // guarantee the miss.
        let (writer, mut reader, issued_session_id) = timeout(
            self.inner.tcp.connect_timeout,
            redial_tcp_uplink_for_migration(
                &plan.manager,
                &candidate,
                &plan.target,
                plan.session_id,
                plan.client_acked_offset,
                symmetric_replay,
            ),
        )
        .await
        .map_err(|_| {
            metrics::record_tun_tcp_event(
                &plan.group_name,
                &plan.uplink_name,
                "carrier_migration_dial_failed",
            );
            anyhow!("carrier migration redial timed out after {:?}", self.inner.tcp.connect_timeout)
        })?
        .inspect_err(|_| {
            metrics::record_tun_tcp_event(
                &plan.group_name,
                &plan.uplink_name,
                "carrier_migration_dial_failed",
            );
        })?;

        // The slot is emptied when (and only when) the writer is installed on the
        // flow. So a still-full slot on the error path is a stream nobody owns —
        // and on a resume miss it has a fresh upstream to the destination behind
        // it, which is exactly what we must not leave dangling.
        let mut writer_slot = Some(writer);
        let outcome = self
            .attach_resumed_carrier(
                key,
                flow,
                plan,
                &mut writer_slot,
                &mut reader,
                consume_timeout,
                symmetric_replay_max_bytes,
                issued_session_id,
            )
            .await;
        match outcome {
            Ok(()) => Ok(reader),
            Err(error) => {
                if let Some(mut writer) = writer_slot {
                    // Closes the carrier stream; the reader half dies with it
                    // when it drops out of scope on the way back up.
                    let _ = writer.close().await;
                }
                Err(error)
            },
        }
    }

    /// The part that must be exactly right: confirm, replay, commit.
    #[allow(clippy::too_many_arguments)]
    async fn attach_resumed_carrier(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
        plan: &MigrationPlan,
        writer_slot: &mut Option<TcpWriter>,
        reader: &mut TcpReader,
        consume_timeout: std::time::Duration,
        symmetric_replay_max_bytes: usize,
        issued_session_id: Option<SessionId>,
    ) -> Result<()> {
        let writer = writer_slot
            .as_mut()
            .ok_or_else(|| anyhow!("carrier migration: writer slot is empty"))?;
        // VLESS holds its request header back until the first `send_chunk`, so
        // without this the server would never parse the handshake, never reach
        // the resume take, and never emit the frames we are about to wait for.
        // SS already sent its target header during setup. An empty `send_chunk`
        // on a VLESS writer emits the header alone (and is a no-op once sent).
        if matches!(writer, TcpWriter::Vless(_)) {
            writer.send_chunk(&[]).await.map_err(|error| {
                anyhow!("carrier migration: VLESS header flush failed: {error}")
            })?;
        }

        // THE hit test. `Ok(Some(up_acked))` — and only that — means the server
        // took our parked upstream out of the orphan registry and re-attached it.
        // `Ok(None)` means it never engaged the protocol (resumption off, or an
        // older build): no proof, no migration. `Err` is a timeout or a frame we
        // could not parse — which, on a miss, is what the *fresh* upstream's
        // first bytes look like.
        let up_acked = match reader.consume_ack_prefix_with_timeout(consume_timeout).await {
            Ok(Some(up_acked)) => up_acked,
            Ok(None) => {
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migration_miss",
                );
                bail!(
                    "carrier migration: server did not confirm the resume (no Ack-Prefix frame); \
                     the upstream it opened is fresh, so continuing this flow on it would splice \
                     a new byte stream onto a half-finished one"
                );
            },
            Err(error) => {
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migration_miss",
                );
                return Err(error.context(
                    "carrier migration: no valid Ack-Prefix control frame on the redial; \
                     treating as a resume miss",
                ));
            },
        };

        // The downstream gap, if the server sent one: the bytes it emitted onto
        // the dead carrier that this flow never accepted. They precede anything
        // the new carrier is about to produce, so they must reach the client
        // first — and they follow everything already queued for the client, since
        // `client_acked_offset` counts bytes at the moment the flow *accepts*
        // them, not when the client ACKs them.
        let downlink_replay = match reader
            .consume_downlink_replay_with_timeout(consume_timeout, symmetric_replay_max_bytes)
            .await
        {
            Ok(None) => None,
            Ok(Some(DownlinkReplayOutcome::Replay(payload))) => {
                (!payload.is_empty()).then_some(payload)
            },
            Ok(Some(DownlinkReplayOutcome::Truncated)) => {
                // The server's downlink ring rolled past the offset we reported:
                // the bytes we never saw are gone for good. The flow would come
                // back with a hole in the middle of its downstream — silent
                // corruption. Refuse.
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migration_replay_failed",
                );
                bail!(
                    "carrier migration: server signalled REPLAY_TRUNCATED (downstream gap is \
                     unrecoverable at offset {})",
                    plan.client_acked_offset,
                );
            },
            Err(error) => {
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migration_replay_failed",
                );
                return Err(error.context(
                    "carrier migration: server negotiated v2 downlink replay but did not emit a \
                     valid frame",
                ));
            },
        };

        // Hold the writer mutex across the commit and the replay: the pump parks
        // on it, so whatever it sends next is queued strictly behind the bytes we
        // are about to put on the wire. This is the only thing keeping the uplink
        // byte stream in order.
        let mut carrier = plan.carrier.lock().await;

        let (replay, epoch) = {
            let mut state = flow.lock().await;
            if matches!(state.status, TcpFlowStatus::Closed) {
                bail!("carrier migration: flow closed while the redial was in flight");
            }
            // Snapshot and epoch bump in ONE critical section — see the module
            // header. Splitting them would let a batch the pump takes in between
            // be neither replayed by us nor sent by it.
            let replay = state.resume.replay_from(up_acked).map_err(|error| {
                metrics::record_tun_tcp_event(
                    &plan.group_name,
                    &plan.uplink_name,
                    "carrier_migration_replay_failed",
                );
                anyhow!(
                    "carrier migration: the uplink tail the server is missing cannot be \
                     reproduced ({error:?}); tearing down rather than resuming with a gap"
                )
            })?;
            state.resume.commit_migration(issued_session_id);
            (replay, state.resume.carrier_epoch())
        };

        let writer = writer_slot
            .take()
            .ok_or_else(|| anyhow!("carrier migration: writer slot is empty"))?;
        *carrier = UpstreamCarrier {
            writer: to_upstream_writer(writer),
            epoch,
        };

        if !replay.is_empty()
            && let Err(error) = carrier.writer.send_chunk(&replay).await
        {
            // The new carrier died on its first write. The commit already
            // happened (epoch bumped, carrier installed), so the flow is
            // consistent — it simply has no working transport, and the caller
            // tears it down. The ring still holds the tail, so nothing was lost
            // that a future attempt could have used.
            metrics::record_tun_tcp_event(
                &plan.group_name,
                &plan.uplink_name,
                "carrier_migration_replay_failed",
            );
            return Err(error.context("carrier migration: replaying the uplink tail failed"));
        }
        let replayed = replay.len();
        drop(carrier);

        // Deliver the downstream gap to the client before the read loop pulls a
        // single fresh byte off the new carrier.
        let mut replayed_down = 0usize;
        if let Some(payload) = downlink_replay {
            replayed_down = payload.len();
            self.deliver_downlink_replay(key, flow, plan, payload).await?;
        }

        debug!(
            uplink = %plan.uplink_name,
            up_acked,
            uplink_replay_bytes = replayed,
            downlink_replay_bytes = replayed_down,
            "TUN TCP flow migrated to a fresh carrier on a confirmed resume hit"
        );
        Ok(())
    }

    /// Push the server's downstream replay slice into the flow's downlink buffer
    /// and flush what the client's window allows, so the gap the dead carrier
    /// left is closed before any newer byte can overtake it.
    async fn deliver_downlink_replay(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
        plan: &MigrationPlan,
        payload: Vec<u8>,
    ) -> Result<()> {
        let len = payload.len();
        let flush = {
            let mut state = flow.lock().await;
            if matches!(state.status, TcpFlowStatus::Closed) {
                bail!("carrier migration: flow closed before the downstream replay was delivered");
            }
            state.pending_server_bytes_total += len;
            // These bytes are ours to deliver from now on — count them exactly
            // like the reader counts a chunk it accepted, or the next migration
            // would ask the server to replay them a second time.
            state.resume.record_downlink_payload(len);
            state.pending_server_data.push_back(payload.into());
            let flush = flush_server_output(&mut state);
            commit_flow_changes(&mut state, &self.inner.tcp);
            flush
        };
        let flush = flush.map_err(|error| {
            error.context("carrier migration: building the downstream replay packets failed")
        })?;
        self.write_server_flush(key, flush, &plan.group_name, &plan.uplink_name)
            .await
            .map_err(|error| {
                error.context("carrier migration: writing the downstream replay to the TUN failed")
            })?;
        metrics::flow_bytes_counter("tcp", "down", &plan.group_name, &plan.uplink_name).add(len);
        Ok(())
    }
}

/// The uplink this flow is bound to, as a dial candidate.
///
/// Read straight out of the manager's configured set rather than through
/// candidate selection: selection filters on health, and the carrier death we
/// are recovering from was just reported as a runtime failure on this very
/// uplink. We do not want a *healthy* uplink here — we want the one holding our
/// parked upstream.
fn migration_candidate(manager: &UplinkManager, uplink_index: usize) -> Result<UplinkCandidate> {
    let uplink = manager
        .uplinks()
        .get(uplink_index)
        .ok_or_else(|| {
            anyhow!("carrier migration: uplink index {uplink_index} is not in the group")
        })?
        .clone();
    Ok(UplinkCandidate { index: uplink_index, uplink })
}

fn to_upstream_writer(writer: TcpWriter) -> UpstreamWriter {
    match writer {
        TcpWriter::Ws(w) => UpstreamWriter::TunneledWs(w),
        TcpWriter::Socket(w) => UpstreamWriter::TunneledSocket(w),
        TcpWriter::Vless(w) => UpstreamWriter::TunneledVless(w),
    }
}
