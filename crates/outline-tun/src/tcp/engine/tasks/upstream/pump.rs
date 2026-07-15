use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, watch};
use tracing::debug;

use outline_metrics as metrics;
use outline_uplink::UplinkManager;

/// Upper bound on bytes coalesced into a single upstream write by the pump.
/// Caps the per-iteration buffer (and copy) while still amortizing the
/// per-segment lock/await overhead across a full receive window's worth of
/// uplink data. Tracks the default `max_buffered_client_bytes` (uplink receive
/// window) so one batch can drain a full window between upstream back-pressure
/// parks — a smaller ceiling re-throttled uplink once the window was enlarged.
const PUMP_BATCH_BYTES: usize = 2 * 1024 * 1024;

use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, UpstreamCarrier, advertised_receive_window, build_flow_ack_packet,
    client_fin_seen,
};
use super::super::super::super::{TCP_FLAG_ACK, TcpFlowKey};
use super::super::super::{TunTcpEngine, close_upstream_writer};

/// How long the pump waits, after a send fails, for the reader to *start* a
/// migration before concluding that none is coming and resetting the flow as it
/// always did.
///
/// The reader is blocked reading the same carrier the send just failed on, so in
/// practice it observes the death within microseconds of us and this grace is
/// never spent; it exists because the alternative — waiting indefinitely — would
/// hang the flow if the reader somehow never errors (it can be parked in
/// downlink back-pressure), and the alternative to *that* — resetting
/// immediately — would race the migration and defeat the whole feature.
const CARRIER_MIGRATION_START_GRACE: Duration = Duration::from_secs(3);

/// What the pump got out of the flow's client buffer.
enum Popped {
    /// A batch (possibly empty), stamped with the carrier epoch its bytes were
    /// mirrored into the replay ring under.
    Batch(Vec<Bytes>, u64),
    /// Nothing: a migration is in flight, and feeding the ring during one would
    /// tear a hole in the replay. Carries the epoch observed while it runs.
    Migrating(u64),
}

/// Verdict of [`TunTcpEngine::await_carrier_verdict`] — what the pump does after
/// a send failed on a carrier that may or may not be about to be replaced.
enum CarrierVerdict {
    /// A migration committed: the flow rides a fresh carrier, and the batch this
    /// pump was holding has already been replayed onto it. Resume draining.
    Migrated,
    /// No migration will save this flow. Do exactly what a failed send always
    /// did: report the uplink failure and reset the flow.
    Abandoned,
    /// The flow is gone (closed by the reader, or torn down elsewhere). Leave;
    /// whoever closed it has already done the accounting.
    Closed,
}

impl TunTcpEngine {
    /// Per-flow upstream pump: the sole writer to `upstream_carrier` once a
    /// flow is connected. It drains `pending_client_data` (filled by the
    /// shared TUN read-loop) into the upstream and parks on the bounded
    /// upstream channel when it back-pressures.
    ///
    /// This is what decouples the read-loop from per-flow upstream
    /// back-pressure: the read-loop only appends to the buffer and wakes
    /// this task, so a slow/degraded uplink stalls one flow's pump instead
    /// of head-of-line-blocking the single read-loop (and with it every
    /// other flow and local service riding the TUN). Back-pressure still
    /// reaches the client honestly — the buffer counts toward
    /// `buffered_client_bytes`, which shrinks the advertised receive window.
    ///
    /// The pump never holds the flow lock and the carrier lock at the same time
    /// (it takes the flow lock, releases it, then takes the carrier lock). That
    /// is what lets a carrier migration hold the carrier lock and take the flow
    /// lock inside it — see `migrate.rs`. Keep it that way.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::tcp::engine) fn spawn_upstream_pump(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        upstream_carrier: Arc<Mutex<UpstreamCarrier>>,
        manager: UplinkManager,
        uplink_index: usize,
        group_name: Arc<str>,
        uplink_name: Arc<str>,
        notify: Arc<Notify>,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        // The pump owns a fixed `(group, uplink)` for its whole lifetime (the
        // task is respawned on failover), so resolve the uplink byte counter
        // once here instead of hashing the label tuple on every batch.
        let up_bytes = metrics::flow_bytes_counter("tcp", "up", &group_name, &uplink_name);
        tokio::spawn(async move {
            loop {
                // Snapshot whether we are currently advertising a *closed*
                // receive window. If so the client has stalled its uplink: the
                // drain below shrinks `buffered_client_bytes` and reopens the
                // window, but without an explicit update the client only learns
                // of it via its own zero-window probe — whose backoff grows and
                // throttles uplink throughput to a fraction of the link. We send
                // a proactive window update after draining to wake it at once.
                let window_was_closed = {
                    let state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        return;
                    }
                    advertised_receive_window(&state) == 0
                };

                // Drain in batches: pull everything currently buffered under a
                // single lock and ship it as one upstream write. The old
                // pop-one/send-one loop paid two locks and an await per ~MSS
                // segment; at line rate that per-segment overhead capped uplink
                // throughput far below the link, so the buffer stayed full and
                // the advertised window collapsed. Coalescing amortizes it (a
                // lone chunk is forwarded without a copy for small interactive
                // flows). Being the only writer keeps the byte stream ordered.
                loop {
                    let popped = {
                        let mut state = flow.lock().await;
                        if matches!(state.status, TcpFlowStatus::Closed) {
                            return;
                        }
                        // A migration is snapshotting the replay ring: a batch
                        // taken now would enter the ring *after* that snapshot, so
                        // the replay would not carry it and the epoch check below
                        // would drop it — losing the bytes. Wait it out instead.
                        // The client's advertised window shrinks meanwhile, so the
                        // back-pressure it feels is honest.
                        if state.resume.migration_in_flight() {
                            Popped::Migrating(state.resume.carrier_epoch())
                        } else {
                            let mut batch: Vec<Bytes> = Vec::new();
                            let mut batch_bytes = 0usize;
                            while batch_bytes < PUMP_BATCH_BYTES {
                                match state.pending_client_data.pop_front() {
                                    Some(chunk) => {
                                        batch_bytes += chunk.len();
                                        batch.push(chunk);
                                    },
                                    None => break,
                                }
                            }
                            // Mirror the batch into the flow's replay ring BEFORE
                            // the send, chunk by chunk in wire order: the ring's
                            // `total_sent` must equal the byte stream the server
                            // sees if the send succeeds. A chunk we pushed but
                            // failed to send stays in the ring, so the migration's
                            // replay re-emits it — exactly the offset semantics
                            // the SOCKS5 pinned relay relies on.
                            record_uplink_batch(&mut state, &batch, &group_name, &uplink_name);
                            // The epoch this batch is accounted against: which
                            // carrier's replay ring now holds these bytes.
                            Popped::Batch(batch, state.resume.carrier_epoch())
                        }
                    };
                    let (batch, epoch) = match popped {
                        Popped::Batch(batch, epoch) => (batch, epoch),
                        Popped::Migrating(epoch) => {
                            match engine.await_carrier_verdict(&flow, &mut close_rx, epoch).await {
                                // Committed, or given up on: either way, go back
                                // and take the buffer as it now stands. If the
                                // migration was abandoned the next send fails and
                                // the verdict below tears the flow down, exactly
                                // as a failed send always did.
                                CarrierVerdict::Migrated | CarrierVerdict::Abandoned => continue,
                                CarrierVerdict::Closed => return,
                            }
                        },
                    };
                    if batch.is_empty() {
                        break;
                    }
                    let sent_bytes: usize = batch.iter().map(Bytes::len).sum();
                    let send_result = {
                        let mut carrier = upstream_carrier.lock().await;
                        if carrier.epoch != epoch {
                            // A migration replaced the carrier after this batch
                            // went into the replay ring — which means its replay,
                            // sent under this very lock just before we got it,
                            // already carried these bytes to the new server.
                            // Sending them again would duplicate them.
                            debug!(
                                uplink = %uplink_name,
                                bytes = sent_bytes,
                                "dropping an uplink batch the carrier migration already replayed"
                            );
                            continue;
                        }
                        if batch.len() == 1 {
                            carrier.writer.send_chunk(&batch[0]).await
                        } else {
                            // Feed the coalesced batch straight into the writer's framer.
                            // Building a `combined` Vec here copied a full receive window
                            // (up to `PUMP_BATCH_BYTES`) per iteration — the uplink hot path's
                            // biggest allocation, which ballooned the allocator's arena under
                            // load. `send_chunks` streams the chunks with a bounded scratch.
                            carrier.writer.send_chunks(&batch).await
                        }
                    };
                    if let Err(error) = send_result {
                        // The batch is already in the replay ring, so a migration
                        // would re-send it — this task must not, and must not kill
                        // a flow the reader may be about to rescue. Park on the
                        // verdict instead.
                        match engine.await_carrier_verdict(&flow, &mut close_rx, epoch).await {
                            CarrierVerdict::Migrated => continue,
                            CarrierVerdict::Closed => return,
                            CarrierVerdict::Abandoned => {
                                engine
                                    .report_tcp_runtime_failure_and_abort(
                                        &key,
                                        &manager,
                                        uplink_index,
                                        &error,
                                        "send_error",
                                    )
                                    .await;
                                return;
                            },
                        }
                    }
                    up_bytes.add(sent_bytes);
                }

                // Buffer drained. If the client half-closed, the flush is
                // complete — close the upstream write half and finish. Doing
                // this here (not in the read-loop) guarantees the FIN never
                // races ahead of still-buffered payload.
                {
                    let state = flow.lock().await;
                    if client_fin_seen(state.status) {
                        // ...unless a migration is mid-flight. Half-closing now
                        // would close the *dead* carrier and end this task, so
                        // the half-close would never reach the upstream the
                        // migration is about to re-attach. Wait for the verdict
                        // and let the next pass send the FIN on whichever carrier
                        // the flow ends up with.
                        if state.resume.migration_in_flight() {
                            let epoch = state.resume.carrier_epoch();
                            drop(state);
                            match engine.await_carrier_verdict(&flow, &mut close_rx, epoch).await {
                                CarrierVerdict::Migrated | CarrierVerdict::Abandoned => continue,
                                CarrierVerdict::Closed => return,
                            }
                        }
                        drop(state);
                        close_upstream_writer(Some(upstream_carrier)).await;
                        return;
                    }
                }

                // Proactive window update: if we had advertised a closed window
                // and the drain reopened it, tell the client now instead of
                // waiting for its (back-off-delayed) zero-window probe.
                if window_was_closed {
                    let ack = {
                        let state = flow.lock().await;
                        if !matches!(state.status, TcpFlowStatus::Closed)
                            && advertised_receive_window(&state) > 0
                        {
                            build_flow_ack_packet(
                                &state,
                                state.server_seq,
                                state.rcv_nxt,
                                TCP_FLAG_ACK,
                            )
                            .ok()
                        } else {
                            None
                        }
                    };
                    if let Some(ack) = ack {
                        let _ = engine.inner.writer.write_packet(&ack).await;
                    }
                }

                // Park until the read-loop buffers more data or the flow is
                // torn down. A `notify_one` issued between the drain above
                // and this await is preserved as a permit, so no wakeup is
                // lost; `close_rx` covers abort / migration / FIN-from-peer.
                tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                    }
                    _ = notify.notified() => {}
                }
            }
        });
    }

    /// Park the pump while a carrier migration decides this flow's fate, and
    /// report what it decided.
    ///
    /// `epoch` is the carrier epoch the caller's batch was accounted against. The
    /// verdict is read off the flow, never guessed:
    ///
    /// * epoch moved → a migration committed; the flow rides a fresh carrier and
    ///   the replay it sent under the carrier lock already carried the caller's
    ///   batch. [`CarrierVerdict::Migrated`].
    /// * migration in flight → keep waiting. It is bounded by its own dial and
    ///   frame timeouts, and it always signals a verdict before it ends.
    /// * this flow can never migrate (disabled, no Session ID, no replay ring,
    ///   budget spent, already abandoned) → [`CarrierVerdict::Abandoned`] at
    ///   once, so a direct flow or a server without resumption pays nothing.
    /// * otherwise the reader has not started one *yet* → wait, but only for
    ///   [`CARRIER_MIGRATION_START_GRACE`]; then [`CarrierVerdict::Abandoned`].
    async fn await_carrier_verdict(
        &self,
        flow: &Arc<Mutex<TcpFlowState>>,
        close_rx: &mut watch::Receiver<bool>,
        epoch: u64,
    ) -> CarrierVerdict {
        let deadline = tokio::time::Instant::now() + CARRIER_MIGRATION_START_GRACE;
        let notify = {
            let state = flow.lock().await;
            state.signals.carrier_migration.clone()
        };
        loop {
            let in_flight = {
                let state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    return CarrierVerdict::Closed;
                }
                if state.resume.carrier_epoch() != epoch {
                    return CarrierVerdict::Migrated;
                }
                let in_flight = state.resume.migration_in_flight();
                if !in_flight
                    && !state
                        .resume
                        .can_attempt_migration(self.inner.tcp.carrier_migration, Instant::now())
                {
                    return CarrierVerdict::Abandoned;
                }
                in_flight
            };
            tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        return CarrierVerdict::Closed;
                    }
                }
                _ = notify.notified() => {}
                // Only armed while we are waiting for a migration to *start*: one
                // that is already running gets as long as its own timeouts allow.
                _ = tokio::time::sleep_until(deadline), if !in_flight => {
                    return CarrierVerdict::Abandoned;
                }
            }
        }
    }
}

/// Appends the batch this pump iteration is about to write upstream to the
/// flow's uplink replay ring, so a future carrier migration can replay the tail
/// the server has not acked yet.
///
/// A chunk too large for the ring downgrades the flow to non-resumable — the
/// ring is dropped and no further chunk is recorded, because a ring with a hole
/// in it is worse than no ring at all (it would let a later replay silently skip
/// bytes). It does **not** disturb the flow: the batch is sent exactly as
/// before, and the flow keeps serving until it ends on its own terms. Losing a
/// hypothetical future migration is never a reason to FIN/RST a working
/// connection.
///
/// No-op on a flow that is already non-resumable (direct flows, and flows that
/// already overflowed), so the cost on those paths is one branch.
fn record_uplink_batch(
    state: &mut TcpFlowState,
    batch: &[Bytes],
    group_name: &str,
    uplink_name: &str,
) {
    if !state.resume.is_resumable() {
        return;
    }
    for chunk in batch {
        if let Err(error) = state.resume.record_uplink_chunk(chunk) {
            metrics::record_tun_tcp_event(group_name, uplink_name, "replay_ring_overflow");
            debug!(
                uplink = %uplink_name,
                error = ?error,
                "uplink chunk exceeds the flow's replay ring cap; flow is no longer \
                 byte-exact resumable and keeps serving without one"
            );
            return;
        }
    }
}
