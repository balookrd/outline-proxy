//! How a splice ended and what that tells each side: the fault and end
//! types, and the close-intent resolution shared by every splice.

use super::*;

/// A failed half of a v5 splice: what the edge must see, and whether the parked
/// upstream survived it.
pub(super) struct SpliceFault {
    /// Reset code sent on the mesh stream before the splice returns — unless the
    /// downlink pump already finished the stream on upstream EOF, in which case
    /// the caller suppresses it. Without the reset quinn's `Drop for SendStream`
    /// finishes the stream, so the edge would read a stalled home or a broken
    /// upstream as a clean close and seal a truncated response to its client.
    pub(super) reset: CloseReason,
    /// Whether the parked upstream is still healthy — i.e. whether the session
    /// is worth re-parking for a later carrier.
    pub(super) upstream_healthy: bool,
    pub(super) error: anyhow::Error,
}

impl SpliceFault {
    /// The mesh peer failed (read or write): the upstream is untouched, so the
    /// session is re-parked exactly as if the client had simply gone away.
    pub(super) fn mesh(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: true,
            error,
        }
    }

    /// The upstream socket failed: a later resume would reattach to a dead
    /// socket, so nothing is parked.
    pub(super) fn upstream(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: false,
            error,
        }
    }

    /// An upstream write stalled past the health budget: the socket itself is
    /// not draining, so it is not worth handing to a later carrier.
    pub(super) fn stalled_upstream(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Budget,
            upstream_healthy: false,
            error,
        }
    }

    /// A mesh write stalled past the health budget: the edge is wedged, but the
    /// parked upstream is fine and worth keeping for the next carrier. The edge
    /// sees [`CloseReason::Budget`] on both stall arms, mirroring what the edge
    /// pump signals to the home.
    pub(super) fn stalled_mesh(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Budget,
            upstream_healthy: true,
            error,
        }
    }

    pub(super) fn into_end(self) -> SpliceEnd {
        SpliceEnd::Faulted {
            reset: self.reset,
            upstream_healthy: self.upstream_healthy,
            error: self.error,
        }
    }
}

/// How a v5 splice ended, once both halves are back in the caller's hands.
///
/// One enum rather than a `reset: Option<_>` / `error: Option<_>` pair: a fault
/// always carries both and a graceful end carries neither, so the two mixed
/// combinations the pair could express were never reachable and are now
/// unrepresentable.
pub(super) enum SpliceEnd {
    /// Neither half failed: the edge finished the mesh stream, or the upstream
    /// EOF'd, or both.
    Graceful { upstream_healthy: bool },
    /// One half failed. The edge is told with `reset` — unless the stream was
    /// already finished on upstream EOF — and the caller returns `error`.
    Faulted {
        reset: CloseReason,
        upstream_healthy: bool,
        error: anyhow::Error,
    },
}

/// What the home does to the mesh send half once a v5 splice ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamClose {
    /// Finish the stream. A no-op when the downlink pump already finished it.
    Finish,
    /// Reset it, so the edge cannot mistake a failed relay for a complete
    /// response.
    Reset(CloseReason),
}

impl SpliceEnd {
    /// How the mesh send half must be closed.
    ///
    /// `stream_finished` — the downlink pump finished the stream on upstream EOF
    /// — overrides everything below. quinn does not reject a reset after a
    /// finish: it drops whatever of the stream is still unacked and queues
    /// RESET_STREAM. Resetting there would hand the edge a **complete** response
    /// as an abort, the mirror image of the truncation the reset exists to
    /// prevent.
    ///
    /// A fault otherwise resets, so the edge cannot read a broken relay as a
    /// clean close.
    ///
    /// A graceful end resets too — with [`CloseReason::Fin`] — when the edge
    /// closed with [`CloseIntent::ClientDone`], because that intent rode a
    /// `STOP_SENDING` on this very half. `finish` on a stopped half is a silent
    /// no-op in quinn, leaving `Drop for SendStream` to reset the stream with
    /// the `STOP_SENDING` code it received: a `CloseIntent` code arriving where
    /// the edge reads a [`CloseReason`], which `CloseReason::from_code` would
    /// then read as `Abort`. An explicit `Fin` reset says the same thing in the
    /// vocabulary resets are parsed in, and drops nothing that was wanted — the
    /// only bytes it abandons are downlink bytes the edge has just asked not to
    /// receive.
    pub(super) fn stream_close(&self, stream_finished: bool, intent: CloseIntent) -> StreamClose {
        if stream_finished {
            return StreamClose::Finish;
        }
        match self {
            SpliceEnd::Faulted { reset, .. } => StreamClose::Reset(*reset),
            SpliceEnd::Graceful { .. } => match intent {
                CloseIntent::ClientDone => StreamClose::Reset(CloseReason::Fin),
                CloseIntent::CarrierEnded => StreamClose::Finish,
            },
        }
    }

    /// Whether the upstream this splice held is still worth handing to a later
    /// carrier — the health verdict both halves agreed on.
    pub(super) fn upstream_healthy(&self) -> bool {
        match self {
            SpliceEnd::Graceful { upstream_healthy }
            | SpliceEnd::Faulted { upstream_healthy, .. } => *upstream_healthy,
        }
    }

    /// Whether the session goes back into the registry once the splice ends.
    ///
    /// Two independent questions, and both must say yes. A broken or EOF'd
    /// upstream is never parked, as before. On top of that,
    /// [`CloseIntent::ClientDone`] never parks a *healthy* one either: the
    /// client that owns the session has finished with it, so the park would
    /// never be claimed — it would hold one of the user's `orphan_per_user_cap`
    /// slots until the TTL (where it can evict a park still wanted) while the
    /// target waits for a request-body FIN that never comes. The caller's
    /// non-park path half-closes the upstream, which is exactly what that
    /// client's target is owed.
    pub(super) fn reparks(&self, intent: CloseIntent) -> bool {
        matches!(intent, CloseIntent::CarrierEnded) && self.upstream_healthy()
    }

    /// Marks the parked upstream unusable whatever else this end says. Used when
    /// the *other* half already found the socket EOF'd or broken: a resume would
    /// reattach to something with nothing left to read.
    pub(super) fn deny_park(self) -> Self {
        match self {
            SpliceEnd::Graceful { .. } => SpliceEnd::Graceful { upstream_healthy: false },
            SpliceEnd::Faulted { reset, error, .. } => {
                SpliceEnd::Faulted { reset, upstream_healthy: false, error }
            },
        }
    }
}

/// Why the downlink pump stopped, when it stopped without failing.
pub(super) enum DownlinkEnd {
    /// The upstream EOF'd. The pump finished the mesh stream on its way out, so
    /// the caller must never reset it afterwards.
    UpstreamEof,
    /// The uplink asked the pump to stop and it returned at a read boundary,
    /// with the upstream socket intact.
    Stopped,
    /// The edge stopped the downlink half with [`CloseIntent::ClientDone`],
    /// failing whatever write was in flight. Not a fault: the client is done, so
    /// downlink bytes it will never read are worth nothing, and the upstream
    /// socket is untouched. Distinct from [`DownlinkEnd::Stopped`] because it
    /// arrives *while the uplink is still running* — and the uplink must keep
    /// running, or the tail of the request body still buffered on the mesh would
    /// be dropped instead of reaching the target, which is the very hole the
    /// close intent exists to close.
    ClientDone,
}

/// Writes one relayed uplink chunk to the parked upstream, counting every byte
/// the socket takes *as it takes it*.
///
/// Incremental, rather than one `write_all` followed by a single `fetch_add` for
/// the whole chunk, because this future is dropped where it stands when the
/// downlink faults: `upstream_bytes_acked` must still name exactly the bytes the
/// socket received. A whole-chunk add records nothing for a cancelled partial
/// write, and a later ack-prefix replay from that counter would resend a prefix
/// the target already has.
///
/// `budget` bounds one write, not the chunk: a socket that keeps taking bytes
/// keeps renewing it, and only a socket that stops draining trips it.
pub(super) async fn write_uplink_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    chunk: &[u8],
    budget: Duration,
    up_bytes: &Counter,
    acked: &AtomicU64,
) -> Result<(), SpliceFault> {
    let mut written = 0usize;
    while written < chunk.len() {
        match tokio::time::timeout(budget, writer.write(&chunk[written..])).await {
            // A socket that takes nothing is not going to take the rest either;
            // looping on it would spin.
            Ok(Ok(0)) => {
                return Err(SpliceFault::upstream(anyhow::anyhow!(
                    "relayed uplink write to the upstream accepted no bytes"
                )));
            },
            Ok(Ok(n)) => {
                written += n;
                up_bytes.increment(n as u64);
                // Keeps the Ack-Prefix counter monotonic across this reattach,
                // the same guarantee the direct relay gives.
                acked.fetch_add(n as u64, Ordering::Relaxed);
            },
            Ok(Err(error)) => {
                return Err(SpliceFault::upstream(
                    anyhow::Error::new(error).context("relayed uplink write to the upstream"),
                ));
            },
            Err(_elapsed) => {
                return Err(SpliceFault::stalled_upstream(anyhow::anyhow!(
                    "relayed uplink stalled past the health budget"
                )));
            },
        }
    }
    Ok(())
}

/// Everything the end-of-splice decisions need once both pumps are back in the
/// caller's hands.
pub(super) struct SpliceOutcome {
    /// How the splice ended, and whether the upstream survived it.
    pub(super) end: SpliceEnd,
    /// The downlink pump finished the mesh stream on upstream EOF, so the
    /// caller must never reset it afterwards.
    pub(super) stream_finished: bool,
    /// The [`CloseIntent`] the pumps actually observed on the wire. Only a
    /// downlink write that failed with `STOP_SENDING(ClientDone)` proves the
    /// client is finished; anything else is [`CloseIntent::CarrierEnded`] until
    /// the stream itself says otherwise (see [`resolve_close_intent`]).
    pub(super) observed_intent: CloseIntent,
}

/// Whether the end-of-splice decision still has to ask the stream for the close
/// intent, or whether the pumps have already settled it.
///
/// Answering "no" wherever possible is not an optimisation. quinn's
/// `SendStream::stopped()` inserts a per-stream `Arc<Notify>` into the
/// connection's `stopped` map the first time it polls `Pending`, and dropping
/// the future does not take it back out: the entry is reaped only by
/// `StreamEvent::Finished` (all data plus the FIN acked), `StreamEvent::Stopped`
/// or the connection dying. A **reset** stream produces none of those, so a poll
/// on a relay that is about to be reset would strand one entry for the whole
/// life of a pooled — and therefore long-lived — mesh connection, once per
/// faulted relay.
///
/// So the poll is confined to the single end where it is both needed and reaped:
///
/// * The pumps saw the intent already — nothing left to ask.
/// * The upstream is not healthy — [`SpliceEnd::reparks`] is `false` whatever
///   the intent says, and this is also the end where the downlink pump has
///   already finished the send half, which is the state
///   `SendStream::stopped()` must not be asked about.
/// * The splice faulted — the send half is about to be reset, so an entry
///   inserted here would never be reaped. Nothing is lost: a `ClientDone` that
///   lands on an in-flight downlink write is reported by the pump itself, and
///   one that lands on a *faulted* relay only costs a park that expires on its
///   TTL, which is exactly the documented fallback for a missing code.
///
/// What remains is the bare-FIN carrier switch with a healthy upstream — the
/// case the intent exists to distinguish — where the send half is finished, its
/// FIN is acked, and quinn reaps the entry.
pub(super) fn needs_stopped_poll(end: &SpliceEnd, observed: CloseIntent) -> bool {
    observed == CloseIntent::CarrierEnded
        && matches!(end, SpliceEnd::Graceful { upstream_healthy: true })
}

/// Reads the [`CloseIntent`] the edge attached to a v5 stream, without waiting
/// for one to arrive.
///
/// The intent rides the `STOP_SENDING` the edge applies to this send half, which
/// it emits together with the FIN on the other half — so by the time the home
/// has seen the FIN, the code is already in quinn's stream state and a single
/// poll observes it. Polling instead of awaiting is deliberate: an edge that
/// merely switched carriers sends no `STOP_SENDING` at all, and awaiting one
/// would delay every re-park by however long the wait was, holding the session
/// out of the registry exactly while the next carrier is trying to resume it.
///
/// Missing the code (a lost or reordered packet) yields
/// [`CloseIntent::CarrierEnded`], the pre-v5 behaviour: the session is re-parked
/// and expires on its TTL. Nothing is lost that way — only reclaimed late.
///
/// Only [`resolve_close_intent`] may call this, and only where
/// [`needs_stopped_poll`] says so: the send half must still be open (quinn
/// reports a closed stream as un-stopped) and must be headed for a `finish`,
/// which is what reaps the map entry the poll leaves behind.
pub(super) fn poll_close_intent(send: &SendStream) -> CloseIntent {
    let stopped = send.stopped();
    let mut stopped = std::pin::pin!(stopped);
    // A no-op waker is right here and nowhere else: this future is polled once
    // and dropped, so there is no later wakeup to deliver.
    let mut cx = TaskContext::from_waker(Waker::noop());
    match stopped.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(Some(code))) => CloseIntent::from_code(code.into_inner()),
        Poll::Ready(_) | Poll::Pending => CloseIntent::CarrierEnded,
    }
}

/// Why the edge ended, from whichever source can still know it.
///
/// The downlink pump observes a `ClientDone` directly whenever the intent lands
/// on an in-flight write — the same `STOP_SENDING`, seen as
/// `WriteError::Stopped`. One that lands while the downlink sits idle in its
/// upstream read leaves no trace there, and that one case is what the stream
/// poll is for.
pub(super) fn resolve_close_intent(
    end: &SpliceEnd,
    observed: CloseIntent,
    send: &SendStream,
) -> CloseIntent {
    if needs_stopped_poll(end, observed) {
        poll_close_intent(send)
    } else {
        observed
    }
}

/// Merges the two halves' verdicts once both have ended.
///
/// The uplink decides what the edge sees — it is the half that ended first and
/// stopped the other — but the park decision is the AND of both: an upstream
/// that either half found EOF'd or broken must never be handed to a later
/// carrier.
pub(super) fn splice_end(
    uplink: Result<(), SpliceFault>,
    downlink: Result<DownlinkEnd, SpliceFault>,
) -> SpliceOutcome {
    let stream_finished = matches!(downlink, Ok(DownlinkEnd::UpstreamEof));
    let observed_intent = match &downlink {
        Ok(DownlinkEnd::ClientDone) => CloseIntent::ClientDone,
        _ => CloseIntent::CarrierEnded,
    };
    let downlink_healthy = match &downlink {
        Ok(DownlinkEnd::Stopped | DownlinkEnd::ClientDone) => true,
        Ok(DownlinkEnd::UpstreamEof) => false,
        Err(fault) => fault.upstream_healthy,
    };
    let end = match uplink {
        Ok(()) => match downlink {
            Ok(_) => SpliceEnd::Graceful { upstream_healthy: true },
            // The uplink ended cleanly but the downlink failed on its way out;
            // the edge must still be told, so the fault wins.
            Err(fault) => fault.into_end(),
        },
        Err(fault) => fault.into_end(),
    };
    SpliceOutcome {
        end: if downlink_healthy { end } else { end.deny_park() },
        stream_finished,
        observed_intent,
    }
}
